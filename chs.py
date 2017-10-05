# -*- coding: utf-8 -*-
"""
CHS -- Csv Hash Steganography

Хеш-Стеганография в CSV файлах

См. статью "Хеш-стеганография в DataSets. На этот раз быстрая": https://habrahabr.ru/post/339432/


Created by pavel on 05.10.17 17:21
"""
import datetime
import hashlib
import mmh3

from Crypto.Cipher import AES


__author__ = 'pavel'
__email__ = 'pavelmstu@stego.su'


seed = 239239239239
salt = 'bmstu20132017'


def get_byte(line):
    return mmh3.hash_bytes(line, seed=seed)[0]


def generate_source(path_csv):

    bytes_dict = {bytes([i])[0]:list() for i in  range(256)}

    fr = open(path_csv, 'r')

    def get_value(byte_):
        nonlocal bytes_dict

        if len(bytes_dict[byte_]) >= 1:
            line_list = bytes_dict[byte_]
            line = line_list[0]
            line_list.popleft()
            return line

        line = fr.readline()
        byte_line = get_byte(line)
        if byte_line == byte_:
            return line

        while True:
            bytes_dict[byte_line].append(line)
            # ###
            # TODO защита от того, что файл кончился
            line = fr.readline()
            byte_line = get_byte(line)
            if byte_line == byte_:
                return line
            else:
                continue

    def end():
        fr.close()

    header = fr.readline()

    return header, get_value, end


def get_key(password):
    password = '{1}#{0}'.format(password, salt)
    return hashlib.sha256(password.encode('utf-8')).digest()


def encrypt(message, password):
    """
    Шифрование
    :param message: текстовое сообщение
    :param password: текстовый пароль
    :return:
    bytes -- crypt_message
    """
    key = get_key(password)
    obj = AES.new(key)

    message_body = message.encode('utf-8')

    while len(message_body) % 16 != 0:
        message_body += b'\0'

    crypt_message = obj.encrypt(message_body)
    return crypt_message


def decrypt(crypt_message, password):
    """
    Расшифрование crypt_message по паролю password
    :param crypt_message: bytes
    :param password:
    :return:
    str -- message
    """
    key = get_key(password)
    obj = AES.new(key)

    body_message = obj.decrypt(crypt_message)

    while body_message[-1] == 0:
        body_message = body_message[:-1]

    message = body_message.decode('utf-8')
    return message


def stego_generate(
    path_csv_in,
    path_csv_out,
    message,
    password,
):
    """
    Функция, созда
    :param path_csv_in: входной CSV
    :param path_csv_out: выходной CSV
    :param message: сообщение для стегосообщения
    :param password: пароль для стегосообщения
    :return:
    """
    crypt_message = encrypt(message, password)


    with open(path_csv_out, 'w') as fw:
        header, get_value, end = generate_source(path_csv_in)
        fw.write(header)
        print("header:: '{0}'".format(header.replace('\n', '')))
        for byte_ in bytes_:
            line = get_value(byte_)
            fw.write(line)
            print("{0} --> '{1}'".format(byte_, line.replace('\n', '')))
        end()

    print("Хеш-стеганография осуществлена! См. файл:\n\t'{0}'".format(path_csv_out))

if __name__ == u"__main__":
    print(u'Run chs {0}'.format(datetime.datetime.now()))

    password = "sdfsdfsdfewf43"
    message = "Привет мир!"

    message2 = decrypt(encrypt(message, password), password)
    if message != message2:
        print("Всё плохо!")
    else:
        print("Всё хорошо!")

