# -*- coding: utf-8 -*-
"""
CHS -- Csv Hash Steganography

Хеш-Стеганография в CSV файлах

См. статью "Хеш-стеганография в DataSets. На этот раз быстрая": https://habrahabr.ru/post/339432/


Created by pavel on 05.10.17 17:21
"""
import os
import datetime
import hashlib
import mmh3
import argparse

from Crypto.Cipher import AES


__author__ = 'pavel'
__email__ = 'pavelmstu@stego.su'


seed = 239239239239
salt = 'bmstu20132017'

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))


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
            line_list.pop(0)
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
        for byte_ in crypt_message:
            line = get_value(byte_)
            fw.write(line)
            print("{0} --> '{1}'".format(byte_, line.replace('\n', '')))
        end()


def stego_extract(
    path_csv,
    password,
):
    """
    Функция по извлечению полезной информации из CSV файла
    :param path_csv: выходной CSV от функции stego_generate
    :param password: пароль
    :return:
    str -- message
    """

    byte_list = list()
    with open(path_csv, 'r') as fr:
        fr.readline()
        for line in fr:
            byte_ = get_byte(line)
            byte_list.append(byte_)

    crypt_message = bytes(byte_list)

    message = decrypt(crypt_message, password)

    return message


def __test():

    path_csv_in = os.path.join(ROOT_PATH, 'data', 'world-cities.csv')
    path_csv_out = os.path.join(ROOT_PATH, 'data', 'world-cities.stego.csv')

    message = """Как рано мог он лицемерить,
Таить надежду, ревновать,
Разуверять, заставить верить,
Казаться мрачным, изнывать,
Являться гордым и послушным,
Внимательным иль равнодушным!
Как томно был он молчалив,
Как пламенно красноречив,
В сердечных письмах как небрежен!
Одним дыша, одно любя,
Как он умел забыть себя!
Как взор его был быстр и нежен,
Стыдлив и дерзок, а порой
Блистал послушною слезой!
    """

    password = """И всё же порядок вещей нелеп.
Люди, плавящие металл,
Ткущие ткани, пекущие хлеб,
Кто-то бессовестно вас обокрал.

Не только ваш труд, любовь, досуг -
Украли пытливость открытых глаз;
Набором истин кормя из рук,
Умение мыслить украли у вас.
    """

    print("stego_generate ({0})".format(datetime.datetime.now()))
    stego_generate(
        path_csv_in,
        path_csv_out,
        message,
        password,
    )

    print("stego_extract ({0})".format(datetime.datetime.now()))
    message2 = stego_extract(path_csv_out, password)

    print('done! ({0})'.format(datetime.datetime.now()))

    print("Извлеченное сообщение:\n\n{0}".format(message2))


def __test2():
    path_csv_out = os.path.join(ROOT_PATH, 'data', 'world-cities.stego.csv')

    password = """И всё же порядок вещей нелеп.
Люди, плавящие металл,
Ткущие ткани, пекущие хлеб,
Кто-то бессовестно вас обокрал.

Не только ваш труд, любовь, досуг -
Украли пытливость открытых глаз;
Набором истин кормя из рук,
Умение мыслить украли у вас.
    """

    message2 = stego_extract(path_csv_out, password)
    print("message2::{0}".format(message2))


def main(args):
    args = vars(args)

    if 'message' in args and args['message'] is not None:
        # режим генерирования
        message = args['message']
        path_csv_in = args['input']
        if not path_csv_in.startswith('/'):
            path_csv_in = os.path.join(ROOT_PATH, path_csv_in)
        path_csv_out = args['output']
        if not path_csv_out.startswith('/'):
            path_csv_out = os.path.join(ROOT_PATH, path_csv_out)

        password = input("Введите пароль: ")

        stego_generate(
            path_csv_in,
            path_csv_out,
            message,
            password,
        )

        pass
    else:
        # режим извлечения

        path_csv_in = args['input']

        password = input("Введите пароль: ")

        message = stego_extract(
            path_csv_in,
            password
        )
        print("Извлечённое сообщение:'{}'".format(message))
    pass


if __name__ == u"__main__":
    print(u'Run chs {0}'.format(datetime.datetime.now()))

    # __test()
    # __test2()

    parser = argparse.ArgumentParser(
        description='CSV Hash Steganography',
        epilog='See more information:https://habrahabr.ru/post/339432/\nPavelMSTU <PavelMSTU@stego.su>'
    )

    parser.add_argument(
        '-m', '--message',
        help='Сообщение для внесения в генерируемый CSV. Если не введен -- режим извлечения.',
    )
    parser.add_argument(
        '-i', '--input',
        help='Входной CSV-файл донор (если есть флаг -m); файл CSV для извлечения сообщения (если не указан флаг -m)',
        required=True,
    )
    parser.add_argument(
        '-o', '--output',
        help="Выходной CSV-файл (если есть флаг -m); если не указан флаг -m, флаг игнорируется",
        # required=True,
    )

    args = parser.parse_args()
    main(args)

