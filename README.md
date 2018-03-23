# CHS
Csv Hash Steganography

Хеш стеганография, реализованная в CSV данных

См. пост: https://habrahabr.ru/post/339432/


## Команды
Сгенерировать CSV файл с сообщением:
```bash
$ python3 chs.py -m "МГТУ" -i data/world-cities.csv -o stego.csv
```

Извлечь сообщение:
```bash
$ python3 chs.py -i stego.csv
```


Красивая гифка как это работает:

![](https://habrastorage.org/webt/qa/ly/is/qalyisqcgndlts0dgbkykmfg2fa.gif)