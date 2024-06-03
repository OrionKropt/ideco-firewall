# ideco-firewall
## Описание
**Firewall**

Программа загружает базу данных из файла ***data_base.txt***, затем проверяет все пакеты которые поступают из коносли.
Есть два режима работы:
1. Чтение пакетов из консоли
2. Чтение пакетов из файла tests.txt
Поумолчанию стоит первый режим. Чтобы включить второй, нужно передать программе параметр ```$ ./out file```

## build
```$ make```

## TESTS
Для запуска тестов нужно запустить test.sh, который находится в корне проекта.

Test 1 и Test 2 проверяют базу данных из задания

Test 3 проверяет пакеты с протоколами ftp и ntp

***Примеры работы программы***

База данных:

```
src: 10.0.1.11  	dst: 1.1.1.1 	proto: tcp 	=> ACCEPT

src: 10.1.2.12  	dst: 1.1.1.1 	proto: tcp 	=> DROP

src: 10.0.2.12  	dst: 8.8.8.8 	proto: tcp	=> ACCEPT

src: 10.0.3.13 	none			none		=> ACCEPT

none 			dst: 1.2.3.4 	proto: udp	=> DROP

none 			dst: 1.2.3.4	none		=> ACCEPT

none 			dst: 10.0.9.1	proto: tcp	=> DROP

src: 10.0.5.0/24 	none			none		=> ACCEPT

src: 128.2.2.1	dst: 64.64.64.64	proto: ftp	=> ACCEPT

src: 128.2.1.2	none			proto: ntp  => ACCEPT

none			dst: 1.64.64.64	proto: ntp	=> DROP
```


Вывод:

Test 1 Console input

```
packet: 10.0.1.11 1.1.1.1 6 => ACCEPT

packet: 10.0.2.12 1.1.1.1 6 => DRPOP

packet: 10.0.2.12 8.8.8.8 6 => ACCEPT

packet: 10.0.3.13 1.2.2.3 17 => ACCEPT

packet: 10.0.2.12 1.2.3.4 17 => DROP

packet: 12.0.4.128/16 1.2.3.4 6 => ACCEPT

packet: 1.1.1.128 10.0.9.1 6 => DROP

packet: 10.0.5.0/24 10.0.11.1 17 => ACCEPT
```

Test 2 file input
```
packet: 10.0.1.11 1.1.1.1 6 => ACCEPT

packet: 10.0.2.12 1.1.1.1 6 => DRPOP

packet: 10.0.2.12 8.8.8.8 6 => ACCEPT

packet: 10.0.3.13 1.2.2.3 17 => ACCEPT

packet: 10.0.2.12 1.2.3.4 17 => DROP

packet: 12.0.4.128/16 1.2.3.4 6 => ACCEPT

packet: 1.1.1.128 10.0.9.1 6 => DROP

packet: 10.0.5.0/24 10.0.11.1 17 => ACCEPT
```

Test 3 Console input (FTP, NTP)
```
packet: 128.2.2.1 64.64.64.64 21 => ACCEPT

packet: 128.2.1.2 41.0.0.0 27 => ACCEPT

packet: 128.1.1.1 1.64.64.64 27 => DROP
```
