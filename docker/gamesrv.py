#!/usr/bin/env python3
"""Мини-игровой UDP-сервер для примера (echo): принимает датаграммы на 7777
и возвращает их отправителю. В лог пишет адрес, с которого «пришёл» игрок, —
это подменённый прокси-клиентом реальный IP клиента."""
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 7777))
print("GAME READY on 0.0.0.0:7777", flush=True)
while True:
    data, addr = sock.recvfrom(65535)
    print("GOT {0}:{1} {2!r}".format(addr[0], addr[1], data), flush=True)
    sock.sendto(data, addr)
