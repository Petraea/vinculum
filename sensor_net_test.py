#!/usr/bin/python
import socket

input = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
output = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
input.connect(('spacenanny', 12345))
output.connect(('localhost', 8123))
while 1:
    data = input.recv(64)
    print (data)
    output.send(data)
input.close()
output.close()

