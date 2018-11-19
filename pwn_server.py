#-*- coding: utf-8 -*-

import socket
import os
import sys
import subprocess

HOST = '127.0.0.1'
PORT = 28080

if len(sys.argv) == 1:
    print("usage: python %s [command]" % (sys.argv[0]))
    sys.exit(-1)
else:
    cmd = sys.argv[1]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.bind((HOST, PORT))

sock.listen(5)

while True:
    con, addr = sock.accept()
    pid = os.fork()

    if pid == 0:
        os.dup2(con.fileno(), 0)
        os.dup2(con.fileno(), 1)
        os.dup2(con.fileno(), 2)
        subprocess.call(cmd.split())
        sys.exit()
    else:
        con.close()

