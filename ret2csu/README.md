# Ret2csu

This talk will walk through the ret2csu attack, which I first heard about from this [Blackhat Paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf).

## What is Going on?

Alright, so the CSU is the C-Startup-.... something, basically referring to the startup routine in `__libc_csu_init()` which is calle dat the start of pretty much any program. The value is, since the attack hits a universal routine, this should be exploitable in any program.

We are going to use the [ret2csu ROPEmporium Challenge](https://ropemporium.com/challenge/ret2csu.html) to guide our conversation.


### Refs
- [Another Analysis](https://bananamafia.dev/post/x64-rop-redpwn/)
