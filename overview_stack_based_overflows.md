# Overview of Introductory Binary Exploitation

## What is Binary Exploitation?

Binary Exploitation is the art and science of maniputlating binareis to your will, typically with the end goal of achieving remote code excution on the box hosting the binary from your (the attcking) box.

## How do you do it?

Typically binary exploitation is done by manipulating a running program's memory to a state where you can have it call `system` or `execve` or `telnet` or whatever it is that will allow you to pop a shell. You could also just look for leaking memory, loading a DLL into process memory, ... lots of options here.

### The Jounery

### How it Started

Binary exploitation started with a basic 32-bit stack overflow. On the stack, a proccess will store memory, including an instruction pointer, essentially an address for where to go to get more intructions to execute. 

For example, suppose a proram has a `read()` call, asking for user input, maybe a name, and you put in John. The input would be put on the stack.

Stack:
```
~nonsense~
JOHN
Old Base Poitner
Old Instruction Pointer
~nonsense~
```

Alright now, you are a hacker, and you notice that the program only allows for names of up to 4 letters, what happens if you put in 12?

```
~nonsense~
JOHN
JOHN
JOHN
~nonsense~
```

So when this program goes to return, instead of going to `old instruction pointer` it will go to `JOHN`. We know as of now, that is nonsensicle, but what is important is now you have influence over what we call "control flow".

The was to take advantage of this was to redirect the control flow back to the memory that you control. So you would write a bunch of stuff in the `read()` that instead of a name, it would arrange the stack like this.

```
~nonsense~
JOHN
JOHN
Poitner ------
             |
malicious <---
instructions
all
the 
way
down
```

So now you could have the program do whatever you want. 

## Address Space Layout Randomiztion (ASLR)

To protect programs from this sort of attack, systems designers of Microsoft Windox and Linux decided to integrate address space layout randomization (ASLR). The weakness was that the stack was alway in the same place, so you know where to redirect execution, so they decided to randomize the layout of memory so that you could not guess the `pointer` on the stack. 

To defeat ASLR a malicious actor would need some sort of memory leak or if the program was forking (and thus keeping the same memory layout), this could be brute forced.  

## Data Execution Prevention (DEP/NX)

With ASLR still being vulnerable, system designers impelented was is officially called Data Execution Prevention (DEP), which essentially made it so no section of memory (stack, heap, ro, data, text) was able to be written to and also able to be executed. Essentially this meant the instructions you dumped on the stack could not be executed due to a lack of permission. 

This was a clever solution, but of course, hackers found a way around this. The work arounds became return-oriented-programming (ROP) (where you jump to other parts of the program to piece together code to be executed). The ROP chain could either piece together exaclty wha tyou need, or get to the point where you instruct the program to change the permissions on a piece of memory. 

## Stack Canary

Tired of hackers finding their way around ASLR and NX, the system developers came up with a "Stack Canary". This, like the allusion to a "canary in a coal mine", was meant to be able to signal when a stack based overflow is being attempted by a malicious actor. To understand this, look at how the stack looks originally, and under ASLR+DEP:

```
~nonsense~
JOHN
Old Base Poitner
Old Instruction Pointer
~nonsense~
```

To avoid the overflow into the instruction pointer, the system developers slipped in the canary between that, and the user cotnrolled memory:

```
~nonsense~
JOHN
Canary
Old Base Poitner
Old Instruction Pointer
~nonsense~
```

Before the program change execution to the location indicated by the Instruction Pointer, the program will check is if the canary is the same as it was at the start of the program, any discrepency will lead to an excpetoin and a halting of execution. The canary is developed by entropy found iin system boot up in latent memory, and thus difficult to guess (Though not impossible).

The stack canary, much like ASLR, can be defeated by either a memory leak or brute forced if the program is designed to fork the process. 

 


## Other Topics In This neighborhood

- Fuzzing to find vulnerabilities
- Format String Vulnerabilities
- Heap Exploitation Techniques
- And so much more

## Great Resources

- [Nightmare](https://github.com/guyinatuxedo/nightmare)
