from pwn import *

def pad(msg, block_size):
	if len(msg) % block_size == 0:
		return msg
	return msg + bytes(block_size - len(msg) % block_size)

p = remote("challs.xmas.htsp.ro" ,1004)
p.recvuntil("= ")
h = p.recvuntil("\n")[:-1]
ans = pwnlib.util.iters.mbruteforce(lambda x: hashlib.sha256(x.encode()).hexdigest()[-5:] == h.decode() , string.ascii_lowercase, length = 10)
p.sendline(ans.encode().hex())

p.sendline('1')
p.sendlineafter("message.\n","SKR".encode().hex())
p.recvuntil("Here is your hash: b'")
h = bytes.fromhex(p.recvuntil("'")[:-1].decode())
m = pad(b"SKR",16)
hm = xor(m,h)
p.sendline('2')
p.sendlineafter("message.\n",(m).hex())
p.sendlineafter("message.\n",(m+hm+m).hex())
p.interactive()