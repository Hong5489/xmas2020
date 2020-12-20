from pwn import *
import hashlib
import re
from itertools import combinations 
import gmpy2

p = remote("challs.xmas.htsp.ro" ,1000)
p.recvuntil("= ")
h = p.recvuntil("\n")[:-1]
ans = pwnlib.util.iters.mbruteforce(lambda x: hashlib.sha256(x.encode()).hexdigest()[-5:] == h.decode() , string.ascii_lowercase, length = 10)
p.sendline(ans.encode().hex())
# p.interactive()
msg = []
keys = []
for i in range(255):
	p.sendlineafter("exit\n\n","1")
	result = p.recvuntil("e: 65537")
	msg.append(re.findall(b"message: ([0-9a-f]+)",result)[0])
	keys.append(re.findall(b"n: ([0-9]+)",result)[0])

key_exp_msg = []
freq = []
for j in range(len(keys)):
	exp = []
	for i in range(1055,2045):
		if (int(keys[j])>>i)&1:
			exp.append(i-1023)
			freq.append(i-1023)
	key_exp_msg.append([keys[j],exp,msg[j]])
freq = sorted(set(freq), key=freq.count)[::-1][:20]
n,exp,ciphertext = sorted(key_exp_msg, key = lambda kv: len(kv[2]))[0]
print(f"Top exp = {freq}")
print(f"exp = {exp}")

filtered = []
for i in exp:
	if i in freq:
		filtered.append(i)
	if i-1 in freq:
		filtered.append(i-1)
print(f"Filtered exp: {filtered}")

n = int(n)
for i in range(1,len(filtered)+1):
	comb = combinations(filtered,i)
	for c in list(comb):
		num = 2**1023
		for c_i in c:
			num += 2**(c_i)
		if n % gmpy2.next_prime(num) == 0:
			print("Factor found!")
			P = gmpy2.next_prime(num)
			Q = n // P
			phi = (P-1)*(Q-1)
			d = inverse(65537,phi)
			c = int(ciphertext,16)
			secret = hex(pow(c,d,n))[2:]
			p.sendline('2')
			p.sendlineafter("got.\n",secret)
			p.interactive()