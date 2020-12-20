from chall import *
import gmpy2
from itertools import combinations 
import sys

cipher = chall(1024, 16)
keys = []
for i in range(255):
	pubkey, privkey = cipher.get_key()
	n, e = pubkey
	n,e,d,p,q = privkey
	keys.append([n,[p,q]])

key_exp = []
freq = []
for k in keys:
	exp = []
	for i in range(1055,2045):
		if (k[0]>>i)&1:
			exp.append(i-1023)
			freq.append(i-1023)
	key_exp.append([k[0],k[1],exp])
freq = sorted(set(freq), key=freq.count)[::-1]

key_exp = sorted(key_exp, key = lambda kv: len(kv[2]))

print(f"Top 20 exponent: {sorted(freq[:20])}")
print(f"Actual exponent: {sorted(cipher.exp)}")
print(f"Most less key: {key_exp[0][0]}")
print(f"Key p: {key_exp[0][1][0]}")
print(f"Key q: {key_exp[0][1][1]}")
print(f"Key exp: {key_exp[0][2]}")

n = key_exp[0][0]
exp = key_exp[0][2]
freq = freq[:20]
filtered = []
for i in exp:
	if i in freq:
		filtered.append(i)
	if i-1 in freq:
		filtered.append(i-1)
	if i-2 in freq:
		filtered.append(i-2)
print(f"Filtered exponent: {filtered}")

for i in range(1,len(filtered)+1):
	comb = combinations(filtered,i)
	for c in list(comb):
		num = 2**1023
		for c_i in c:
			num += 2**(c_i)
		if n % gmpy2.next_prime(num) == 0:
			p = gmpy2.next_prime(num)
			q = n // p
			print("Factor found!")
			print(f"p = {p}")
			print(f"q = {q}")
			sys.exit()