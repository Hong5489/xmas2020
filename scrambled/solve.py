text = open("output.txt",'r').read().decode('hex')
freq = sorted(set(text), key = text.count)[::-1]

# Spaces are most frequent
englishLetterFreq = ' ERNIOSALTHGCUMWBDYPFVKJXQZ'
# Map each ciphertext with a letter
mapping = {}
for i,t in enumerate(freq):
	if i < 27:
		mapping[t] = englishLetterFreq[i]

flag = ''
for c in text:
	if c in mapping.keys():
		flag += mapping[c]

print(flag)