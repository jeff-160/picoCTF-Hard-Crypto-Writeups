import itertools

ctxt_hex = "57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637"
ctxt = bytes.fromhex(ctxt_hex)

random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'break it'
]

def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt

decrypt = encrypt

flags = set()

for combo in itertools.product([0, 1], repeat=len(random_strs)):
    current = ctxt
    
    for i in range(len(random_strs)-1, -1, -1):
        if combo[i]:  
            current = encrypt(current, random_strs[i])
    
    possible_start = b"picoCTF{"
    
    for key_len in range(1, 50):
        if len(current) >= len(possible_start):
            derived_key = b''
            for j in range(len(possible_start)):
                derived_key += bytes([current[j] ^ possible_start[j]])
            
            is_valid = True
            for j in range(len(possible_start)):
                if derived_key[j % key_len] != derived_key[j]:
                    if j >= key_len:  
                        is_valid = False
                        break
            
            if is_valid and len(derived_key) >= key_len:
                key = derived_key[:key_len]
                decrypted = decrypt(current, key)
                
                try:
                    decrypted_str = decrypted.decode('ascii')
                    if 'picoCTF{' in decrypted_str:
                        flags.add(decrypted_str)
                except:
                    continue

print('\n'.join(flags))