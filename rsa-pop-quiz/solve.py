from pwn import *

r = remote("fickle-tempest.picoctf.net", 64863)

def get(char):
    r.recvuntil(f'{char} :'.encode())

    return int(r.recvline().decode().strip())

def answer(value, delim):
    possible = bool(value is not None)
    
    r.sendlineafter(b'(Y/N)', b'Y' if possible else b"N")

    if not possible:
        return

    r.sendlineafter(delim.encode(), str(value).encode())

# qn 1
q = get('q')
p = get('p')

def get_n(q, p):
    n = p * q
    
    possible = p > 0 and q > 0

    return n if possible else None

n = get_n(q, p)

answer(n, 'n')

# qn 2
p = get('p')
n = get('n')

def get_q(p, n):
    if n % p == 0:
        q = n // p
        
        return q
    else:
        return None
    
q = get_q(p, n)

answer(q, 'q')

# qn 3
e = get('e')
n = get('n')

def get_qp(e, n):
    if n % 2 == 0:
        q = 2
        p = n // 2
    
        return p, q

    else:
        return None, None
    
p, q  = get_qp(e, n)

answer(p, "")

# qn 4
q = get('q')
p = get('p')

def get_totient(q, p):
    n = p * q
    
    totient = (p - 1) * (q - 1)

    return totient

totient = get_totient(q, p)
answer(totient, "totient(n)")

# qn 5
plaintext = get('plaintext')
e = get('e')
n = get('n')

def get_cipher(plaintext, e, n):
    c = pow(plaintext, e, n)

    return c

answer(get_cipher(plaintext, e, n), 'ciphertext:')

# qn 6
ciphertext = get('ciphertext')
e = get('e')
n = get('n')

def get_plain(ciphertext, e, n):
    cube_root = round(ciphertext ** (1/3))

    if cube_root ** 3 == ciphertext:
        return cube_root
    else:
        return None

plaintext = get_plain(ciphertext, e, n)
answer(plaintext, "plaintext:")

# qn 7
q = get('q')
p = get('p')
e = get('e')

def get_d(q, p, e):
    phi = (p - 1) * (q - 1)
    
    d = pow(e, -1, phi)
    
    return d

d = get_d(q, p, e)
answer(d, 'd')

# qn 8
p = get('p')
ciphertext = get('ciphertext')
e = get('e')
n = get('n')

def get_plain(p, ciphertext, e, n):
    if n % p != 0:
        return None
    
    q = n // p    
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    
    plaintext = pow(ciphertext, d, n)
    return plaintext

plaintext = get_plain(p, ciphertext, e, n)

answer(plaintext, 'plaintext:')

r.close()

# final task (If you convert the last plaintext to a hex number, then ascii, you'll find what you need! ;))
plaintext = hex(plaintext)[2:]
flag = bytes.fromhex(plaintext)

print("Flag:", flag.decode())