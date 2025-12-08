import math
from Crypto.Util.number import long_to_bytes
from pwn import *

r = remote("fickle-tempest.picoctf.net", 53826)

def get(char):
    r.recvuntil(f'{char}:'.encode())

    return int(r.recvline().decode().strip())

c = get('c')
n = get('n')
e = get('e')

r.close()

def wiener_attack(e, n):
    def continued_fraction(e, n):
        cf = []
        while n:
            q = e // n
            cf.append(q)
            e, n = n, e - q * n
        return cf
    
    def convergents(cf):
        convergents = []
        for i in range(1, len(cf) + 1):
            num = 1
            den = cf[i-1]
            for j in range(i-2, -1, -1):
                num, den = den, cf[j] * den + num
            convergents.append((den, num))  
        return convergents
    
    cf = continued_fraction(e, n)
    convs = convergents(cf)
    
    for k, d in convs:
        if k == 0:
            continue
        
        if (e * d - 1) % k != 0:
            continue
            
        phi = (e * d - 1) // k
        b = n - phi + 1
        discriminant = b * b - 4 * n
        
        if discriminant < 0:
            continue
            
        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue
            
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        
        if p * q == n:
            return d, p, q
    
    return None, None, None

d, p, q = wiener_attack(e, n)
m = pow(c, d, n)

print(f"Flag: {long_to_bytes(m).decode()}")