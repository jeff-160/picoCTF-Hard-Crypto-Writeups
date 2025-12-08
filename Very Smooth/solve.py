from math import gcd
import re

with open("output.txt", "r") as f:
    contents = f.read()

n_hex = re.findall(r'n = (.+)', contents)[0].strip()
c_hex = re.findall(r'c = (.+)', contents)[0].strip()

n = int(n_hex, 16)
c = int(c_hex, 16)
e = 0x10001

def pollard_p_minus_1(n, max_B=2**20):
    a = 2
    for j in range(2, max_B):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None

def factor_smooth_n(n):
    bounds = [2**16, 2**17, 2**18, 2**19, 2**20]
    
    for B in bounds:
        p = pollard_p_minus_1(n, B)
        if p:
            q = n // p
            return p, q
    
    return None, None

def decrypt_rsa(p, q, c, e):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    
    m = pow(c, d, n)
    return m

p, q = factor_smooth_n(n)
m = decrypt_rsa(p, q, c, e)
        
flag_bytes = bytes.fromhex(hex(m)[2:])
print(f"Flag: {flag_bytes.decode()}")