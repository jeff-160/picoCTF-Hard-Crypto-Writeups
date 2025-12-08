## Very Smooth  

<img src="chall.png" width=600>

### Deepseek prompt

```
#!/usr/bin/python

from binascii import hexlify
from gmpy2 import *
import math
import os
import sys

if sys.version_info < (3, 9):
    math.gcd = gcd
    math.lcm = lcm

_DEBUG = False

FLAG  = open('flag.txt').read().strip()
FLAG  = mpz(hexlify(FLAG.encode()), 16)
SEED  = mpz(hexlify(os.urandom(32)).decode(), 16)
STATE = random_state(SEED)

def get_prime(state, bits):
    return next_prime(mpz_urandomb(state, bits) | (1 << (bits - 1)))

def get_smooth_prime(state, bits, smoothness=16):
    p = mpz(2)
    p_factors = [p]
    while p.bit_length() < bits - 2 * smoothness:
        factor = get_prime(state, smoothness)
        p_factors.append(factor)
        p *= factor

    bitcnt = (bits - p.bit_length()) // 2

    while True:
        prime1 = get_prime(state, bitcnt)
        prime2 = get_prime(state, bitcnt)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() < bits:
            bitcnt += 1
            continue
        if tmpp.bit_length() > bits:
            bitcnt -= 1
            continue
        if is_prime(tmpp + 1):
            p_factors.append(prime1)
            p_factors.append(prime2)
            p = tmpp + 1
            break

    p_factors.sort()

    return (p, p_factors)

e = 0x10001

while True:
    p, p_factors = get_smooth_prime(STATE, 1024, 16)
    if len(p_factors) != len(set(p_factors)):
        continue
    # Smoothness should be different or some might encounter issues.
    q, q_factors = get_smooth_prime(STATE, 1024, 17)
    if len(q_factors) != len(set(q_factors)):
        continue
    factors = p_factors + q_factors
    if e not in factors:
        break

if _DEBUG:
    import sys
    sys.stderr.write(f'p = {p.digits(16)}\n\n')
    sys.stderr.write(f'p_factors = [\n')
    for factor in p_factors:
        sys.stderr.write(f'    {factor.digits(16)},\n')
    sys.stderr.write(f']\n\n')

    sys.stderr.write(f'q = {q.digits(16)}\n\n')
    sys.stderr.write(f'q_factors = [\n')
    for factor in q_factors:
        sys.stderr.write(f'    {factor.digits(16)},\n')
    sys.stderr.write(f']\n\n')

n = p * q

m = math.lcm(p - 1, q - 1)
d = pow(e, -1, m)

c = pow(FLAG, e, n)

print(f'n = {n.digits(16)}')
print(f'c = {c.digits(16)}')


n = a1355e27e1419c3f129f1db20915bf2a2d8db159b67b55858ccb2fbe4c6f4f8245411928326496b416f389dc88f6f89f1e7dc2f184a4fb5efd40d53c4f578bd4643aea45971c21bde2ddfc6582c2955466cb8f5f2341d11ad3bdcb678efeadd043d203105545d104b1c6bde632fe72e89e37af6c69b8ca3c0d7f1367e3f9967f719e816ff603544530999eda08d28b6390fc9e3c8e0eb7432e9506bf5e638c4f548dd8c6c6c0791915f2e31b4f4114c89036650ebf541fec907017d17062114f6d2008aa641166a27734c936e7cb0f4c9df4ca5c7b57019901cbb4f3d3bbc78befbfb770ca8cbf0f3d9b752d55b81f57379e9a13bd33cf3ee17f131c16db8b21
c = 73d31ba14f88d1343a774e5d4315e1733af382318d7bf99116e5e42f0b11dc9561dfa7eafca3e061504538396fd5e463247596e8524df1c51600644d9ea7e607d5be8f79ef237907616d2ab958debc6bef12bd1c959ed3e4c2b0d7aff8ea74711d49fc6e8d438de536d6dd6eb396587e015289717e2c6ea9951822f46aae4a8aa4fc2902ceeddefd45e67fe6d15a6b182bafe8a254323200c728720bfd2d727cc779172f0848616ed37d467179a6912e8bbeb12524c7ac5cda79eee31b96cc7e36d9d69ef673f3016d0e6f0444b4f9de3d05f9d483ee6c1af479a0ffb96e9efab8098e12c7160fe3e4288364be80633a637353979c3d62376abfc99c635b703c


write a script to solve this ctf challenge
```

Flag: `picoCTF{p0ll4rd_f4ct0r1z4at10n_FTW_148cbc0f}`  