import hashlib
import sys

sys.set_int_max_str_digits(0)

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfe7d7086e788af7922b")

MOD = 10**10000

A = [
    [21,     301,   (-9549) % MOD, 55692],
    [1,      0,     0,             0    ],
    [0,      1,     0,             0    ],
    [0,      0,     1,             0    ],
]

INIT = [4, 3, 2, 1]

def mat_mul(X, Y):
    Z = [[0]*4 for _ in range(4)]
    for i in range(4):
        xi = X[i]
        zi = Z[i]
        for k in range(4):
            xik = xi[k]
            if xik == 0:
                continue
            yk = Y[k]
            
            zi[0] = (zi[0] + xik * yk[0]) % MOD
            zi[1] = (zi[1] + xik * yk[1]) % MOD
            zi[2] = (zi[2] + xik * yk[2]) % MOD
            zi[3] = (zi[3] + xik * yk[3]) % MOD
    return Z

def mat_pow(mat, e):
    R = [[1 if i==j else 0 for j in range(4)] for i in range(4)]
    M = [row[:] for row in mat]
    while e > 0:
        if e & 1:
            R = mat_mul(R, M)
        M = mat_mul(M, M)
        e >>= 1
    return R

def mat_vec_mul(mat, vec):
    res = [0]*4
    for i in range(4):
        s = 0
        row = mat[i]
        s = (s + row[0]*vec[0]) % MOD
        s = (s + row[1]*vec[1]) % MOD
        s = (s + row[2]*vec[2]) % MOD
        s = (s + row[3]*vec[3]) % MOD
        res[i] = s
    return res

def decrypt_flag_with_sol(sol_bigint):
    sol = sol_bigint % MOD
    sol_str = str(sol)

    key = hashlib.sha256(sol_str.encode()).digest()
    flag = bytearray([c ^ key[i] for i, c in enumerate(ENCRYPTED_FLAG)]).decode()
    return flag

for i in range(1, 5):
    if ITERS == i:
        decrypt_flag_with_sol(i)
        sys.exit(0)

exp = ITERS - 3  
Aexp = mat_pow(A, exp)
state_n = mat_vec_mul(Aexp, INIT)
m_n = state_n[0]  

flag = decrypt_flag_with_sol(m_n)
print("Flag:", flag)