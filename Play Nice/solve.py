from pwn import *
import re

SQUARE_SIZE = 6

def generate_square(alphabet):
    assert len(alphabet) == SQUARE_SIZE * SQUARE_SIZE
    matrix = []
    for i, letter in enumerate(alphabet):
        if i % SQUARE_SIZE == 0:
            row = []
        row.append(letter)
        if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
            matrix.append(row)
    return matrix

def get_index(letter, matrix):
    for r in range(SQUARE_SIZE):
        for c in range(SQUARE_SIZE):
            if matrix[r][c] == letter:
                return (r, c)
    raise ValueError("letter not found in matrix: {!r}".format(letter))

def decrypt_pair(pair, matrix):
    p1 = get_index(pair[0], matrix)
    p2 = get_index(pair[1], matrix)

    if p1[0] == p2[0]:
        return matrix[p1[0]][(p1[1] - 1) % SQUARE_SIZE] + matrix[p2[0]][(p2[1] - 1) % SQUARE_SIZE]
    elif p1[1] == p2[1]:
        return matrix[(p1[0] - 1) % SQUARE_SIZE][p1[1]] + matrix[(p2[0] - 1) % SQUARE_SIZE][p2[1]]
    else:
        return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]

def decrypt_string(ctext, matrix):
    if len(ctext) % 2 != 0:
        raise ValueError("ciphertext length must be even")
    result = ""
    for i in range(0, len(ctext), 2):
        result += decrypt_pair(ctext[i:i+2], matrix)
    return result

r = remote("mercury.picoctf.net", 40742)

r.recvuntil(b"the alphabet: ")
alphabet = r.recvline().decode().strip()

r.recvuntil(b"message: ")
ciphertext = r.recvline().decode().strip()

m = generate_square(alphabet)
plaintext = decrypt_string(ciphertext, m)

r.sendline(plaintext.encode())

flag = re.findall(r'flag: (.+)', r.recvline().decode())[0]
print(flag)

r.close()