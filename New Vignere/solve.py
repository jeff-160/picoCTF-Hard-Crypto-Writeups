import string

ALPHABET = string.ascii_lowercase[:16]  
HEX_ALLOWED = set("0123456789abcdef")

def decode_b16_with_key_indices(ciphertext, key_indices):
    b16 = []
    L = len(key_indices)
    for i, c in enumerate(ciphertext):
        c_idx = ALPHABET.index(c)
        k_idx = key_indices[i % L]
        b16_idx = (c_idx - k_idx) % 16
        b16.append(ALPHABET[b16_idx])
    
    if len(b16) % 2 != 0:
        return None
    out_chars = []
    for i in range(0, len(b16), 2):
        nib1 = ALPHABET.index(b16[i])
        nib2 = ALPHABET.index(b16[i+1])
        byte = (nib1 << 4) | nib2
        ch = chr(byte)
        out_chars.append(ch)
    return "".join(out_chars)

def partial_check(ciphertext, partial_key, key_len):
    assigned = partial_key  
    n = len(ciphertext)
    
    for i in range(0, n, 2):
        pos0 = i % key_len
        pos1 = (i+1) % key_len
        if pos0 in assigned and pos1 in assigned:
            c0 = ALPHABET.index(ciphertext[i])
            c1 = ALPHABET.index(ciphertext[i+1])
            b0 = (c0 - assigned[pos0]) % 16
            b1 = (c1 - assigned[pos1]) % 16
            byte = (b0 << 4) | b1
            ch = chr(byte)
            if ch not in HEX_ALLOWED:
                return False
    return True

def search_key_for_length(ciphertext, key_len):
    solutions = []
    
    stack = [(0, {})]
    while stack:
        pos, assigned = stack.pop()
        if pos == key_len:
            
            key_indices = [assigned[i] for i in range(key_len)]
            inner = decode_b16_with_key_indices(ciphertext, key_indices)
            if inner is None:
                continue
            
            if all(ch in HEX_ALLOWED for ch in inner):
                solutions.append((key_indices, inner))
            continue
        
        for val in range(16):
            new_assigned = dict(assigned)
            new_assigned[pos] = val
            
            if partial_check(ciphertext, new_assigned, key_len):
                stack.append((pos+1, new_assigned))
            
    return solutions

ciphertext = "bgjpchahecjlodcdbobhjlfadpbhgmbeccbdefmacidbbpgioecobpbkjncfafbe"

for L in range(1, 15):  
    print(f"Trying key length {L} ...")
    sols = search_key_for_length(ciphertext, L)
    if sols:
        for key_indices, inner in sols:
            print("picoCTF{%s}" % inner)
            exit()