from Crypto.Util.number import long_to_bytes

known_msgs = [
    b'I just cannot wait for rowing practice today!',
    b'I hope we win that big rowing match next week!',
    b'Rowing is such a fun sport!'
]

def integer_nth_root(n, k):
    if n < 0:
        if k % 2 == 0:
            raise ValueError("Even root of negative number")
        return -integer_nth_root(-n, k)
    
    low, high = 0, 1
    while high ** k <= n:
        high <<= 1
    
    while low < high:
        mid = (low + high) // 2
        mid_k = pow(mid, k)
        if mid_k < n:
            low = mid + 1
        else:
            high = mid
    
    return low

def solve_hastad(ciphertexts, moduli, e=3):
    from functools import reduce
    
    N = reduce(lambda a, b: a*b, moduli)
    
    result = 0
    for i in range(len(ciphertexts)):
        Ni = N // moduli[i]
        
        inv = pow(Ni, -1, moduli[i])
        result = (result + ciphertexts[i] * Ni * inv) % N

    m_pow_e = result
    
    m = integer_nth_root(m_pow_e, e)
    
    if pow(m, e) == m_pow_e:
        return m
    
    for i in range(-1000, 1000):
        test_m = m + i
        if test_m >= 0 and pow(test_m, e) == m_pow_e:
            return test_m
    
    return None

def parse_encrypted_data(data):
    entries = []
    current_entry = {}
    
    lines = data.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith('n:'):
            if current_entry:
                entries.append(current_entry)
            current_entry = {'n': int(line.split(': ')[1])}
        elif line.startswith('e:'):
            current_entry['e'] = int(line.split(': ')[1])
        elif line.startswith('c:'):
            current_entry['c'] = int(line.split(': ')[1])
    
    if current_entry:
        entries.append(current_entry)
    
    return entries

def main():
    with open('encrypted-messages.txt', 'r') as f:
        data = f.read()
    
    entries = parse_encrypted_data(data)
    
    ciphertext_groups = {}
    for i, entry in enumerate(entries):
        c = entry['c']
        if c not in ciphertext_groups:
            ciphertext_groups[c] = []
        ciphertext_groups[c].append((i, entry))
    
    for c_val, group in ciphertext_groups.items():
        if len(group) >= 3:  
            indices = [g[0] for g in group[:3]]
            moduli = [entries[i]['n'] for i in indices]
            ciphertexts = [entries[i]['c'] for i in indices]
            
            m = solve_hastad(ciphertexts, moduli, e=3)
            
            if m is not None:
                msg_bytes = long_to_bytes(m)
                
                if b'pico' in msg_bytes:
                    print("Flag:", msg_bytes.decode())
                    exit()
        
if __name__ == "__main__":
    main()