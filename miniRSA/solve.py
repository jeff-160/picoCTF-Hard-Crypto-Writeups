c = 2205316413931134031074603746928247799030155221252519872650071180063478720345728937440462363958133000362976196173236315998819688740694410016076856674894300137626732019302117879371506448085294669646806967879964095166284387938624130891918949

def integer_cube_root(n):
    low, high = 1, n
    while low < high:
        mid = (low + high) // 2
        if mid ** 3 < n:
            low = mid + 1
        else:
            high = mid
    return low - 1 if (low - 1) ** 3 == n else low

m = integer_cube_root(c)

flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

print(flag)