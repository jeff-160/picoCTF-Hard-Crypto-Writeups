from pathlib import Path

BLOCK_SIZE = 16
UMAX = 1 << (8 * BLOCK_SIZE)  

def parse_header_ppm(data_bytes):
    idx = 0
    lines_found = 0
    for i, b in enumerate(data_bytes):
        if b == 0x0A:  
            lines_found += 1
            if lines_found == 3:
                idx = i + 1
                break
    if lines_found < 3:
        raise ValueError("Could not find a 3-line PPM header.")
    return data_bytes[:idx], data_bytes[idx:]

def blocks_of(data, size=BLOCK_SIZE):
    return [data[i:i+size] for i in range(0, len(data), size)]

def recover_ct_from_transformed(blocks):
    ct_blocks = []
    for i in range(len(blocks) - 1):
        prev = int.from_bytes(blocks[i], byteorder='big')
        curr = int.from_bytes(blocks[i+1], byteorder='big')
        c = (curr - prev) % UMAX
        ct_blocks.append(c.to_bytes(BLOCK_SIZE, byteorder='big'))
    return b"".join(ct_blocks)

def main():
    in_path = Path("src/body.enc.ppm")

    data = in_path.read_bytes()
    header, body = parse_header_ppm(data)

    if len(body) % BLOCK_SIZE != 0:
        print("Warning: body length is not a multiple of 16. Truncating to full blocks.")
        body = body[:(len(body) // BLOCK_SIZE) * BLOCK_SIZE]

    blocks = blocks_of(body, BLOCK_SIZE)
    if len(blocks) < 2:
        print("Not enough blocks to recover ciphertext.")
        return

    recovered_ct = recover_ct_from_transformed(blocks)

    out_path = Path("flag.ppm")
    out_path.write_bytes(header + recovered_ct)
    print(f"Wrote recovered ECB-visualization image to: {out_path}")

if __name__ == "__main__":
    main()