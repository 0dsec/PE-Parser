import struct
import sys

def read_file_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def get_dos_magic(data):
    return data[0:2]

def get_e_lfanew(data):
    return struct.unpack("<I", data[0x3C:0x40])[0]

def get_pe_signature(data, pe_offset):
    return data[pe_offset:pe_offset + 4]

def main():
    if len(sys.argv) != 2:
        print("Usage: python pe_reader.py <path_to_exe_or_dll>")
        return
    
    path = sys.argv[1]
    data = read_file_bytes(path)

    print(f"[+] Read {len(data)} bytes from {path}")

    dos_magic = get_dos_magic(data)
    print(f"[+] DOS magic: {dos_magic}")

    if dos_magic != b"MZ":
        print("[-] Not a valid PE file: missing MZ header")
        return
    
    if len(data) < 0x40:
        print("[-] File too small to contain e_lfanew")
        return

    pe_offset = get_e_lfanew(data)
    print(f"[+] e_lfanew (PE header offset): 0x{pe_offset:08X}")

    pe_signature = get_pe_signature(data, pe_offset)
    print(f"[+] PE signature: {pe_signature}")

    if pe_signature != b"PE\x00\x00":
        print("[-] Invalid PE signature")
        return
    
    print("[+] Valid PE file detected")

if __name__ == "__main__":
    main()