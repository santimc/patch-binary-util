import sys
import os
import re

def patch_binary(binary_path):
    binary_data = open(binary_path, 'rb').read()

    # Disassemble the binary
    disasm = os.popen(f'riscv64-unknown-elf-objdump -d {binary_path}').read()
    hexdump_out = os.popen(f'hexdump {binary_path}').read()

    # Find all instances of 'jal <setStats>'
    jal_assam = re.findall(r'(\w+):\s+(\w+)\s+jal\s+\w+ <setStats>', disasm)


    for (index, (_, dissas)) in enumerate(jal_assam):
        first = dissas[0:len(dissas)//2]
        secnd = dissas[len(dissas)//2:]
        little_endian = secnd + " " + first
        hex_addresses = re.findall(fr"(\w+)(.*)\s+({little_endian})", hexdump_out)

        addr_str = hex_addresses[0][0]
        extra_two_bytes = hex_addresses[0][1].split(' ')[1:]
        offset = len(extra_two_bytes) * 2
        addr = int(addr_str, 16) + offset
        jal_assam[index] = (addr, little_endian)


   # Replace 'jal' with 'addi zero, zero, 1'
    patched_binary_data = bytearray(binary_data)
    for index, (addr, dissas) in enumerate(jal_assam):
        patched_binary_data[addr] = 0x13
        patched_binary_data[addr + 1] = 0x00
        patched_binary_data[addr + 3] = 0x00
        if index % 2 == 0:
            patched_binary_data[addr + 2] = 0x10
        else:
            patched_binary_data[addr + 2] = 0x20

    return patched_binary_data

# Usage example
if len(sys.argv) < 2:
    print("Usage: python script.py <binary_file>")
    sys.exit(1)

binary_path = sys.argv[1]
patched_binary = patch_binary(binary_path)

sys.stdout.buffer.write(patched_binary)
