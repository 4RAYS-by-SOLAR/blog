#!/usr/bin/env python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hexdump import hexdump

import crypt_shellcode as cs

from pathlib import Path
from unicorn import *
from unicorn.x86_const import *
from struct import pack, unpack

from capstone import *

from io import BytesIO

import snappy
from datetime import datetime

md = Cs(CS_ARCH_X86, CS_MODE_64)


def hook_code(mu, address, size, user_data):
    instr_b = mu.mem_read(address, 8)
    # print("Follow instruction at address {:08x}".format(address))
    if instr_b[0] == 0xe8:
        _, _, mnem, op_str = next(md.disasm_lite(instr_b, address))
        if op_str == "0x125c":
            buf_addr = mu.reg_read(UC_X86_REG_RCX)
            length =   mu.reg_read(UC_X86_REG_R8)
            mu.mem_write(buf_addr, b"\x00"*length)
            mu.reg_write(UC_X86_REG_RIP, address + size)
    pass


def hook_memw_inv(mu, access, address, size, value, user_data):
    instr_b = mu.mem_read(mu.reg_read(UC_X86_REG_RIP), 8)
    print("Follow instruction at address {:08x}".format(mu.reg_read(UC_X86_REG_RIP)))

    print(f"EBP: {mu.reg_read(UC_X86_REG_RBP):08x}")
    _, _, mnem, op_str = next(md.disasm_lite(instr_b, address))
    print(mnem, op_str)
    # mu.reg_write(UC_X86_REG_RIP, address + size)
    pass


def decrypt_a2(magic, buf):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    BASE = 0x000000
    BASE_SIZE =  0x1e000
    STACK_ADDR = 0x50000
    STACK_SIZE = 0x20000

    dec_addr = STACK_ADDR+len(buf)
    a1 = unpack(">I", magic)[0]

    mu.mem_map(BASE, BASE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    start_addr = cs.f_cryption["offset"]
    end_addr = cs.f_cryption["offset"] + len(cs.f_cryption["shellcode"])
    stack_enter_addr = STACK_ADDR + STACK_SIZE - 1 - 0x30

    mu.mem_write(cs.f_cryption["offset"], cs.f_cryption["shellcode"])
    mu.mem_write(cs.main_crypt["offset"], cs.main_crypt["shellcode"])
    mu.mem_write(cs.looks_like_the_key["offset"], cs.looks_like_the_key["data"])
    mu.reg_write(UC_X86_REG_RSP, stack_enter_addr)
    mu.mem_write(stack_enter_addr, pack("Q", end_addr)) # For quit on return

    mu.mem_write(STACK_ADDR, buf)

    mu.reg_write(UC_X86_REG_RCX, a1)
    mu.reg_write(UC_X86_REG_R8, len(buf))
    mu.reg_write(UC_X86_REG_RDX, STACK_ADDR)
    mu.reg_write(UC_X86_REG_R9, dec_addr)

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_READ_UNMAPPED, hook_memw_inv)

    mu.emu_start(cs.f_cryption["offset"], end_addr)

    decrypted = mu.mem_read(dec_addr, len(buf))
    return decrypted


def decrypt_modules(enc_m):

    module = decrypt_a2(enc_m[:4], enc_m)
    # with open("raw_mod1.bin", mode="rb") as f:
    #     module = f.read()


    s = snappy.decompress(bytes(module[0x38:]))

    m = ShadowPad_module(module[:0x38], s)
    times = datetime.utcfromtimestamp(m.timestamp).strftime('%Y-%m-%d %H:%M:%S')
    print(f"module_{m._id}: {times}", flush=True)
    print(f"Entry point: 0x{m.entrypoint:08x}")
    print(f"Base address: 0x{m.code_base:08x}")
    m.bs.seek(0)
    return m.bs.read()

    # s = decompress(module[0x3c:], False)
    # with open("raw_d_mod1.bin", mode="wb") as f:
    #     # f.write(module[:0x38])
    #     f.write(s)
    # hexdump(s[0x3a:0x13a])


class ShadowPad_module():
    """
    To make it easy to view in ida pro
    """
    def __init__(self, headers, buf):
        # print(f"{len(buf)=:08x}")
        self.raw_buf = BytesIO(buf)
        self.headers = headers
        self.__deserialize_header()
        length = self.rem_encrypted_size + self.rem_data_size + self.rem_code_size
        self.bs = BytesIO(b"\x00"*length)
        self.__apply_header()

    def __deserialize_header(self):
        fields                   = iter(unpack("IIIIQIIIIIIII", self.headers))
        self.timestamp           = next(fields)
        self.magic               = next(fields)
        self._id                 = next(fields)
        self.entrypoint          = next(fields)
        self.reloc_diff          = next(fields)
        self.code_base           = next(fields)
        print("CB", hex(self.code_base))
        self.rem_code_size       = next(fields)
        self.code_size           = next(fields)
        self.rem_data_size       = next(fields)
        self.data_size           = next(fields)
        self.rem_encrypted_size  = next(fields)
        self.encrypted_size      = next(fields)
        self.reloc_size          = next(fields)

    def __apply_reloc(self, segment, reloc, patch):
        _type = reloc >> 12
        offset = segment - self.code_base + (reloc & 0xfff) + 0 # 0 -- virtual module address
        print("Offset:", hex(offset))
        if _type == 3 or _type == 10:
            self.bs.seek(offset)
            cur_val = unpack("I", self.bs.read(4))[0]
            new_val = (cur_val + patch) & 0xffffffff
            self.bs.seek(offset)
            self.bs.write(pack("I", new_val))

    def __apply_header(self):
        self.bs.seek(0)
        self.raw_buf.seek(0)
        self.bs.write(self.raw_buf.read(self.code_size))
        self.bs.seek(self.rem_code_size)
        self.bs.write(self.raw_buf.read(self.data_size))

        if self.encrypted_size:
            self.bs.seek(self.rem_code_size + self.rem_data_size)
            self.bs.write(self.raw_buf.read(self.encrypted_size))
        if self.reloc_size > 8:
            patch = 0 - self.reloc_diff - self.code_base # 0 -- virtual module address. I write to file so it's 0
            rel_size = 1
            headers_reloc = iter(unpack("II", self.raw_buf.read(8)))
            segment       = next(headers_reloc)
            print("SEG:", hex(segment))
            rel_size      = next(headers_reloc)
            while rel_size < 8:
                get_relocs = lambda x: map(lambda y: unpack("H", bytes(y))[0], zip(*[iter(x)]*2))
                for reloc in get_relocs(self.raw_buf.read(rel_size-8)):
                    self.__apply_reloc(segment, reloc, patch)
                headers_reloc = iter(unpack("II", self.raw_buf.read(8)))
                segment  = next(headers_reloc)
                rel_size = next(headers_reloc)


def main():
    enc_modules = [Path("module1")]
    for enc_module_file in enc_modules:
        with enc_module_file.open("rb") as f:
            enc_module = f.read()
        m = decrypt_modules(enc_module)
        deced_file = enc_module_file.parent / f"{enc_module_file.name}_deced.bin"
        with deced_file.open("wb") as f:
            f.write(m)


if __name__ == '__main__':
    main()
