#!/usr/bin/env python3
# ARM64 string-xref + function disassembler (chained-fixups-independent).
# Usage: xref.py <binary> <hex_vaddr_of_string> [window]
import sys, lief, numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BIN = sys.argv[1]
TARGET = int(sys.argv[2], 16)
WIN = int(sys.argv[3]) if len(sys.argv) > 3 else 60

b = lief.parse(BIN)
# Collect __text section
text = None
for s in b.sections:
    if s.name == "__text":
        text = s; break
tvaddr = text.virtual_address
tbytes = bytes(text.content)
words = np.frombuffer(tbytes, dtype="<u4")
n = words.size

# image base (first segment vmaddr with offset 0 / __TEXT)
# vaddr of an instruction index i = tvaddr + i*4
# ADRP detection: bit31==1, bits[28:24]==0b10000
w = words
is_adrp = ((w >> 31) & 1) == 1
is_adrp &= ((w >> 24) & 0x1f) == 0x10
idx = np.nonzero(is_adrp)[0]

def adrp_page(word, pc):
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):      # sign-extend 21-bit
        imm -= (1 << 21)
    return (pc & ~0xfff) + (imm << 12)

def adrp_rd(word): return word & 0x1f

tgt_page = TARGET & ~0xfff
tgt_lo = TARGET & 0xfff

hits = []
for i in idx:
    pc = tvaddr + int(i)*4
    page = adrp_page(int(w[i]), pc)
    if page != tgt_page:
        continue
    rd = adrp_rd(int(w[i]))
    # look at next up to 6 instrs for ADD (imm) Xrd, Xrd, #lo  OR LDR
    for j in range(i+1, min(i+7, n)):
        ins = int(w[j])
        # ADD immediate 64-bit: sf=1, bits[30:23]=00100010
        if ((ins >> 23) & 0x1ff) == 0b100100010 and ((ins >> 31) & 1) == 1:
            rn = (ins >> 5) & 0x1f
            rd2 = ins & 0x1f
            imm12 = (ins >> 10) & 0xfff
            shift = (ins >> 22) & 0x3
            if rn == rd and shift == 0 and imm12 == tgt_lo:
                hits.append(tvaddr + int(i)*4)
                break
        # LDR (literal/unsigned offset) variant with base rd
        if ((ins >> 22) & 0x3ff) == 0b1111100101 and ((ins >> 5) & 0x1f) == rd:
            off = ((ins >> 10) & 0xfff) * 8
            if off == tgt_lo:
                hits.append(tvaddr + int(i)*4); break
print(f"[{hex(TARGET)}] code refs: {[hex(h) for h in hits]}")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def find_func_start(addr):
    # scan back for prologue-ish: 'stp x29, x30, [sp, ...' (pacibsp/sub sp) heuristics
    i = (addr - tvaddr)//4
    start = i
    for k in range(i, max(0, i-400), -1):
        word = int(w[k])
        # pacibsp = 0xd503237f ; retab/ret = 0xd65f0bff/0xd65f03c0 ; 'sub sp, sp' or stp x29
        if word == 0xd503237f:   # pacibsp (common prologue first instr)
            return tvaddr + k*4
        if word in (0xd65f03c0, 0xd65f0bff):  # ret / retab -> previous func end
            return tvaddr + (k+1)*4
    return tvaddr + start*4

# dump string table for annotation
cstr = {}
for s in b.sections:
    if s.name in ("__cstring","__objc_methname","__objc_classname","__oslogstring"):
        base=s.virtual_address; data=bytes(s.content)
        off=0
        for chunk in data.split(b"\x00"):
            if chunk:
                try: cstr[base+off]=chunk.decode("utf-8","replace")
                except: pass
            off+=len(chunk)+1

def annotate_block(fstart, focus):
    i0 = (fstart - tvaddr)//4
    # disassemble up to WIN instrs or until ret
    code = tbytes[i0*4:(i0+WIN)*4]
    last_adrp = {}
    for ins in md.disasm(code, fstart):
        note=""
        m=ins.mnemonic
        if m=="adrp":
            try:
                rd=ins.op_str.split(",")[0].strip()
                page=int(ins.op_str.split("#")[1],0)
                last_adrp[rd]=page
            except: pass
        if m=="add" and "#" in ins.op_str:
            parts=[p.strip() for p in ins.op_str.split(",")]
            if len(parts)>=3 and parts[0]==parts[1] and parts[0] in last_adrp:
                try:
                    lo=int(parts[2].replace("#",""),0)
                    va=last_adrp[parts[0]]+lo
                    if va in cstr: note=f"  ; \"{cstr[va][:60]}\""
                except: pass
        star = ">>" if ins.address==focus else "  "
        print(f"{star} 0x{ins.address:x}: {m:<8}{ins.op_str}{note}")
        if m in ("ret","retab") and ins.address>focus:
            break

for h in hits:
    fs=find_func_start(h)
    print(f"\n===== function @ {hex(fs)} (ref at {hex(h)}) =====")
    annotate_block(fs, h)
