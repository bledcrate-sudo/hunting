#!/usr/bin/env python3
# Annotated arm64 disassembler: resolves ObjC selectors/classes/strings via fixup map.
# Usage: dis.py <binary> <hex_func_start> [max_instrs]
import sys, lief, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BIN=sys.argv[1]; START=int(sys.argv[2],16); MAXI=int(sys.argv[3]) if len(sys.argv)>3 else 160
b=lief.parse(BIN)
segs=[]
for s in b.segments:
    if s.virtual_size>0 and len(s.content)>0:
        segs.append((s.virtual_address,s.virtual_address+s.virtual_size,bytes(s.content)))
def read(v,n):
    for a,e,d in segs:
        if a<=v<e: return d[v-a:v-a+n]
    return b""
def u64(v):
    d=read(v,8); return struct.unpack("<Q",d)[0] if len(d)==8 else None
def cstr(v):
    out=b""
    while True:
        c=read(v,1)
        if not c or c==b"\x00": break
        out+=c; v+=1
    return out.decode("utf-8","replace")
fx={}
for r in b.relocations: fx[r.address]=r.target
def rp(v): return fx.get(v, u64(v))

# section ranges for classification
def rng(name):
    for s in b.sections:
        if s.name==name: return (s.virtual_address, s.virtual_address+s.size)
    return (0,0)
SELREFS=rng("__objc_selrefs"); CLASSREFS=rng("__objc_classrefs")
CSTR=rng("__cstring"); METHNAME=rng("__objc_methname"); CFSTR=rng("__cfstring")
def cfstr(va):
    dp=rp(va+0x10)
    return cstr(dp) if dp else None

def classify(slot):
    """Given a pointer slot address, resolve what it points to with a label."""
    tgt=rp(slot)
    if tgt is None: return None
    if SELREFS[0]<=slot<SELREFS[1]:
        return f'sel "{cstr(tgt)}"'
    if CLASSREFS[0]<=slot<CLASSREFS[1]:
        # class ref -> class_t -> ro.name
        data=rp(tgt+0x20)
        if data:
            nm=rp((data&~0x7)+0x18)
            if nm: return f'class {cstr(nm)}'
        return f'classref->{hex(tgt)}'
    # maybe direct cstring pointer
    if CSTR[0]<=tgt<CSTR[1] or METHNAME[0]<=tgt<METHNAME[1]:
        return f'ptr "{cstr(tgt)}"'
    return None

md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
regs={}  # reg -> ('page',val) after adrp
i=(START); code=read(START, MAXI*4)
depth=0
for ins in md.disasm(code, START):
    note=""
    m=ins.mnemonic; ops=ins.op_str
    if m=="adrp":
        try:
            rd,imm=ops.split(", ")
            regs[rd.strip()]=int(imm.replace("#","").strip(),0)
        except Exception as ex: pass
    elif m=="add" and "#" in ops:
        p=[x.strip() for x in ops.split(",")]
        if len(p)>=3 and p[1] in regs:
            try:
                va=regs[p[1]]+int(p[2].replace("#",""),0)
                if CSTR[0]<=va<CSTR[1] or METHNAME[0]<=va<METHNAME[1]:
                    note=f'  ; "{cstr(va)[:70]}"'
                elif CFSTR[0]<=va<CFSTR[1]:
                    note=f'  ; @"{cfstr(va)}"'
                regs[p[0]]=va  # track computed addr too (for later ldr? no)
            except: pass
    elif m=="ldr":
        p=[x.strip() for x in ops.split(",",1)]
        # form: Xd, [Xn, #off]
        if "[" in ops:
            inside=ops[ops.find("[")+1:ops.find("]")]
            pp=[x.strip() for x in inside.split(",")]
            base=pp[0]
            if base in regs:
                off=0
                if len(pp)>1:
                    try: off=int(pp[1].replace("#",""),0)
                    except: off=0
                slot=regs[base]+off
                lab=classify(slot)
                if lab: note=f"  ; {lab}"
    if m in ("bl","b") and ops.startswith("#"):
        tgt=int(ops[1:],0)
        # annotate known objc runtime stubs by nearby symbol? skip; mark msgSend heuristic
    print(f"0x{ins.address:x}: {m:<7}{ops}{note}")
    if m in ("ret","retab"): break
