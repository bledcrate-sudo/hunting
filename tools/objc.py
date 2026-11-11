#!/usr/bin/env python3
# ObjC class/method resolver using LIEF chained-fixup map. Prints methods + IMP addrs.
# Usage: objc.py <binary> <class_substring>
import sys, lief, struct

BIN=sys.argv[1]; FILT=sys.argv[2]
b=lief.parse(BIN)

# segment map for vaddr -> bytes
segs=[]
for s in b.segments:
    if s.virtual_size>0 and len(s.content)>0:
        segs.append((s.virtual_address, s.virtual_address+s.virtual_size, bytes(s.content)))
def read(vaddr, n):
    for a,e,data in segs:
        if a<=vaddr<e:
            off=vaddr-a
            return data[off:off+n]
    return b""
def u32(v):
    d=read(v,4); return struct.unpack("<I",d)[0] if len(d)==4 else None
def u64(v):
    d=read(v,8); return struct.unpack("<Q",d)[0] if len(d)==8 else None
def cstr(v):
    out=b"";
    while True:
        c=read(v,1)
        if not c or c==b"\x00": break
        out+=c; v+=1
    return out.decode("utf-8","replace")

# fixup map address->target
print("building fixup map...", file=sys.stderr)
fx={}
for r in b.relocations:
    fx[r.address]=r.target
print(f"fixups: {len(fx)}", file=sys.stderr)
def rp(vaddr):  # resolve pointer at slot via fixup (fallback raw)
    if vaddr in fx: return fx[vaddr]
    return u64(vaddr)

def sect(name):
    for s in b.sections:
        if s.name==name: return s.virtual_address, s.size
    return None,None

cl_va, cl_sz = sect("__objc_classlist")
classes=[]
for i in range(cl_sz//8):
    slot=cl_va+i*8
    cva=rp(slot)
    if cva: classes.append(cva)

def parse_methlist(mlva, clsname):
    if not mlva: return
    entsize=u32(mlva); count=u32(mlva+4)
    if entsize is None or count is None or count>100000: return
    rel = (entsize & 0x80000000)!=0
    es = entsize & 0xffff
    base=mlva+8
    for i in range(count):
        if rel:
            ent=base+i*12
            noff=struct.unpack("<i",read(ent,4))[0]
            ioff=struct.unpack("<i",read(ent+8,4))[0]
            # name field: relative to a SEL pointer slot -> deref
            selptr_slot=ent+noff
            selstr=rp(selptr_slot)
            name=cstr(selstr) if selstr else "?"
            imp=(ent+8+ioff) & 0xffffffffffffffff
        else:
            ent=base+i*es
            name_p=rp(ent); imp=rp(ent+16)
            name=cstr(name_p) if name_p else "?"
        print(f"  0x{imp:x}  -[{clsname} {name}]")

for cva in classes:
    data=rp(cva+0x20)   # class_t.data (bits masked)
    if not data: continue
    data &= ~0x7
    name_p=rp(data+0x18)
    clsname=cstr(name_p) if name_p else ""
    if FILT.lower() not in clsname.lower(): continue
    base_methods=rp(data+0x20)
    print(f"== class {clsname} (class@{hex(cva)} ro@{hex(data)}) ==")
    parse_methlist(base_methods, clsname)
