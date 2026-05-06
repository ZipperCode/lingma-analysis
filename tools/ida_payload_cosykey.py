import ida_bytes, ida_funcs, idautils

BADADDR = 0xFFFFFFFFFFFFFFFF

addr = 0x142000000
while addr < 0x145000000:
    addr = ida_bytes.find_bytes(b"cosy_key", addr)
    if addr == BADADDR:
        break
    print(f"cosy_key at {hex(addr)}")
    for xref in idautils.XrefsTo(addr):
        print(f"  xref from: {hex(xref.frm)}")
        func = ida_funcs.get_func(xref.frm)
        if func:
            name = ida_funcs.get_func_name(xref.frm)
            print(f"    function: {name} @ {hex(func.start_ea)}")
    addr += 1
