import ida_bytes, ida_funcs, ida_hexrays, idautils, ida_idaapi

start = 0x142000000
end = 0x146000000
addr = start
while addr < end:
    addr = ida_bytes.find_bytes(b"auth/login", addr)
    if addr == ida_idaapi.BADADDR:
        break
    print(f"string at {hex(addr)}")
    for xref in idautils.XrefsTo(addr):
        print(f"  xref from: {hex(xref.frm)} type={xref.type}")
        func = ida_funcs.get_func(xref.frm)
        if func:
            name = ida_funcs.get_func_name(func.start_ea)
            print(f"    in function: {name} @ {hex(func.start_ea)}")
    addr += 1
print("Done")
