import ida_search, ida_bytes, ida_funcs, ida_hexrays, idautils

# Search for "auth/login" string
addr = ida_search.find_text(b"auth/login", 0, 0, 0, 0, ida_search.SEARCH_DOWN)
print("auth/login string addr:", hex(addr) if addr else "not found")
if addr:
    for xref in idautils.XrefsTo(addr):
        print(f"  xref from: {hex(xref.frm)} type={xref.type}")
        func = ida_funcs.get_func(xref.frm)
        if func:
            print(f"    function: {hex(func.start_ea)}")

# List all functions in the auth login handler range
for ea in range(0x141aaba00, 0x141aac000, 8):
    func = ida_funcs.get_func(ea)
    if func and func.start_ea == ea:
        name = ida_funcs.get_func_name(ea)
        if "login" in name.lower():
            print(f"Login function: {name} @ {hex(ea)}")
