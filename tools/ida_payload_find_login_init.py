import ida_bytes, ida_funcs, ida_hexrays, idautils, ida_idaapi, ida_search

# Search for "auth_login" in function names
for i in range(0x141a00000, 0x141b00000, 0x10):
    func = ida_funcs.get_func(i)
    if func and func.start_ea == i:
        name = ida_funcs.get_func_name(i)
        if "auth_login" in name.lower() or "login.Init" in name or "LoginInit" in name:
            print(f"Found: {name} @ {hex(i)}")

# Also try the structure referenced at off_143947B90
print("\n--- Checking off_143947B90 structure ---")
