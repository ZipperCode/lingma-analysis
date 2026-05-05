import ida_search, ida_bytes, ida_funcs, ida_hexrays, idautils

addr = ida_search.find_text(b"auth/login", 0, 0, 0, 0, ida_search.SEARCH_DOWN)
print("auth/login string addr:", hex(addr) if addr else "not found")
if addr:
    for xref in idautils.XrefsTo(addr):
        print(f"xref from: {hex(xref.frm)} type={xref.type}")
        func = ida_funcs.get_func(xref.frm)
        if func:
            print(f"function: {hex(func.start_ea)}")
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                text = str(cfunc)
                print(text[:3000])
            except Exception as e:
                print(f"(could not decompile: {e})")
else:
    # Try different search for "auth"
    addr2 = ida_search.find_text(b"auth/", 0, 0, 0, 0, ida_search.SEARCH_DOWN)
    while addr2:
        text = ida_bytes.get_strlit_contents(addr2)
        if text and b"auth" in text and b"login" not in text:
            print(f"found string at {hex(addr2)}: {text.decode(errors='replace')}")
        addr2 = ida_search.find_text(b"auth/", addr2+1, 0, 0, 0, ida_search.SEARCH_DOWN)
