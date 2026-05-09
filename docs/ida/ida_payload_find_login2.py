import ida_bytes, ida_funcs, ida_hexrays, idautils

# Look at InitHandlers to find auth_login_InitHandlers caller
func = ida_funcs.get_func(0x141aadb20)
if func:
    # Get the bytes at the start
    print("InitHandlers @", hex(func.start_ea))
    # Try to decompile and extract the called function
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        text = str(cfunc)
        # Find first function call
        for line in text.split('\n'):
            if 'auth_login_InitHandlers' in line or 'InitHandlers' in line:
                print(line)
    except Exception as e:
        print(f"decompile error: {e}")
