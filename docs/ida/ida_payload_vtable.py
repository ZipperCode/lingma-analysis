# First find LoginStart function using GetQword on the vtable
import ida_bytes, ida_funcs

# Read the HttpServer vtable function at offset for LoginStart
# Looking at how LoginHandler calls it: cosy_auth__ptr_HttpServer_LoginStart(qword_1460D9530, ...)
# The function pointer is in the vtable at some offset

# Let's also look at off_143947B10/B20/B30 to get string pointers by following the qword
for label, addr in [("B10", 0x143947B10), ("B20", 0x143947B20), ("B30", 0x143947B30)]:
    val = ida_bytes.get_qword(addr)
    print(f"off_143947B{label} @ {hex(addr)}: qword = {hex(val)}")
    if val > 0x140000000 and val < 0x147000000:
        buf = ida_bytes.get_bytes(val, 60)
        if buf:
            idx = buf.find(b'\x00')
            if idx >= 0:
                s = buf[:idx].decode(errors='replace')
            else:
                s = buf.decode(errors='replace')
            print(f"  string at {hex(val)}: {s}")

# Also directly search for the log message strings used in LoginHandler
# "aksks" and "personalToken" were used for login type comparison
# But what log messages?
# Search for the strings referenced by off_143947Bxx
print("\n--- vtable method indices for HttpServer ---")
# Let's try: the HttpServer vtable is accessed via qword_1460D9530
# and methods are called through the vtable
# LoginStart, LoginWithAkSk, LoginWithPersonalToken, LoginStart, DeviceLogin, HandleAuthCallback
# These are all methods on *HttpServer

# Check function at the LoginHandler_func1 callback
func = ida_funcs.get_func(0x141aad0a0 + 0x60)
if func:
    print(f"LoginHandler_func1: {ida_funcs.get_func_name(func.start_ea)} @ {hex(func.start_ea)}")
else:
    print("No func at LoginHandler+0x60")
