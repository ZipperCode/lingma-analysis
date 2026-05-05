import ida_bytes

# Read the offset strings for log messages
offsets = [
    (0x143947B10, "AK/SK login"),
    (0x143947B20, "PersonalToken login"),
    (0x143947B30, "Default login (device code)"),
]

for addr, desc in offsets:
    # Read the data at the offset - this is a typed structure
    # In Go, off_tables contain type info, so let's try reading as pointer
    ptr = ida_bytes.get_qword(addr)
    if ptr > 0x140000000 and ptr < 0x147000000:
        try:
            s = ida_bytes.get_strlit_contents(ptr)
            if s:
                print(f"{desc} @ {hex(addr)}: ptr {hex(ptr)} = {s.decode(errors='replace')}")
                continue
        except:
            pass
    # Maybe it's direct string data
    raw = ida_bytes.get_bytes(addr, 40)
    s = raw.split(b"\x00")[0].decode(errors="replace") if raw else ""
    print(f"{desc} @ {hex(addr)}: raw hex = {raw[:20].hex()}, str = '{s}'")

# Also check the 5-byte "aksks" constant
print("\n--- Login type strings in binary ---")
# Search for "aksks" in the binary
addr = 0x142000000
while addr < 0x145000000:
    addr = ida_bytes.find_bytes(b"aksks", addr)
    if addr == ida_idaapi.BADADDR:
        break
    print(f"  'aksks' found at {hex(addr)}")
    addr += 1

# Also check for "personalToken"
addr = 0x142000000
while addr < 0x145000000:
    addr = ida_bytes.find_bytes(b"personalToken", addr)
    if addr == ida_idaapi.BADADDR:
        break
    print(f"  'personalToken' found at {hex(addr)}")
    addr += 1
