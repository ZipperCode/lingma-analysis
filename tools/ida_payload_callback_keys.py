import ida_bytes, ida_hexrays

# Read parseAuthInfoV2 more carefully
# Key at 0x1424AC340 should be "auth" (4 bytes)
# CustomDecryptParts: decodeString + split("\n", 3)
# The auth value in V2 is NOT JSON, but UID\nAID\nName

# Let me also check: what's the auth encoding in the 37510 callback?
# It comes from the Aliyun custom login page, not from ToLoginAuthCallbackParam

# Verify: CustomDecryptParts splits by what separator?
# Look at unk_14393A1D0 - the split separator
raw = ida_bytes.get_bytes(0x14393A1D0, 8)
print(f"Split separator at 0x14393A1D0: {raw.hex()} = {raw}")

# Check if there's a \n (0x0a)
# The split separator for strings.Split is usually a single char
if 0x0a in raw:
    print("  -> Contains \\n (0x0a)")
else:
    print(f"  -> Bytes: {[hex(b) for b in raw[:4]]}")

# Let me also read what actual strings are at the key offsets
# V2 auth key at 0x1424AC340 (4 bytes)
raw2 = ida_bytes.get_bytes(0x1424AC340, 4)
print(f"\nV2 auth key (4 bytes): {raw2} = {raw2.decode(errors='replace')}")

# V2 token key at 0x1424AD922 (5 bytes)
raw3 = ida_bytes.get_bytes(0x1424AD922, 5)
print(f"V2 token key (5 bytes): {raw3} = {raw3.decode(errors='replace')}")

# V1 keys
raw4 = ida_bytes.get_bytes(0x1424AAE6B, 3)
print(f"V1 aid key (3 bytes): {raw4} = {raw4.decode(errors='replace')}")

raw5 = ida_bytes.get_bytes(0x1424AAE6E, 3)
print(f"V1 uid key (3 bytes): {raw5} = {raw5.decode(errors='replace')}")

raw6 = ida_bytes.get_bytes(0x1424AC1DC, 4)
print(f"V1 name key (4 bytes): {raw6} = {raw6.decode(errors='replace')}")
