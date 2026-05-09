"""
IDA Python: Trace refresh_token xrefs and decompile key functions
"""
import idautils
import ida_funcs
import ida_xref
import ida_bytes
import json

# Step 1: Find all API endpoint strings
print("=" * 60)
print("STEP 1: API Endpoint Strings")
print("=" * 60)

api_endpoints = {}
for ea in idautils.Strings():
    val = str(ea)
    if "/api/v3/" in val or "/algo/api/" in val:
        xrefs = []
        for xref in idautils.XrefsTo(ea.ea):
            func = ida_funcs.get_func(xref.frm)
            func_name = ida_funcs.get_func_name(xref.frm) if func else "unknown"
            func_ea = hex(func.start_ea) if func else ""
            xrefs.append({"from": hex(xref.frm), "func": func_name, "func_ea": func_ea})
        api_endpoints[val] = xrefs
        print(f"\n  {val} @ {hex(ea.ea)}")
        for x in xrefs[:5]:
            print(f"    xref from: {x['from']} in {x['func']} ({x['func_ea']})")

# Step 2: Find Cosy/Signature related strings
print("\n" + "=" * 60)
print("STEP 2: Cosy/Signature Headers")
print("=" * 60)

cosy_strings = ["Cosy-Key", "Cosy-Date", "Signature", "Bearer", "cosy_key", "encrypt_user_info"]
for s in cosy_strings:
    for ea in idautils.Strings():
        val = str(ea)
        if val == s or (isinstance(val, str) and s.lower() in val.lower()):
            xrefs = []
            for xref in idautils.XrefsTo(ea.ea):
                func = ida_funcs.get_func(xref.frm)
                func_name = ida_funcs.get_func_name(xref.frm) if func else "unknown"
                func_ea = hex(func.start_ea) if func else ""
                xrefs.append({"from": hex(xref.frm), "func": func_name, "func_ea": func_ea})
            print(f"\n  '{val}' @ {hex(ea.ea)}")
            for x in xrefs[:5]:
                print(f"    xref from: {x['from']} in {x['func']} ({x['func_ea']})")

# Step 3: Find refresh_token xrefs
print("\n" + "=" * 60)
print("STEP 3: refresh_token xrefs")
print("=" * 60)

for ea in idautils.Strings():
    val = str(ea)
    if "refresh_token" in val.lower():
        xrefs = []
        for xref in idautils.XrefsTo(ea.ea):
            func = ida_funcs.get_func(xref.frm)
            func_name = ida_funcs.get_func_name(xref.frm) if func else "unknown"
            func_ea = hex(func.start_ea) if func else ""
            xrefs.append({"from": hex(xref.frm), "func": func_name, "func_ea": func_ea})
        print(f"\n  '{val}' @ {hex(ea.ea)}")
        for x in xrefs[:8]:
            print(f"    xref from: {x['from']} in {x['func']} ({x['func_ea']})")

# Step 4: Find doRefreshToken and related function names
print("\n" + "=" * 60)
print("STEP 4: Token/Refresh related functions")
print("=" * 60)

for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if name and ("refresh" in name.lower() or "Refresh" in name or "refreshToken" in name):
        func = ida_funcs.get_func(ea)
        size = func.size_ea - func.start_ea if func else 0
        print(f"\n  {name} @ {hex(ea)} (size={hex(size)})")

print("\nDone!")
