"""
IDAPython Script: Extract Lingma Token Refresh Flow
Analyzes doRefreshToken function and related HTTP request/response handling
"""
import idc
import idautils
import idaapi
import ida_nalt
import ida_hexrays
import ida_funcs
import ida_segregs
import ida_xref
import ida_bytes
import ida_search
import json
import re
import os

output = {}

# ─────────────────────────────────────────────────
# 1. Find key strings
# ─────────────────────────────────────────────────
print("=" * 60)
print("[*] Step 1: Searching for key strings...")
print("=" * 60)

target_strings = [
    "refresh_token",
    "/api/v3/user/refresh_token",
    "/algo/api/v3/user/refresh_token",
    "securityOauthToken",
    "RefreshToken",
    "TokenExpireTime",
    "doRefreshToken",
    "Cosy-Key",
    "Cosy-Date",
    "Cosy-Signature",
    "Cosy-Machineid",
    "cosy_key",
    "encrypt_user_info",
    "Bearer",
    "Signature",
    "X-Cosy-",
    "/algo/api/",
    "/api/v3/",
    "refreshToken",
]

string_results = {}
for s in target_strings:
    # Search for string in binary
    # IDAPython method: search for UTF-8 strings
    found = []
    for ea in idautils.Strings():
        try:
            if s.lower() in str(ea).lower():
                found.append({
                    "ea": hex(ea.ea),
                    "value": str(ea)
                })
        except:
            pass
    if found:
        string_results[s] = found
        print(f"  [+] '{s}' found at: {[f['ea'] for f in found]}")

output["strings"] = string_results

# ─────────────────────────────────────────────────
# 2. Find doRefreshToken function
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 2: Finding doRefreshToken function...")
print("=" * 60)

refresh_funcs = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if "refresh" in name.lower() or "Refresh" in name:
        func = ida_funcs.get_func(ea)
        if func:
            refresh_funcs.append({
                "name": name,
                "ea": hex(ea),
                "size": func.size_ea - func.start_ea
            })
            print(f"  [+] Function: {name} @ {hex(ea)} (size={hex(func.size_ea - func.start_ea)})")

output["refresh_functions"] = refresh_funcs

# ─────────────────────────────────────────────────
# 3. Decompile doRefreshToken and surrounding functions
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 3: Decompiling token refresh functions...")
print("=" * 60)

decompiled = {}
for func_info in refresh_funcs:
    ea = int(func_info["ea"], 16)
    name = func_info["name"]

    # Try to decompile with Hex-Rays
    try:
        if ida_hexrays.init_hexrays_plugin():
            hf = ida_hexrays.decompile(ea)
            if hf:
                # Get pseudocode
                pseudo = str(hf)
                decompiled[name] = {
                    "ea": func_info["ea"],
                    "pseudocode": pseudo[:5000],  # Limit size
                    "size": len(pseudo)
                }
                print(f"  [+] Decompiled {name} ({len(pseudo)} chars)")

                # Extract HTTP request construction
                if "http" in pseudo.lower() or "request" in pseudo.lower() or "url" in pseudo.lower():
                    decompiled[name]["has_http"] = True

                # Extract signature/encryption patterns
                if "md5" in pseudo.lower() or "sha" in pseudo.lower() or "sign" in pseudo.lower():
                    decompiled[name]["has_crypto"] = True
    except Exception as e:
        print(f"  [-] Failed to decompile {name}: {e}")
        decompiled[name] = {"ea": func_info["ea"], "error": str(e)}

output["decompiled"] = decompiled

# ─────────────────────────────────────────────────
# 4. Trace cross-references to refresh_token strings
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 4: Tracing xrefs to refresh_token strings...")
print("=" * 60)

xref_data = {}
# Find exact strings for xref tracing
for ea in idautils.Strings():
    val = str(ea)
    if "refresh_token" in val.lower() or "RefreshToken" in val:
        print(f"\n  [*] String: '{val}' @ {hex(ea.ea)}")
        xrefs = []
        for xref in idautils.Xrefs(ea.ea):
            func = ida_funcs.get_func(xref.frm)
            func_name = idc.get_func_name(xref.frm) if func else "unknown"
            xrefs.append({
                "from": hex(xref.frm),
                "type": str(xref.type),
                "func": func_name
            })
            print(f"      xref from: {hex(xref.frm)} in {func_name}")
        if xrefs:
            xref_data[val] = xrefs

output["xrefs"] = xref_data

# ─────────────────────────────────────────────────
# 5. Find HTTP request building functions
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 5: Finding HTTP request building patterns...")
print("=" * 60)

http_funcs = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if not name or name.startswith("_"):
        continue
    # Look for functions that reference both URL and signing patterns
    func = ida_funcs.get_func(ea)
    if not func or (func.size_ea - func.start_ea) > 0x10000:  # Skip huge functions
        continue

    # Search for specific patterns in the function body
    func_data = ida_bytes.get_bytes(func.start_ea, min(func.size_ea - func.start_ea, 0x2000))
    if func_data:
        try:
            func_text = func_data.decode('utf-8', errors='replace')
            # Check for relevant patterns
            patterns = ["algo/api", "cosy", "signature", "bearer", "md5", "authorization"]
            matches = sum(1 for p in patterns if p.lower() in func_text.lower())
            if matches >= 2:
                http_funcs.append({
                    "name": name,
                    "ea": hex(ea),
                    "size": func.size_ea - func.start_ea,
                    "matches": matches
                })
                print(f"  [+] {name} @ {hex(ea)} ({matches} pattern matches)")
        except:
            pass

output["http_functions"] = http_funcs

# ─────────────────────────────────────────────────
# 6. Find all /algo/api/ related string references
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 6: All /algo/api/ related strings...")
print("=" * 60)

algo_api_strings = []
for ea in idautils.Strings():
    val = str(ea)
    if "/algo/api/" in val or "/api/v3/" in val:
        algo_api_strings.append({
            "ea": hex(ea.ea),
            "value": val
        })
        print(f"  [+] {hex(ea.ea)}: {val}")

output["api_strings"] = algo_api_strings

# ─────────────────────────────────────────────────
# 7. Find Cosy/Signature related functions
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 7: Cosy/Signature related functions...")
print("=" * 60)

cosy_funcs = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if not name:
        continue
    if "cosy" in name.lower() or "sign" in name.lower() or "auth" in name.lower() or "token" in name.lower():
        func = ida_funcs.get_func(ea)
        if func and (func.size_ea - func.start_ea) < 0x50000:
            cosy_funcs.append({
                "name": name,
                "ea": hex(ea),
                "size": func.size_ea - func.start_ea
            })
            print(f"  [+] {name} @ {hex(ea)} (size={hex(func.size_ea - func.start_ea)})")

output["cosy_functions"] = cosy_funcs

# ─────────────────────────────────────────────────
# 8. Try to decompile the key functions (cosy/auth related)
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 8: Decompiling cosy/auth/token functions...")
print("=" * 60)

key_funcs_to_decompile = [f for f in cosy_funcs if "token" in f["name"].lower() or "refresh" in f["name"].lower() or "sign" in f["name"].lower()]

decompiled_cosy = {}
for func_info in key_funcs_to_decompile:
    ea = int(func_info["ea"], 16)
    name = func_info["name"]

    try:
        if ida_hexrays.init_hexrays_plugin():
            hf = ida_hexrays.decompile(ea)
            if hf:
                pseudo = str(hf)
                decompiled_cosy[name] = {
                    "ea": func_info["ea"],
                    "pseudocode": pseudo[:8000],
                    "size": len(pseudo)
                }
                print(f"  [+] Decompiled {name} ({len(pseudo)} chars)")
    except Exception as e:
        print(f"  [-] Failed to decompile {name}: {e}")

output["decompiled_cosy"] = decompiled_cosy

# ─────────────────────────────────────────────────
# 9. Find Bearer token / signing construction
# ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[*] Step 9: Searching for Bearer/signing construction patterns...")
print("=" * 60)

# Search for specific byte patterns related to signing
sign_patterns = [
    (b"Bearer", "Bearer string"),
    (b"Cosy-Key", "Cosy-Key header"),
    (b"Cosy-Date", "Cosy-Date header"),
    (b"Signature", "Signature header"),
    (b"md5", "MD5 reference"),
    (b"MD5", "MD5 reference uppercase"),
]

sign_findings = []
for pattern_bytes, desc in sign_patterns:
    found_positions = []
    pos = 0
    while True:
        ea = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), pattern_bytes.hex(), 0, ida_search.SEARCH_DOWN)
        if ea == idaapi.BADADDR:
            break
        func = ida_funcs.get_func(ea)
        func_name = idc.get_func_name(ea) if func else "???"
        found_positions.append({
            "ea": hex(ea),
            "func": func_name if func else "unknown"
        })
        # Mark as found and continue search from next byte
        idaapi.set_item_color(ea, 0x00FF00)
        idc.set_cmt(ea, f"Pattern: {desc}", 0)
        pos = ea + 1
        # break out to avoid infinite loop
        if len(found_positions) > 20:
            break

    if found_positions:
        sign_findings.append({
            "pattern": desc,
            "matches": found_positions[:10]
        })
        print(f"  [+] '{desc}' found in {len(found_positions)} locations")
        for m in found_positions[:5]:
            print(f"      {m['ea']} in {m['func']}")

output["signing_patterns"] = sign_findings

# ─────────────────────────────────────────────────
# Save results
# ─────────────────────────────────────────────────
output_path = os.path.join(idc.get_idb_path() + "_token_refresh_analysis.json")
with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2, ensure_ascii=False, default=str)

print("\n" + "=" * 60)
print(f"[+] Analysis complete! Results saved to: {output_path}")
print("=" * 60)
