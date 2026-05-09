#!/usr/bin/env python3
"""
Constraint-based session key oracle attack.
Uses ALL 7 oracle pairs for cross-validation.
Systematically tests combinations of known data.
"""
import hashlib
import json
import os
from email.utils import parsedate_to_datetime

ORACLES = [
    ("Fri, 24 Apr 2026 07:54:36 GMT", "e8b434d0a2596ca2ff99c60c4756a1ff"),
    ("Fri, 24 Apr 2026 14:23:16 GMT", "8d915d7d99452c143dc52ce040b9a355"),
    ("Fri, 24 Apr 2026 14:26:16 GMT", "e7d5d7c586d345ad664fff195518b425"),
    ("Fri, 24 Apr 2026 14:29:16 GMT", "0a12e309cb9d31686a753ab261deaf15"),
    ("Fri, 24 Apr 2026 13:43:57 GMT", "9856df4b14fd343d0deb0018874c2a30"),
    ("Fri, 24 Apr 2026 13:45:32 GMT", "9186780ae747446a74b0c555c686b38d"),
    ("Fri, 24 Apr 2026 13:46:37 GMT", "47e0e4e4f3ce25b2d1e9e8e4f3ce25b2"),
]

# Keys from static analysis
LONG_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"
SHORT_KEY_B64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
SHORT_KEY_DECODED = "war, war never changes"
HEX_TAIL = "9f1dff714a390b20aeb19175ecc496e6"

# Load config for additional candidates
CFG_PATH = r"C:/Users/Zipper/.lingma/portable_config.json"
cfg = json.load(open(CFG_PATH))

# Build comprehensive key candidates
CANDIDATES = []

# 1. Static keys
CANDIDATES.append(("long_key", LONG_KEY))
CANDIDATES.append(("short_key_b64", SHORT_KEY_B64))
CANDIDATES.append(("short_key_decoded", SHORT_KEY_DECODED))
CANDIDATES.append(("hex_tail", HEX_TAIL))

# 2. Config-derived
CANDIDATES.append(("machine_id", cfg.get("machine_id", "")))
CANDIDATES.append(("user_id", cfg.get("user_id", "")))
CANDIDATES.append(("user_name", cfg.get("user_name", "")))
CANDIDATES.append(("security_oauth_token", cfg.get("security_oauth_token", "")))
CANDIDATES.append(("refresh_token", cfg.get("refresh_token", "")))

# 3. Machine ID variants
mid = cfg.get("machine_id", "")
CANDIDATES.append(("machine_id_no_dash", mid.replace("-", "")))
CANDIDATES.append(("machine_id_first16", mid[:16]))
CANDIDATES.append(("machine_id_last16", mid[-16:]))
# UUID-like: take the hex part
for part in mid.split("-"):
    if len(part) > 4:
        CANDIDATES.append((f"machine_id_part_{part}", part))

# 4. Composite keys
CANDIDATES.append(("long+mid", LONG_KEY + mid))
CANDIDATES.append(("mid+long", mid + LONG_KEY))
CANDIDATES.append(("short+mid", SHORT_KEY_B64 + mid))
CANDIDATES.append(("hex+mid", HEX_TAIL + mid))

# 5. Truncations
for n in [8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 64]:
    CANDIDATES.append((f"long_key_{n}", LONG_KEY[:n]))
    CANDIDATES.append((f"machine_id_{n}", mid[:n]))
    CANDIDATES.append((f"hex_tail_{n}", HEX_TAIL[:n]))

# 6. Various concatenations of mid and long key
for sep in ["", "-", "_", ":"]:
    CANDIDATES.append((f"long{sep}mid", LONG_KEY + sep + mid))

# 7. MD5 of things (maybe key is MD5 of something)
for name, val in list(CANDIDATES[:20]):  # Copy first 20
    CANDIDATES.append((f"md5_{name}", hashlib.md5(val.encode()).hexdigest()))

# 8. The "cosy" prefix itself
CANDIDATES.append(("cosy", "cosy"))
CANDIDATES.append(("cosyauthsigntest", "cosyauthsigntest"))

# Date format variants
def date_variants(rfc1123):
    variants = []
    variants.append(("rfc1123", rfc1123))
    dt = parsedate_to_datetime(rfc1123)
    unix = str(int(dt.timestamp()))
    variants.append(("unix_utc", unix))
    # Try unix with different timezone offsets
    variants.append(("unix_minus_8h", str(int(dt.timestamp()) - 8*3600)))
    variants.append(("unix_plus_8h", str(int(dt.timestamp()) + 8*3600)))
    variants.append(("rfc1123z", dt.strftime("%a, %d %b %Y %H:%M:%S +0000")))
    variants.append(("iso8601", dt.strftime("%Y-%m-%dT%H:%M:%SZ")))
    variants.append(("date_compact", dt.strftime("%Y%m%d")))
    variants.append(("datetime_compact", dt.strftime("%Y%m%d%H%M%S")))
    return variants

# Formula generators
def gen_formulas(key, date_str):
    results = []
    key_str = key if isinstance(key, str) else str(key)

    # Different prefix variations
    prefixes = ["cosy", "COSY", "Cosy", "cosyauthsigntest", ""]

    for prefix in prefixes:
        for sep in ["", "|", "\n", " ", "||", "|\n|", "&"]:
            orders = [
                [prefix, key_str, date_str],
                [prefix, date_str, key_str],
                [key_str, prefix, date_str],
                [date_str, prefix, key_str],
                [key_str, date_str, prefix],
                [date_str, key_str, prefix],
            ]
            if not prefix:
                orders = [[key_str, date_str], [date_str, key_str]]

            for order in orders:
                preimage = sep.join(o for o in order if o)
                md5 = hashlib.md5(preimage.encode()).hexdigest()
                results.append((f"join('{sep}') {order}", preimage, md5))

    # Upper/lower case
    for order in [[key_str, date_str], [date_str, key_str]]:
        for case_prefix in ["cosy", "COSY", ""]:
            base = case_prefix + order[0] + order[1] if case_prefix else order[0] + order[1]
            for transform in [str.upper, str.lower]:
                preimage = transform(base)
                md5 = hashlib.md5(preimage.encode()).hexdigest()
                results.append((f"{transform.__name__}({base[:50]})", preimage, md5))

    return results


def test_all():
    print("=" * 100)
    print("CONSTRAINT-BASED SESSION KEY ORACLE ATTACK")
    print(f"Oracles: {len(ORACLES)}")
    print(f"Base candidates: {len(CANDIDATES)}")
    print("=" * 100)

    matches = []
    tested = 0

    for cand_name, cand_key in CANDIDATES:
        if not cand_key:
            continue

        # For each date variant of the first oracle
        base_date = ORACLES[0][0]
        for date_name, date_str in date_variants(base_date):
            for formula_name, preimage, md5 in gen_formulas(cand_key, date_str):
                tested += 1

                if tested % 100000 == 0:
                    print(f"  ... tested {tested} combinations ...")

                # Check first oracle
                if md5 != ORACLES[0][1]:
                    continue

                # Verify against ALL other oracles
                all_match = True
                for oracle_date, oracle_sig in ORACLES[1:]:
                    dt = parsedate_to_datetime(oracle_date)

                    if date_name == "rfc1123":
                        test_date = oracle_date
                    elif date_name == "unix_utc":
                        test_date = str(int(dt.timestamp()))
                    elif date_name == "unix_minus_8h":
                        test_date = str(int(dt.timestamp()) - 8*3600)
                    elif date_name == "unix_plus_8h":
                        test_date = str(int(dt.timestamp()) + 8*3600)
                    elif date_name == "rfc1123z":
                        test_date = dt.strftime("%a, %d %b %Y %H:%M:%S +0000")
                    elif date_name == "iso8601":
                        test_date = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    elif date_name == "date_compact":
                        test_date = dt.strftime("%Y%m%d")
                    elif date_name == "datetime_compact":
                        test_date = dt.strftime("%Y%m%d%H%M%S")
                    else:
                        all_match = False
                        break

                    # Reconstruct preimage
                    preimage_test = preimage.replace(date_str, test_date)
                    md5_test = hashlib.md5(preimage_test.encode()).hexdigest()
                    if md5_test != oracle_sig:
                        all_match = False
                        break

                if all_match:
                    matches.append({
                        'candidate': cand_name,
                        'key': cand_key[:80],
                        'date_fmt': date_name,
                        'formula': formula_name,
                        'preimage': preimage[:120],
                        'md5': md5,
                    })
                    print(f"\n*** MATCH FOUND ***")
                    print(f"  Candidate: {cand_name} = {cand_key[:80]}")
                    print(f"  Date format: {date_name}")
                    print(f"  Formula: {formula_name}")
                    print(f"  Preimage: {preimage[:120]}")
                    print(f"  Verified against all {len(ORACLES)} oracles!")

    print(f"\n{'=' * 100}")
    print(f"Total tests: {tested}")
    print(f"Matches: {len(matches)}")

    if matches:
        for m in matches:
            print(f"\n  {m['candidate']} | {m['date_fmt']} | {m['formula']}")
            print(f"  Key: {m['key']}")
            print(f"  Preimage: {m['preimage']}")
    else:
        print("\nNo matches found.")
        print("The key is NOT a simple combination of known config values and static keys.")
        print("It may be: runtime-generated, server-provided, or use an unknown transformation.")

    return matches

if __name__ == "__main__":
    test_all()
