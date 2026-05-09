#!/usr/bin/env python3
"""
Exhaustive session_key oracle brute-force.
Tests ALL formula variations against the 7 known (Date, Signature) pairs.
"""
import hashlib
import base64

# All known oracles from capture files
ORACLES = [
    ("Fri, 24 Apr 2026 07:54:36 GMT", "e8b434d0a2596ca2ff99c60c4756a1ff"),
    ("Fri, 24 Apr 2026 14:23:16 GMT", "8d915d7d99452c143dc52ce040b9a355"),
    ("Fri, 24 Apr 2026 14:26:16 GMT", "e7d5d7c586d345ad664fff195518b425"),
    ("Fri, 24 Apr 2026 14:29:16 GMT", "0a12e309cb9d31686a753ab261deaf15"),
    ("Fri, 24 Apr 2026 13:43:57 GMT", "9856df4b14fd343d0deb0018874c2a30"),
    ("Fri, 24 Apr 2026 13:45:32 GMT", "9186780ae747446a74b0c555c686b38d"),
    ("Fri, 24 Apr 2026 13:46:37 GMT", "47e0e4e4f3ce25b2d1e9e8e4f3ce25b2"),  # might be approximate
]

# Known keys from static analysis
LONG_KEY = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"   # 32 chars, used when flag=1
SHORT_KEY = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="     # 32 chars, used when flag=0
SHORT_KEY_DECODED = "war, war never changes"          # 24 chars
PREFIX_KEY = LONG_KEY  # Alias
HEX_TAIL = "9f1dff714a390b20aeb19175ecc496e6"         # 32 hex chars

# Additional key candidates from .rodata
# The hex tail might be MD5 of something, or might BE a key
TAIL_BYTES = bytes.fromhex(HEX_TAIL)

# Build candidate list
CANDIDATES = []

# 1. Long key as-is (32 chars ASCII)
CANDIDATES.append(("long_key", LONG_KEY))

# 2. Short key as-is (32 chars ASCII)
CANDIDATES.append(("short_key_b64", SHORT_KEY))

# 3. Short key decoded (24 chars)
CANDIDATES.append(("short_key_decoded", SHORT_KEY_DECODED))

# 4. Long key with different truncations
for n in [16, 24, 31, 33, 48, 64]:
    CANDIDATES.append((f"long_key_{n}", LONG_KEY[:n]))

# 5. Short key with different truncations
for n in [16, 24, 31, 33]:
    CANDIDATES.append((f"short_key_{n}", SHORT_KEY[:n]))

# 6. Hex tail as key
CANDIDATES.append(("hex_tail", HEX_TAIL))
CANDIDATES.append(("hex_tail_bytes", TAIL_BYTES.hex()))

# 7. Combinations
CANDIDATES.append(("long+hex", LONG_KEY + HEX_TAIL))

# 8. Cosy prefix variations
CANDIDATES.append(("cosy", "cosy"))
CANDIDATES.append(("cosyauthsigntest", "cosyauthsigntest"))

# Date format variations
def date_variants(rfc1123):
    """Generate all date format variants."""
    variants = []
    variants.append(("rfc1123", rfc1123))

    # Unix timestamp
    from email.utils import parsedate_to_datetime
    dt = parsedate_to_datetime(rfc1123)
    unix = str(int(dt.timestamp()))
    variants.append(("unix", unix))

    # Various date formats
    variants.append(("rfc1123_no_gmt", rfc1123.replace(" GMT", "")))
    variants.append(("rfc1123_utc", rfc1123.replace("GMT", "UTC")))
    variants.append(("iso8601", dt.strftime("%Y-%m-%dT%H:%M:%SZ")))
    variants.append(("date_only", dt.strftime("%Y-%m-%d")))
    variants.append(("rfc850", dt.strftime("%A, %d-%b-%y %H:%M:%S GMT")))
    variants.append(("asctime", dt.strftime("%a %b %d %H:%M:%S %Y")))

    return variants

# Formula generators
def gen_formulas(key, date_str):
    """Generate (preimage, MD5) for all formula variations."""
    results = []

    key_str = key if isinstance(key, str) else key.decode()

    # Direct concatenations
    for sep in ["", "|", "\n", ":", " ", "||", "|\n|"]:
        for order in [
            [date_str, key_str],
            [key_str, date_str],
            ["cosy", key_str, date_str],
            ["cosy", date_str, key_str],
            [key_str, "cosy", date_str],
            [date_str, "cosy", key_str],
            ["COSY", key_str, date_str],
            ["COSY", date_str, key_str],
            ["Cosy", key_str, date_str],
        ]:
            preimage = sep.join(order)
            md5 = hashlib.md5(preimage.encode()).hexdigest()
            results.append((f"join('{sep}') {order}", preimage, md5))

    # With key as hex-decoded
    try:
        key_bytes = bytes.fromhex(key_str)
        for sep in ["", "|", "\n"]:
            for order in [
                [date_str, key_bytes.hex()],
                [key_bytes.hex(), date_str],
            ]:
                preimage = sep.join(order)
                md5 = hashlib.md5(preimage.encode()).hexdigest()
                results.append((f"hex_key join('{sep}') {order}", preimage, md5))
    except ValueError:
        pass

    # Upper/lower case variations
    for sep in ["", "|", "\n"]:
        for order in [[date_str, key_str], [key_str, date_str]]:
            for case in ["upper", "lower"]:
                preimage = sep.join(order)
                if case == "upper":
                    preimage = preimage.upper()
                else:
                    preimage = preimage.lower()
                md5 = hashlib.md5(preimage.encode()).hexdigest()
                results.append((f"{case} join('{sep}') {order}", preimage, md5))

    return results


def test_oracles():
    """Test all formulas against all oracles."""
    from email.utils import parsedate_to_datetime

    print("=" * 100)
    print("EXHAUSTIVE SESSION KEY ORACLE TESTING")
    print(f"Oracles: {len(ORACLES)}")
    print(f"Candidates: {len(CANDIDATES)}")
    print("=" * 100)

    total_tests = 0
    matches = []

    for cand_name, cand_key in CANDIDATES:
        # Generate all date variants for the first oracle
        base_date = ORACLES[0][0]
        for date_name, date_str in date_variants(base_date):
            for formula_name, preimage, md5 in gen_formulas(cand_key, date_str):
                total_tests += 1

                # Test against first oracle
                if md5 == ORACLES[0][1]:
                    # Verify against ALL oracles
                    all_match = True
                    for oracle_date, oracle_sig in ORACLES[1:]:
                        dt = parsedate_to_datetime(oracle_date)
                        if date_name == "rfc1123":
                            test_date = oracle_date
                        elif date_name == "unix":
                            test_date = str(int(dt.timestamp()))
                        elif date_name == "rfc1123_no_gmt":
                            test_date = oracle_date.replace(" GMT", "")
                        elif date_name == "rfc1123_utc":
                            test_date = oracle_date.replace("GMT", "UTC")
                        elif date_name == "iso8601":
                            test_date = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                        elif date_name == "date_only":
                            test_date = dt.strftime("%Y-%m-%d")
                        elif date_name == "rfc850":
                            test_date = dt.strftime("%A, %d-%b-%y %H:%M:%S GMT")
                        elif date_name == "asctime":
                            test_date = dt.strftime("%a %b %d %H:%M:%S %Y")
                        else:
                            all_match = False
                            break

                        # Reconstruct preimage with the test date
                        preimage_test = preimage.replace(date_str, test_date)
                        md5_test = hashlib.md5(preimage_test.encode()).hexdigest()
                        if md5_test != oracle_sig:
                            all_match = False
                            break

                    if all_match:
                        matches.append({
                            'candidate': cand_name,
                            'date_fmt': date_name,
                            'formula': formula_name,
                            'preimage': preimage,
                            'md5': md5,
                        })
                        print(f"\n*** MATCH FOUND ***")
                        print(f"  Candidate: {cand_name}")
                        print(f"  Date format: {date_name}")
                        print(f"  Formula: {formula_name}")
                        print(f"  Preimage: {preimage[:100]}")
                        print(f"  MD5: {md5}")
                        print(f"  Verified against all {len(ORACLES)} oracles!")

    print(f"\n{'=' * 100}")
    print(f"Total tests: {total_tests}")
    print(f"Matches found: {len(matches)}")

    if matches:
        print("\n*** ALL MATCHING FORMULAS ***")
        for m in matches:
            print(f"  {m['candidate']} | {m['date_fmt']} | {m['formula']}")
            print(f"    Preimage: {m['preimage'][:120]}")

    return matches

if __name__ == "__main__":
    test_oracles()
