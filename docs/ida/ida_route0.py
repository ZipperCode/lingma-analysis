import ida_bytes, json
raw = ida_bytes.get_bytes(0x1424BD2C0, 20)
if raw:
    for i in range(len(raw)):
        if raw[i] == 0:
            s = raw[:i].decode(errors='replace')
            result = {'route0_bytes': raw[:i].hex(), 'route0_str': s}
            break
    else:
        s = raw.decode(errors='replace')
        result = {'route0_bytes': raw.hex(), 'route0_str': s}
else:
    result = {'error': 'Failed'}
print(json.dumps(result))
