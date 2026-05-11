"""Verify encrypt_user_info inner content by comparing padding-aligned length."""
import json
import base64
from tools.credential_extractor import decrypt_cache_user
from pathlib import Path

data = decrypt_cache_user(Path.home() / '.lingma')

# Build the expected inner JSON (with empty key/encrypt_user_info)
inner = dict(data)
del inner['_machine_id']
inner['key'] = ''
inner['encrypt_user_info'] = ''

expected_json = json.dumps(inner, separators=(',', ':'), ensure_ascii=False, default=str)
print(f'Expected inner JSON length: {len(expected_json)}')
print(f'Expected padded length: {(len(expected_json.encode()) + 15) // 16 * 16}')

eui_bytes = base64.b64decode(data['encrypt_user_info'])
print(f'encrypt_user_info decoded length: {len(eui_bytes)}')
print(f'Match (with empty key/eui): {(len(expected_json.encode()) + 15) // 16 * 16 == len(eui_bytes)}')

# Also test without key/encrypt_user_info at all
inner_no_keui = {k: v for k, v in data.items()
                 if k not in ('_machine_id', 'key', 'encrypt_user_info')}
json_no_keui = json.dumps(inner_no_keui, separators=(',', ':'), ensure_ascii=False, default=str)
print(f'')
print(f'Without key/eui JSON length: {len(json_no_keui)}')
print(f'Without padded length: {(len(json_no_keui.encode()) + 15) // 16 * 16}')
print(f'Match (without key/eui): {(len(json_no_keui.encode()) + 15) // 16 * 16 == len(eui_bytes)}')

# Test with organization_tags = null vs omitted
inner_tags_null = dict(inner)
inner_tags_null['organization_tags'] = None
json_tags_null = json.dumps(inner_tags_null, separators=(',', ':'), ensure_ascii=False, default=str)
print(f'')
print(f'With org_tags=null length: {len(json_tags_null)}')
print(f'With org_tags=null padded: {(len(json_tags_null.encode()) + 15) // 16 * 16}')
print(f'Match (with null tags): {(len(json_tags_null.encode()) + 15) // 16 * 16 == len(eui_bytes)}')

# Go json.Marshal includes all fields (including zero values) unless omitempty
# Let's see what happens with organization_tags omitted
inner_tags_omitted = {k: v for k, v in inner.items() if k != 'organization_tags'}
json_tags_omitted = json.dumps(inner_tags_omitted, separators=(',', ':'), ensure_ascii=False, default=str)
print(f'')
print(f'Without org_tags length: {len(json_tags_omitted)}')
print(f'Without org_tags padded: {(len(json_tags_omitted.encode()) + 15) // 16 * 16}')
print(f'Match (without tags): {(len(json_tags_omitted.encode()) + 15) // 16 * 16 == len(eui_bytes)}')
