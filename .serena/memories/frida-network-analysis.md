# Frida Network Analysis - Lingma Remote Connections

## Analysis Date
2026-04-26

## Key Findings

### Remote Host Confirmed via Frida
- **DNS hook (GetAddrInfoW)**: Lingma resolves `lingma.alibabacloud.com` during chat
- **TLS data flow**: Large TLS records sent to this host (293B ClientHello, 64+86B handshake, then 16KB+ application data chunks)
- **Socket pattern**: AF_INET6 sockets created first, then converted to AF_INET for actual connection

### Go Network Stack on Windows
- **Standard connect APIs NOT used**: Go bypasses ws2_32.dll's `connect`, `WSAConnect`, `WSAConnectByList`, `WSAConnectByNameW` — all hooked but NONE fire
- **ConnectEx via WSAIoctl**: Go uses `WSAIoctl` with `SIO_GET_EXTENSION_FUNCTION_POINTER` (0xC8000006) to get extension function pointers from mswsock.dll
- **GUID observed**: `{b5367df1-cbac-11cf-95ca-00805f48a192}` = AcceptEx (for local WebSocket server)
- **ConnectEx GUID**: `{25a207b9-ddf3-4660-8ee9-76e58c74063e}` — not observed (already cached before Frida attach)
- **SIO_SET_COMPATIBILITY_MODE** (0x98000004): Called on every socket before TLS handshake

### Frida Hook Architecture Tested
| Script | What It Hooks | Result |
|--------|--------------|--------|
| `frida_minimal_hook.js` | connect, WSASend, WSARecv | No connect events; TLS data via send |
| `frida_dns_trace.py` | getaddrinfo, gethostbyname, WSASocketW, connect, send | No DNS/connect; sockets + TLS data seen |
| `frida_go_dial.py` | WSASocketW, connect, WSAConnect + stack traces | No connect events |
| `frida_connect_all.py` | ALL ws2 connect variants + mswsock ConnectEx | No connect events; GetAddrInfoW("l") partial read |
| `frida_connect_and_chat.py` | All connect variants + full chat trigger | No connect events; GetAddrInfoW correct read |
| `frida_wsaioctl_hook.py` | WSAIoctl + ConnectEx dynamic hook | SIO_GET_EXTENSION detected (signed/unsigned bug) |
| `frida_wsaioctl_v2.py` | Fixed WSAIoctl + ConnectEx dynamic hook | AcceptEx hooked dynamically; ConnectEx pre-cached |

### Root Cause: ConnectEx Pre-cached
Go's net package calls `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` to get ConnectEx **once at startup**. Since Frida attached after startup, this initialization was missed. The dynamic hook successfully caught AcceptEx acquisition but ConnectEx was already cached.

### Remote API Verified Working
- `lingma_remote_api.py` successfully calls `https://lingma.alibabacloud.com/algo/api/v2/service/pro/sse/agent_chat_generation`
- COSY Bearer auth works with credentials from `cache/user`
- Model list returned: qwen3-coder, qwen3-thinking, qwen2.5-max, etc.
- Chat test returned "Success" — full round-trip working

### Frida Scripts Created
| File | Purpose |
|------|---------|
| `tools/frida_connect_all.py` | Hooks ALL ws2_32 connect variants + mswsock ConnectEx |
| `tools/frida_connect_and_chat.py` | Combined hook + chat trigger |
| `tools/frida_wsaioctl_hook.py` | WSAIoctl hook (first version, signed/unsigned bug) |
| `tools/frida_wsaioctl_v2.py` | Fixed WSAIoctl hook with dynamic ConnectEx hooking |
| `tools/frida_dns_trace.py` | DNS + socket + TLS send tracing |
| `tools/frida_go_dial.py` | Go-level export enumeration + WSA hooking |
| `tools/frida_chat_real.py` | Chat flow with Frida hooks |
| `tools/frida_spawn_trace.py` | Spawn Lingma from startup with hooks |
| `tools/frida_minimal_hook.js` | Core Frida hook script (connect + WSASend + WSARecv + TLS SNI extraction) |
