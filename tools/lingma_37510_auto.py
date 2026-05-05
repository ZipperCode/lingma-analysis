#!/usr/bin/env python3
"""获取 login URL -> 停止 Lingma -> 启动模拟服务器"""
import json, re, time, sys, subprocess, urllib.parse, webbrowser, threading, http.server, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lingma_37510_server import *

def stop_lingma():
    """停止 Lingma 进程释放 37510"""
    print("[*] 停止 Lingma 释放 37510...")
    subprocess.run(["taskkill", "/f", "/im", "Lingma.exe"],
                   capture_output=True, timeout=10)
    time.sleep(2)

    # 等待 37510 释放
    for i in range(10):
        try:
            import socket
            s = socket.socket()
            s.settimeout(0.5)
            s.connect(("127.0.0.1", CALLBACK_PORT))
            s.close()
            time.sleep(1)
        except:
            print(f"  [✓] 端口 {CALLBACK_PORT} 已释放")
            return
    print(f"  [!] 端口 {CALLBACK_PORT} 可能仍被占用")

def main():
    print("=" * 60)
    print("Lingma 37510 模拟服务器 (自动模式)")
    print("=" * 60)

    machine_id = str(uuid.uuid4())
    print(f"[*] Machine ID: {machine_id}")

    # 1. 获取 login URL
    print(f"\n{'='*60}")
    print("Step 1: 获取 Login URL")
    print(f"{'='*60}")
    login_info = get_login_url_via_lsp()
    if not login_info.get("login_url"):
        print("[!] 失败")
        sys.exit(1)

    login_url = login_info["login_url"]
    auth_report = login_info.get("auth_report", {})
    url_params = login_info.get("url_params", {})

    if auth_report:
        print(f"\n  [*] auth/report 已获取到 token 信息")

    # 2. 停止 Lingma
    print(f"\n{'='*60}")
    print("Step 2: 停止 Lingma 释放 37510")
    print(f"{'='*60}")
    stop_lingma()

    # 3. 启动我们的 37510 服务器
    print(f"\n{'='*60}")
    print("Step 3: 启动模拟 37510 服务器")
    print(f"{'='*60}")
    server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"  [*] http://127.0.0.1:{CALLBACK_PORT}/auth/callback")

    # 4. 修改 redirect_uri 指向我们的 37510
    print(f"\n{'='*60}")
    print("Step 4: 打开浏览器")
    print(f"{'='*60}")
    final_url = re.sub(
        r'redirect_uri=[^&]*',
        f'redirect_uri=http%3A%2F%2F127.0.0.1%3A{CALLBACK_PORT}%2Fauth%2Fcallback',
        login_url
    )
    final_url = re.sub(r'port=(\d+)', f'port={CALLBACK_PORT}', final_url)
    print(f"  URL: {final_url[:120]}...")
    webbrowser.open(final_url)

    # 5. 等待回调
    print(f"\n{'='*60}")
    print("Step 5: 等待 OAuth 回调 (180s)")
    print(f"{'='*60}")
    if not CallbackHandler.result_event.wait(timeout=180):
        print("\n[!] 超时")
        server.shutdown()
        sys.exit(1)
    server.shutdown()

    params = CallbackHandler.captured["query_params"]
    print(f"\n  回调数据: {json.dumps(params, indent=2)}")

    # 6. 后端 API 交互
    print(f"\n{'='*60}")
    print("Step 6: 后端 API 交互")
    print(f"{'='*60}")
    cb_aid, cb_uid, cb_name = params.get("aid",""), params.get("uid",""), params.get("name","")
    auth = build_auth_string(cb_uid, cb_aid, cb_name)
    print(f"  Auth ({len(auth)} chars)")

    # 如果有 auth/report 数据，直接保存
    if auth_report:
        print(f"\n  [*] auth/report 已有 token，直接保存")
        creds = {
            "machine_id": machine_id,
            "user_id": auth_report.get("uid", cb_uid),
            "user_name": auth_report.get("name", cb_name),
            "security_oauth_token": auth_report.get("token", ""),
            "refresh_token": auth_report.get("refreshToken", ""),
            "expire_time": auth_report.get("tokenExpireTime", 0),
        }
        save_portable_creds(creds)
        print(f"  [✓] 凭据已保存")
    else:
        # 调用后端 API
        print(f"\n  [*] 调用 /api/v3/user/login...")
        s, r = call_user_login(machine_id, cb_aid, cb_uid, cb_name)
        print(f"  -> HTTP {s}")
        if s != 200 and r.get("body"):
            print(f"  error: {r['body'][:200]}")

        print(f"\n  [*] 调用 /api/v3/user/status...")
        s, r = call_user_status(machine_id, cb_uid)
        print(f"  -> HTTP {s}")
        if s == 200:
            print(f"  [✓] 成功: {json.dumps(r, ensure_ascii=False)[:200]}")
        elif s != 0 and r.get("body"):
            print(f"  error: {r['body'][:200]}")

    print(f"\n{'='*60}")
    print("完成！喵~ o(*￣︶￣*)o")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
