#!/usr/bin/env python3
"""
组合测试：启动 Frida Hook + WebSocket refresh + 监控认证函数调用

流程：
1. Frida spawn 灵码程序并安装 Hook
2. 等待灵码监听 37010 端口
3. 运行 ws_refresh_test.py 触发 refresh
4. 观察 Frida Hook 输出，验证签名参数顺序
"""

import subprocess
import time
import sys
import socket
import threading
import queue

def wait_for_port(port=37010, timeout=30):
    """等待指定端口监听"""
    print(f"[*] 等待端口 {port} 监听...")
    for i in range(timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                print(f"✅ 端口 {port} 已监听（{i} 秒）")
                return True
        except:
            pass
        time.sleep(1)
    print(f"❌ 端口 {port} 未监听（超时 {timeout} 秒）")
    return False

def run_frida():
    """运行 Frida Hook"""
    print("\n" + "="*60)
    print("步骤 1：启动 Frida Hook")
    print("="*60)

    cmd = [
        'frida',
        '-l', 'frida_hooks/hook_simple_offset.js',
        '-f', r'C:\Users\Zipper\.lingma\bin\2.11.2\x86_64_windows\Lingma.exe'
    ]

    print(f"命令: {' '.join(cmd)}")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )

    return process

def run_ws_refresh_test():
    """运行 WebSocket refresh 测试"""
    print("\n" + "="*60)
    print("步骤 3：运行 WebSocket refresh 测试")
    print("="*60)

    cmd = ['python', 'tools/ws_refresh_test.py']
    print(f"命令: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20
        )

        print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print("❌ WebSocket 测试超时")
        return False
    except Exception as e:
        print(f"❌ WebSocket 测试失败: {e}")
        return False

def monitor_frida_output(process, output_queue, stop_event):
    """监控 Frida 输出"""
    print("\n" + "="*60)
    print("步骤 2：监控 Frida 输出")
    print("="*60)

    while not stop_event.is_set():
        try:
            line = process.stdout.readline()
            if line:
                output_queue.put(line)
                print(line.rstrip())

                # 检查关键输出
                if 'getAuthSignature] Called' in line:
                    print("\n🎉 检测到认证函数被触发！")
                elif 'Signature (MD5)' in line:
                    print("\n✅ 签名计算完成！")

            if process.poll() is not None:
                print("\nFrida 进程已退出")
                break

        except:
            break

def main():
    print("="*60)
    print("组合测试：Frida + WebSocket Refresh")
    print("="*60)

    # 启动 Frida
    frida_process = run_frida()
    output_queue = queue.Queue()
    stop_event = threading.Event()

    # 启动 Frida 输出监控线程
    monitor_thread = threading.Thread(
        target=monitor_frida_output,
        args=(frida_process, output_queue, stop_event)
    )
    monitor_thread.start()

    # 等待灵码监听 37010 端口
    if not wait_for_port(37010, 30):
        print("\n❌ 灵码程序启动失败，终止测试")
        stop_event.set()
        frida_process.terminate()
        monitor_thread.join()
        sys.exit(1)

    # 运行 WebSocket refresh 测试
    ws_success = run_ws_refresh_test()

    # 等待 Frida 处理完成
    print("\n等待 Frida Hook 输出...")
    time.sleep(5)

    # 清理
    stop_event.set()
    frida_process.terminate()
    monitor_thread.join()

    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    print(f"WebSocket 测试: {'✅ 成功' if ws_success else '❌ 失败'}")
    print("Frida Hook 输出已捕获")

    # 检查是否有认证函数调用
    print("\n检查 Frida 输出中是否有认证函数调用...")
    found_auth = False
    while not output_queue.empty():
        line = output_queue.get()
        if 'getAuthSignature] Called' in line:
            found_auth = True
            break

    if found_auth:
        print("✅ 检测到认证函数被调用")
        print("💡 请查看上方 Frida 输出，验证签名参数顺序")
    else:
        print("⚠️ 未检测到认证函数调用")
        print("   可能原因：")
        print("   1. WebSocket refresh 未触发 HTTP 认证")
        print("   2. Token 未过期，不需要刷新")
        print("   3. Frida Hook 未正确安装")

    print("\n✅ 测试完成")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断测试")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        sys.exit(1)