#!/bin/bash
# 组合脚本：启动 Frida Hook + WebSocket refresh 测试

echo "============================================================"
echo "步骤 1：启动 Frida Hook（后台）"
echo "============================================================"

# 启动 Frida（使用正确的参数）
frida -l frida_hooks/hook_simple_offset.js -f ~/.lingma/bin/2.11.2/x86_64_windows/Lingma.exe &
FRIDA_PID=$!

echo "Frida PID: $FRIDA_PID"
echo "等待灵码程序启动..."

# 等待灵码程序启动并监听 37010 端口
for i in {1..30}; do
    if netstat -an | grep -q "37010.*LISTENING"; then
        echo "✅ 检测到灵码程序监听 37010 端口"
        break
    fi
    echo "等待 $i 秒..."
    sleep 1
done

# 检查端口是否监听
if ! netstat -an | grep -q "37010.*LISTENING"; then
    echo "❌ 灵码程序未监听 37010 端口，可能启动失败"
    exit 1
fi

echo ""
echo "============================================================"
echo "步骤 2：运行 WebSocket refresh 测试"
echo "============================================================"

# 运行 WebSocket refresh 测试
python tools/ws_refresh_test.py

echo ""
echo "============================================================"
echo "步骤 3：清理"
echo "============================================================"

# 等待几秒让 Frida 输出完成
sleep 5

# 终止 Frida 进程
echo "终止 Frida 进程..."
kill $FRIDA_PID || true

echo "✅ 完成"