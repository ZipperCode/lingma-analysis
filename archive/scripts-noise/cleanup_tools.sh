#!/bin/bash
# 清理 tools 目录冗余脚本
# 将中间迭代产物移动到 archive 子目录，保留核心可用工具

set -e

TOOLS_DIR="D:/Project/lingma/tools"
ARCHIVE_DIR="$TOOLS_DIR/archive"

echo "=== Lingma Tools 清理脚本 ==="
echo "归档目录: $ARCHIVE_DIR"

# 创建归档目录
mkdir -p "$ARCHIVE_DIR"

# ============================================================
# 1. Frida Hook 迭代版本（保留最新和基础版）
# ============================================================
echo ""
echo "[1/7] 归档 Frida Hook 迭代版本..."

FRIDA_ARCHIVE=(
    # pipe hook 迭代 - 保留 frida_hook_pipe.py，归档 v2-v4
    "frida_hook_pipe_v2.py"
    "frida_hook_pipe_v3.py"
    "frida_hook_pipe_v4.py"
    # 通用 hook 迭代 - 保留 frida_hook_v15.py（最新），归档其他
    "frida_hook_v7.py"
    "frida_hook_v8.py"
    "frida_hook_v9.py"
    "frida_hook_v10.py"
    "frida_hook_v11.py"
    "frida_hook_v12.py"
    "frida_hook_v13.py"
    "frida_hook_v14.py"
    # appsalt 迭代 - 全部归档（分析已完成）
    "frida_hook_appsalt.py"
    "frida_hook_appsalt_v2.py"
    "frida_hook_appsalt_v3.py"
    "frida_hook_appsalt_v4.py"
    "frida_hook_appsalt_v5.py"
    "frida_hook_appsalt_v6.py"
    "frida_hook_appsalt_v7.py"
    "frida_getappsalt_v3.py"
    "frida_getappsalt_v4.py"
    "frida_getappsalt_v5.py"
    # encode 迭代
    "frida_hook_encode_v2.py"
    # body trace 迭代
    "frida_trace_body_v2.py"
)

for f in "${FRIDA_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$ARCHIVE_DIR/"
        echo "  → $f"
    fi
done

# ============================================================
# 2. 分析脚本迭代版本（保留最终版，归档中间版）
# ============================================================
echo ""
echo "[2/7] 归档分析脚本迭代版本..."

ANALYZE_ARCHIVE=(
    # 二进制分析迭代
    "analyze_binary_region_v2.py"
    # encoding 分析迭代
    "analyze_encoding_comprehensive.py"
    "analyze_encoding_deep.py"
    "analyze_encoding_diff.py"
    # encrypt 分析迭代
    "analyze_encrypt_refs2.py"
    # getappsalt 分析迭代 - 全部归档（分析已完成）
    "analyze_getappsalt_deep.py"
    "analyze_getappsalt_detail.py"
    "analyze_getappsalt_flow.py"
    "analyze_getappsalt_strings.py"
    # heartbeat 分析迭代
    "analyze_heartbeat2.py"
    "analyze_heartbeat3.py"
    "analyze_heartbeat4.py"
    "analyze_heartbeat5.py"
    "analyze_heartbeat6.py"
    "analyze_heartbeat_structure.py"
)

for f in "${ANALYZE_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$ARCHIVE_DIR/"
        echo "  → $f"
    fi
done

# ============================================================
# 3. 解密脚本迭代版本
# ============================================================
echo ""
echo "[3/7] 归档解密脚本迭代版本..."

DECRYPT_ARCHIVE=(
    "decrypt_with_key2.py"
    "decrypt_with_key3.py"
    "disasm_encrypt2.py"
)

for f in "${DECRYPT_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$ARCHIVE_DIR/"
        echo "  → $f"
    fi
done

# ============================================================
# 4. getappsalt 搜索/定位迭代版本
# ============================================================
echo ""
echo "[4/7] 归档 getappsalt 搜索脚本..."

SEARCH_ARCHIVE=(
    "find_appsalt_by_name.py"
    "find_appsalt_precise.py"
    "find_getappsalt.py"
    "find_getappsalt_callers.py"
    "find_getappsalt_direct.py"
    "find_getappsalt_final.py"
    "find_getappsalt_pclntab.py"
    "locate_getappsalt.py"
    "locate_getappsalt_final.py"
    "locate_getappsalt_v2.py"
    "test_frida_getappsalt.py"
    "verify_getappsalt.py"
    "confirm_getappsalt.py"
    "final_getappsalt.py"
)

for f in "${SEARCH_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$ARCHIVE_DIR/"
        echo "  → $f"
    fi
done

# ============================================================
# 5. Pipe/Frida 输出日志
# ============================================================
echo ""
echo "[5/7] 归档 Frida 输出日志..."

LOG_ARCHIVE=(
    "appsalt_v7_stderr.txt"
    "appsalt_v7_stdout.txt"
    "pipe_stderr.txt"
    "pipe_stdout.txt"
    "pipe_v2_stderr.txt"
    "pipe_v2_stdout.txt"
    "pipe_v3_stderr.txt"
    "pipe_v3_stdout.txt"
    "pipe_v3b_stderr.txt"
    "pipe_v3b_stdout.txt"
    "pipe_v4_stderr.txt"
    "pipe_v4_stdout.txt"
    "scan_stderr.txt"
    "scan_stdout.txt"
)

for f in "${LOG_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$ARCHIVE_DIR/"
        echo "  → $f"
    fi
done

# ============================================================
# 6. Hook/patch 中间产物
# ============================================================
echo ""
echo "[6/7] 归档 hook/patch 中间产物..."

PATCH_ARCHIVE=(
    "call_getappsalt_direct.py"
    "hook_caller_880da0.py"
    "hook_getappsalt.js"
    "hook_http_layer.py"
    "hook_mapassign.js"
    "hook_stalker.js"
    "patch_getappsalt.py"
    "patch_getappsalt_v2.py"
    "patch_getappsalt_v3.py"
    "test_patched.py"
    "test_patched_v3.py"
    "test_rva.py"
    "test_rva2.py"
    "scan_and_hook_functions.py"
    "resolve_lea_refs.py"
    "resolve_signing_refs.py"
    "resolve_caller_strings.py"
    "resolve_key_ptr.py"
    "deep_trace_signing.py"
    "final_brute.py"
)

for f in "${PATCH_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$ARCHIVE_DIR/"
        echo "  → $f"
    fi
done

# ============================================================
# 7. 分析 Markdown（归档到 docs/tools-archive/）
# ============================================================
echo ""
echo "[7/7] 归档分析 Markdown..."

mkdir -p "$TOOLS_DIR/../docs/tools-archive"

MD_ARCHIVE=(
    "auth_final_report.md"
    "getappsalt_analysis.md"
    "getappsalt_analysis_v2.md"
    "getappsalt_result.md"
    "signing_analysis.md"
    "signing_final.md"
    "next_steps.md"
)

for f in "${MD_ARCHIVE[@]}"; do
    if [ -f "$TOOLS_DIR/$f" ]; then
        mv "$TOOLS_DIR/$f" "$TOOLS_DIR/../docs/tools-archive/"
        echo "  → docs/tools-archive/$f"
    fi
done

# ============================================================
# 统计结果
# ============================================================
echo ""
echo "=== 清理完成 ==="
echo "归档文件数: $(ls -1 "$ARCHIVE_DIR/" | wc -l)"
echo "tools 目录剩余文件数: $(ls -1 "$TOOLS_DIR/" | wc -l)"
echo "tools 目录剩余目录数: $(ls -1d "$TOOLS_DIR"/*/ 2>/dev/null | wc -l)"
