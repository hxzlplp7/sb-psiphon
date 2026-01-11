#!/usr/bin/env bash
set -euo pipefail

color() { local c="$1"; shift; printf "\033[%sm%s\033[0m\n" "$c" "$*"; }
info() { color "36" "[*] $*"; }
ok()   { color "32" "[+] $*"; }
warn() { color "33" "[!] $*"; }
err()  { color "31" "[-] $*"; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  err "请用 root 运行"
  exit 1
fi

info "停止并禁用服务..."
systemctl disable --now sing-box >/dev/null 2>&1 || true
systemctl disable --now warp-plus >/dev/null 2>&1 || true

info "删除 warp-plus 服务文件..."
rm -f /etc/systemd/system/warp-plus.service
systemctl daemon-reload || true

info "删除配置目录..."
rm -rf /etc/warp-plus
rm -rf /etc/sing-box

info "删除可执行文件..."
rm -f /usr/local/bin/warp-plus
rm -f /usr/local/bin/proxyctl
rm -f /usr/local/bin/sbmenu

info "清理自签证书..."
rm -rf /etc/ssl/sbox

# 可选：删除 sing-box（如果是通过官方脚本安装的）
if command -v sing-box >/dev/null 2>&1; then
  warn "sing-box 二进制文件保留（如需完全删除请手动执行：rm -f /usr/local/bin/sing-box）"
fi

ok "卸载完成"
echo ""
echo "注意事项："
echo "  - Let's Encrypt 证书保留在 /etc/letsencrypt/"
echo "  - sing-box 二进制可能保留，请手动清理"
echo "  - 防火墙规则未自动删除，请自行管理"
