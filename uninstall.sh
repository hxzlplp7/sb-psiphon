#!/usr/bin/env bash
set -euo pipefail

red(){ echo -e "\033[31m$*\033[0m" >&2; }
grn(){ echo -e "\033[32m$*\033[0m" >&2; }
ylw(){ echo -e "\033[33m$*\033[0m" >&2; }

need_root(){
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    red "请用 root 运行：sudo -i"
    exit 1
  fi
}

need_root

ylw "[*] 停止并禁用服务..."
systemctl disable --now warp-plus 2>/dev/null || true
systemctl disable --now xray 2>/dev/null || true
systemctl disable --now hysteria2 2>/dev/null || true
systemctl disable --now tuic 2>/dev/null || true
systemctl disable --now sing-box 2>/dev/null || true

ylw "[*] 删除 systemd 服务文件..."
rm -f /etc/systemd/system/warp-plus.service
rm -f /etc/systemd/system/xray.service
rm -f /etc/systemd/system/hysteria2.service
rm -f /etc/systemd/system/tuic.service
rm -f /etc/systemd/system/sing-box.service 2>/dev/null || true
systemctl daemon-reload

ylw "[*] 删除配置目录..."
rm -rf /etc/warp-plus
rm -rf /etc/xray
rm -rf /etc/hysteria
rm -rf /etc/tuic
rm -rf /etc/sing-box 2>/dev/null || true

ylw "[*] 删除可执行文件..."
rm -f /usr/local/bin/warp-plus
rm -f /usr/local/bin/xray
rm -f /usr/local/bin/hysteria
rm -f /usr/local/bin/tuic-server
rm -f /usr/local/bin/sing-box 2>/dev/null || true
rm -f /usr/local/bin/proxyctl
rm -f /usr/local/bin/vpsmenu
rm -f /usr/local/bin/sbmenu 2>/dev/null || true

ylw "[*] 清理自签证书..."
rm -rf /etc/ssl/sbox

ylw "[*] 清理 Xray 数据文件..."
rm -rf /usr/local/share/xray

grn "[+] 卸载完成"
echo ""
echo "注意事项："
echo "  - Let's Encrypt 证书保留在 /etc/letsencrypt/"
echo "  - 防火墙规则未自动删除，请自行管理"
