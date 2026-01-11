#!/usr/bin/env bash
set -euo pipefail

# ========= 可调默认值 =========
DEFAULT_HOST="example.com"
DEFAULT_VLESS_PORT="443"
DEFAULT_HY2_PORT="8443"
DEFAULT_TUIC_PORT="2053"
DEFAULT_REALITY_SNI="www.apple.com"
DEFAULT_CERT_MODE="self"   # self | le
DEFAULT_PSIPHON_COUNTRY="US"
DEFAULT_PSIPHON_SOCKS="1081"

# ========= 工具函数 =========
red(){ echo -e "\033[31m$*\033[0m" >&2; }
grn(){ echo -e "\033[32m$*\033[0m" >&2; }
ylw(){ echo -e "\033[33m$*\033[0m" >&2; }

need_root(){
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    red "请用 root 运行：sudo -i"
    exit 1
  fi
}

detect_arch(){
  local a
  a="$(uname -m)"
  case "$a" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) red "不支持的架构: $a"; exit 1 ;;
  esac
}

detect_pm(){
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return; fi
  if command -v dnf >/dev/null 2>&1; then echo "dnf"; return; fi
  if command -v yum >/dev/null 2>&1; then echo "yum"; return; fi
  red "不支持的系统：找不到 apt/dnf/yum"
  exit 1
}

install_deps(){
  local pm
  pm="$(detect_pm)"
  ylw "[*] 安装依赖..."
  if [[ "$pm" == "apt" ]]; then
    apt-get update -y
    apt-get install -y curl jq unzip openssl ca-certificates socat cron
  else
    "$pm" -y install curl jq unzip openssl ca-certificates socat cronie || true
    systemctl enable --now crond >/dev/null 2>&1 || true
  fi
  grn "[+] 依赖安装完成"
}

prompt(){
  local var="$1" msg="$2" def="$3" val=""
  read -r -p "$msg (默认: $def): " val || true
  val="${val:-$def}"
  printf -v "$var" "%s" "$val"
}

gen_uuid(){
  cat /proc/sys/kernel/random/uuid
}

rand_hex(){
  openssl rand -hex "$1"
}

download_latest_github_release_asset(){
  local repo="$1" regex="$2"
  local api="https://api.github.com/repos/${repo}/releases/latest"
  local url
  url="$(curl -fsSL "$api" | jq -r ".assets[].browser_download_url" | grep -E "$regex" | head -n1 || true)"
  if [[ -z "$url" ]]; then
    red "找不到 ${repo} 的 release 资源：$regex"
    exit 1
  fi
  echo "$url"
}

# ========= warp-plus (Psiphon SOCKS5) =========
install_warp_plus(){
  local arch="$1"

  ylw "[*] 安装 warp-plus..."
  local api="https://api.github.com/repos/bepass-org/warp-plus/releases/latest"
  local asset="warp-plus_linux-${arch}.zip"
  local url
  url="$(curl -fsSL "$api" | jq -r --arg A "$asset" '.assets[] | select(.name==$A) | .browser_download_url' | head -n1)"
  
  if [[ -z "$url" || "$url" == "null" ]]; then
    red "获取 warp-plus 下载链接失败（架构: ${arch}）"
    exit 1
  fi

  rm -rf /tmp/warp-plus && mkdir -p /tmp/warp-plus
  curl -fsSL "$url" -o /tmp/warp-plus/pkg.zip
  unzip -q /tmp/warp-plus/pkg.zip -d /tmp/warp-plus || true

  local bin
  bin="$(find /tmp/warp-plus -type f -name "warp-plus" | head -n1 || true)"
  if [[ -z "$bin" ]]; then
    bin="$(find /tmp/warp-plus -type f -perm -111 | head -n1 || true)"
  fi
  if [[ -z "$bin" ]]; then
    red "warp-plus 包结构未知，未找到可执行文件"
    exit 1
  fi

  install -m 0755 "$bin" /usr/local/bin/warp-plus
  grn "[+] warp-plus 安装完成"

  mkdir -p /etc/warp-plus
  cat > /etc/warp-plus/config.json <<EOF
{
  "bind": "127.0.0.1:${PSIPHON_SOCKS}",
  "cfon": true,
  "country": "${PSIPHON_COUNTRY}"
}
EOF

  cat > /etc/systemd/system/warp-plus.service <<'EOF'
[Unit]
Description=warp-plus (WARP + Psiphon) local SOCKS5
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/warp-plus -4 -c /etc/warp-plus/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now warp-plus
  grn "[+] warp-plus 已启动（SOCKS5: 127.0.0.1:${PSIPHON_SOCKS}, 国家: ${PSIPHON_COUNTRY}）"
}

# ========= Xray (VLESS + REALITY) =========
install_xray_vless_reality(){
  local arch="$1"

  ylw "[*] 安装 Xray-core（VLESS+REALITY）..."
  local url
  if [[ "$arch" == "amd64" ]]; then
    url="$(download_latest_github_release_asset "XTLS/Xray-core" "Xray-linux-64.zip")"
  else
    url="$(download_latest_github_release_asset "XTLS/Xray-core" "Xray-linux-arm64-v8a.zip")"
  fi

  rm -rf /tmp/xray && mkdir -p /tmp/xray
  curl -fsSL "$url" -o /tmp/xray/xray.zip
  unzip -q /tmp/xray/xray.zip -d /tmp/xray

  install -m 0755 /tmp/xray/xray /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  cp -f /tmp/xray/*.dat /usr/local/share/xray/ 2>/dev/null || true

  # 生成 REALITY keypair
  local keypair priv pub sid uuid
  keypair="$(/usr/local/bin/xray x25519)"
  priv="$(echo "$keypair" | awk -F': ' '/Private key/ {print $2}')"
  pub="$(echo "$keypair" | awk -F': ' '/Public key/ {print $2}')"
  sid="$(rand_hex 8)"
  uuid="$(gen_uuid)"

  mkdir -p /etc/xray
  cat > /etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${uuid}", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "${REALITY_SNI}:443",
          "serverNames": ["${REALITY_SNI}"],
          "privateKey": "${priv}",
          "shortIds": ["${sid}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] }
    }
  ],
  "outbounds": [
    {
      "protocol": "socks",
      "tag": "psiphon",
      "settings": {
        "servers": [
          { "address": "127.0.0.1", "port": ${PSIPHON_SOCKS} }
        ]
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "psiphon", "network": "tcp,udp" }
    ]
  }
}
EOF

  cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray-core (VLESS+REALITY) Server
After=network-online.target warp-plus.service
Wants=network-online.target warp-plus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now xray
  grn "[+] Xray 已启动：VLESS+REALITY"

  XRAY_UUID="$uuid"
  XRAY_PUB="$pub"
  XRAY_SID="$sid"
}

# ========= Hysteria2 =========
install_hysteria2(){
  local arch="$1"

  ylw "[*] 安装 Hysteria2..."
  local url
  if [[ "$arch" == "amd64" ]]; then
    url="$(download_latest_github_release_asset "apernet/hysteria" "hysteria-linux-amd64$")"
  else
    url="$(download_latest_github_release_asset "apernet/hysteria" "hysteria-linux-arm64$")"
  fi

  curl -fsSL "$url" -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria

  local hy_pass obfs_pass
  hy_pass="$(rand_hex 12)"
  obfs_pass="$(rand_hex 12)"

  mkdir -p /etc/hysteria
  mkdir -p /etc/ssl/sbox

  # 生成自签证书（如果不存在）
  if [[ ! -f /etc/ssl/sbox/self.key ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout /etc/ssl/sbox/self.key -out /etc/ssl/sbox/self.crt \
      -subj "/CN=${HOST}" >/dev/null 2>&1
  fi

  if [[ "$CERT_MODE" == "le" ]]; then
    cat > /etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
acme:
  domains:
    - ${HOST}
  email: admin@${HOST}
auth:
  type: password
  password: ${hy_pass}
obfs:
  type: salamander
  salamander:
    password: ${obfs_pass}
outbounds:
  - name: psiphon
    type: socks5
    socks5:
      addr: 127.0.0.1:${PSIPHON_SOCKS}
EOF
  else
    cat > /etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
tls:
  cert: /etc/ssl/sbox/self.crt
  key: /etc/ssl/sbox/self.key
auth:
  type: password
  password: ${hy_pass}
obfs:
  type: salamander
  salamander:
    password: ${obfs_pass}
outbounds:
  - name: psiphon
    type: socks5
    socks5:
      addr: 127.0.0.1:${PSIPHON_SOCKS}
EOF
  fi

  cat > /etc/systemd/system/hysteria2.service <<'EOF'
[Unit]
Description=Hysteria2 Server
After=network-online.target warp-plus.service
Wants=network-online.target warp-plus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now hysteria2
  grn "[+] Hysteria2 已启动"

  HY2_PASS="$hy_pass"
  HY2_OBFS="$obfs_pass"
}

# ========= TUIC (EAimTY/tuic 官方实现) =========
install_tuic_server(){
  local arch="$1"

  ylw "[*] 安装 tuic-server..."
  local url
  if [[ "$arch" == "amd64" ]]; then
    url="$(download_latest_github_release_asset "EAimTY/tuic" "tuic-server.*x86_64.*linux" || true)"
  else
    url="$(download_latest_github_release_asset "EAimTY/tuic" "tuic-server.*aarch64.*linux" || true)"
  fi

  if [[ -z "$url" ]]; then
    ylw "[!] 未能自动获取 tuic-server，尝试备用方式..."
    # 尝试直接从 releases 列表获取
    local api="https://api.github.com/repos/EAimTY/tuic/releases"
    if [[ "$arch" == "amd64" ]]; then
      url="$(curl -fsSL "$api" | jq -r '.[0].assets[].browser_download_url' | grep -i "tuic-server.*x86_64.*linux" | head -n1 || true)"
    else
      url="$(curl -fsSL "$api" | jq -r '.[0].assets[].browser_download_url' | grep -i "tuic-server.*aarch64.*linux" | head -n1 || true)"
    fi
  fi

  if [[ -z "$url" ]]; then
    red "未能获取 tuic-server 下载链接，请手动下载放到 /usr/local/bin/tuic-server"
    exit 1
  fi

  curl -fsSL "$url" -o /usr/local/bin/tuic-server
  chmod +x /usr/local/bin/tuic-server

  local tuic_uuid tuic_pass
  tuic_uuid="$(gen_uuid)"
  tuic_pass="$(rand_hex 10)"

  mkdir -p /etc/tuic

  cat > /etc/tuic/config.json <<EOF
{
  "server": "[::]:${TUIC_PORT}",
  "users": {
    "${tuic_uuid}": "${tuic_pass}"
  },
  "certificate": "/etc/ssl/sbox/self.crt",
  "private_key": "/etc/ssl/sbox/self.key",
  "congestion_control": "bbr",
  "alpn": ["h3"],
  "zero_rtt_handshake": false,
  "auth_timeout": "3s",
  "max_idle_time": "10s",
  "log_level": "info"
}
EOF

  cat > /etc/systemd/system/tuic.service <<'EOF'
[Unit]
Description=tuic-server
After=network-online.target warp-plus.service
Wants=network-online.target warp-plus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/tuic-server -c /etc/tuic/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now tuic
  grn "[+] TUIC 已启动"

  TUIC_UUID="$tuic_uuid"
  TUIC_PASS="$tuic_pass"
}

# ========= proxyctl =========
install_proxyctl(){
  ylw "[*] 安装 proxyctl..."
  cat > /usr/local/bin/proxyctl <<'PROXYCTL_EOF'
#!/usr/bin/env bash
set -euo pipefail

CFG="/etc/warp-plus/config.json"
SOCKS_PORT="$(jq -r '.bind' "$CFG" 2>/dev/null | awk -F: '{print $2}' || echo "1081")"
COUNTRY="$(jq -r '.country' "$CFG" 2>/dev/null || echo "US")"

usage(){
  cat <<USAGE
proxyctl - 管理 warp-plus(Psiphon) 出站 + 出口测试

用法:
  proxyctl status               查看服务状态
  proxyctl country <CC>         切换出口国家
  proxyctl egress-test          测试当前出口 IP
  proxyctl country-test <CC...> 批量测试国家可用性
  proxyctl restart              重启所有服务
  proxyctl logs [wp|xray|hy2|tuic]
USAGE
}

egress_test(){
  curl -fsS --max-time 10 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://ipinfo.io/json 2>/dev/null \
    | jq -r '"IP: \(.ip)\nCountry: \(.country)\nOrg: \(.org)\nCity: \(.city)\nRegion: \(.region)"' || {
      echo "[-] 出口测试失败（SOCKS 无响应）"
      return 1
    }
}

case "${1:-}" in
  status)
    echo "========== warp-plus =========="
    echo "Country: ${COUNTRY}"
    echo "SOCKS : 127.0.0.1:${SOCKS_PORT}"
    systemctl --no-pager -l status warp-plus 2>/dev/null || echo "未运行"
    echo
    echo "========== xray =========="
    systemctl --no-pager -l status xray 2>/dev/null || echo "未运行"
    echo
    echo "========== hysteria2 =========="
    systemctl --no-pager -l status hysteria2 2>/dev/null || echo "未运行"
    echo
    echo "========== tuic =========="
    systemctl --no-pager -l status tuic 2>/dev/null || echo "未运行"
    ;;
  country)
    cc="${2:-}"
    if [[ -z "$cc" ]]; then usage; exit 1; fi
    cc="${cc^^}"
    tmp="$(mktemp)"
    jq --arg cc "$cc" '.country=$cc' "$CFG" > "$tmp"
    mv "$tmp" "$CFG"
    systemctl restart warp-plus
    echo "[+] 已切换国家为: $cc"
    ;;
  egress-test)
    egress_test
    ;;
  country-test)
    shift || true
    if [[ $# -lt 1 ]]; then usage; exit 1; fi
    ok=()
    fail=()
    for cc in "$@"; do
      cc="${cc^^}"
      echo "==> 测试 $cc"
      proxyctl country "$cc" >/dev/null 2>&1
      sleep 3
      if out="$(egress_test 2>/dev/null)"; then
        echo "$out"
        ok+=("$cc")
      else
        echo "[-] $cc 失败"
        fail+=("$cc")
      fi
      echo
    done
    echo "========== 汇总 =========="
    echo "成功: ${ok[*]:-无}"
    echo "失败: ${fail[*]:-无}"
    ;;
  restart)
    systemctl restart warp-plus xray hysteria2 tuic 2>/dev/null || true
    echo "[+] 已重启所有服务"
    ;;
  logs)
    case "${2:-}" in
      wp|warp) journalctl -u warp-plus -n 100 --no-pager ;;
      xray) journalctl -u xray -n 100 --no-pager ;;
      hy2|hysteria) journalctl -u hysteria2 -n 100 --no-pager ;;
      tuic) journalctl -u tuic -n 100 --no-pager ;;
      *) journalctl -u warp-plus -u xray -u hysteria2 -u tuic -n 100 --no-pager ;;
    esac
    ;;
  *)
    usage
    ;;
esac
PROXYCTL_EOF
  chmod +x /usr/local/bin/proxyctl
  grn "[+] proxyctl 已安装"
}

# ========= vpsmenu =========
install_menu(){
  ylw "[*] 安装菜单命令 vpsmenu..."
  cat > /usr/local/bin/vpsmenu <<'MENU_EOF'
#!/usr/bin/env bash
set -euo pipefail

while true; do
  clear
  cat <<MENU
╔══════════════════════════════════════════════════════╗
║     多协议入站 + Psiphon 出站 管理菜单               ║
╠══════════════════════════════════════════════════════╣
║  1) 查看服务状态        (proxyctl status)            ║
║  2) 查看当前出口 IP     (proxyctl egress-test)       ║
║  3) 切换出口国家        (proxyctl country <CC>)      ║
║  4) 批量测试国家可用性  (proxyctl country-test ...)  ║
║  5) 重启所有服务        (proxyctl restart)           ║
║  6) 查看日志            (proxyctl logs ...)          ║
║  0) 退出                                             ║
╚══════════════════════════════════════════════════════╝
MENU
  read -r -p "请选择 [0-6]: " c || true
  case "$c" in
    1) proxyctl status; read -r -p "回车继续..." _ ;;
    2) proxyctl egress-test; read -r -p "回车继续..." _ ;;
    3) 
      echo "常用: US JP SG DE FR GB NL HK TW KR"
      read -r -p "国家代码: " cc
      [[ -n "$cc" ]] && proxyctl country "$cc"
      read -r -p "回车继续..." _ 
      ;;
    4) 
      read -r -p "输入国家列表(空格分隔，如 US JP SG): " line
      # shellcheck disable=SC2086
      [[ -n "$line" ]] && proxyctl country-test $line
      read -r -p "回车继续..." _ 
      ;;
    5) proxyctl restart; read -r -p "回车继续..." _ ;;
    6) 
      echo "wp=warp-plus, xray, hy2=hysteria2, tuic"
      read -r -p "选择(默认全部): " t
      proxyctl logs "${t:-all}"
      read -r -p "回车继续..." _ 
      ;;
    0) exit 0 ;;
  esac
done
MENU_EOF
  chmod +x /usr/local/bin/vpsmenu
  grn "[+] vpsmenu 已安装：运行 vpsmenu 打开菜单"
}

# ========= 输出客户端信息 =========
print_client_info(){
  cat <<EOF

==================== 客户端参数（请妥善保存）====================

[VLESS + REALITY] (Xray)
  地址: ${HOST}
  端口: ${VLESS_PORT} (TCP)
  UUID: ${XRAY_UUID}
  Flow: xtls-rprx-vision
  SNI/ServerName: ${REALITY_SNI}
  Reality PublicKey (pbk): ${XRAY_PUB}
  Reality ShortID (sid): ${XRAY_SID}
  指纹(fp): chrome

  分享链接:
  vless://${XRAY_UUID}@${HOST}:${VLESS_PORT}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${XRAY_PUB}&sid=${XRAY_SID}&type=tcp&flow=xtls-rprx-vision#VLESS-Reality

[Hysteria2]
  地址: ${HOST}
  端口: ${HY2_PORT} (UDP)
  密码: ${HY2_PASS}
  OBFS: salamander
  OBFS密码: ${HY2_OBFS}
  证书: ${CERT_MODE} (self 模式客户端需 skip-cert-verify / insecure=true)

[TUIC v5]
  地址: ${HOST}
  端口: ${TUIC_PORT} (UDP)
  UUID: ${TUIC_UUID}
  密码: ${TUIC_PASS}
  Congestion: bbr
  ALPN: h3
  证书: self（客户端需 skip-cert-verify / insecure=true）

===============================================================

管理命令：
  vpsmenu             # 交互式菜单
  proxyctl status     # 查看状态
  proxyctl country US # 切换出口国家
  proxyctl egress-test
  proxyctl country-test US JP SG DE FR GB

EOF
}

# ========= main =========
main(){
  need_root
  local arch
  arch="$(detect_arch)"
  install_deps

  prompt HOST "请输入用于客户端连接的域名或IP（HOST）" "$DEFAULT_HOST"
  prompt VLESS_PORT "VLESS+REALITY 端口(TCP)" "$DEFAULT_VLESS_PORT"
  prompt HY2_PORT "Hysteria2 端口(UDP)" "$DEFAULT_HY2_PORT"
  prompt TUIC_PORT "TUIC v5 端口(UDP)" "$DEFAULT_TUIC_PORT"
  prompt REALITY_SNI "REALITY 伪装站点(需TLS1.3/H2，示例 www.apple.com)" "$DEFAULT_REALITY_SNI"
  prompt CERT_MODE "HY2/TUIC TLS证书模式：le(自动申请) 或 self(自签)" "$DEFAULT_CERT_MODE"
  prompt PSIPHON_COUNTRY "Psiphon 出站国家(两位代码，如 US/JP/SG/DE...)" "$DEFAULT_PSIPHON_COUNTRY"
  prompt PSIPHON_SOCKS "Psiphon 本地 SOCKS5 端口" "$DEFAULT_PSIPHON_SOCKS"

  ylw "[*] 请确保放行端口：${VLESS_PORT}/tcp, ${HY2_PORT}/udp, ${TUIC_PORT}/udp"

  install_warp_plus "$arch"
  install_xray_vless_reality "$arch"
  install_hysteria2 "$arch"
  install_tuic_server "$arch"

  install_proxyctl
  install_menu

  print_client_info
  grn "[+] 安装完成！"
}

main "$@"
