#!/usr/bin/env bash
set -euo pipefail

# === Config defaults ===
DEFAULT_VLESS_PORT="443"      # TCP
DEFAULT_HY2_PORT="8443"       # UDP
DEFAULT_TUIC_PORT="2053"      # UDP
DEFAULT_PSI_SOCKS_PORT="1081" # local socks5 provided by warp-plus
DEFAULT_PSI_COUNTRY="US"

SB_CONFIG_DIR="/etc/sing-box"
SB_CONFIG_FILE="${SB_CONFIG_DIR}/config.json"
WARPPLUS_BIN="/usr/local/bin/warp-plus"
WARPPLUS_DIR="/etc/warp-plus"
WARPPLUS_ENV="${WARPPLUS_DIR}/warp-plus.env"
WARPPLUS_SERVICE="/etc/systemd/system/warp-plus.service"

color() { local c="$1"; shift; printf "\033[%sm%s\033[0m\n" "$c" "$*"; }
info() { color "36" "[*] $*"; }
ok()   { color "32" "[+] $*"; }
warn() { color "33" "[!] $*"; }
err()  { color "31" "[-] $*"; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "请用 root 运行：sudo -i 或 sudo bash install.sh"
    exit 1
  fi
}

detect_pm() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return; fi
  if command -v dnf >/dev/null 2>&1; then echo "dnf"; return; fi
  if command -v yum >/dev/null 2>&1; then echo "yum"; return; fi
  err "不支持的系统：找不到 apt/dnf/yum"
  exit 1
}

install_deps() {
  local pm; pm="$(detect_pm)"
  info "安装依赖 (curl, jq, unzip, openssl, socat, ca-certificates)..."
  if [[ "$pm" == "apt" ]]; then
    apt-get update -y
    apt-get install -y curl jq unzip openssl socat ca-certificates cron
  else
    "$pm" -y install curl jq unzip openssl socat ca-certificates cronie || true
    systemctl enable --now crond >/dev/null 2>&1 || true
  fi
  ok "依赖安装完成"
}

read_input() {
  local prompt="$1" default="$2" var
  read -r -p "${prompt} (默认: ${default}): " var || true
  if [[ -z "${var}" ]]; then var="$default"; fi
  echo "$var"
}

get_arch() {
  local a; a="$(uname -m)"
  case "$a" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      err "不支持的架构: $a (仅支持 amd64/arm64)"
      exit 1
      ;;
  esac
}

install_singbox() {
  if command -v sing-box >/dev/null 2>&1; then
    ok "sing-box 已安装：$(sing-box version 2>/dev/null | head -n1 || true)"
    return
  fi
  info "安装 sing-box (官方脚本)..."
  # 官方安装方式（文档）
  curl -fsSL https://sing-box.app/install.sh | sh
  ok "sing-box 安装完成"
}

install_warpplus() {
  local arch; arch="$(get_arch)"
  info "安装 warp-plus (Psiphon 出站提供本地 SOCKS5)..."
  mkdir -p /tmp/warpplus && cd /tmp/warpplus

  # GitHub API: latest release asset
  local api="https://api.github.com/repos/bepass-org/warp-plus/releases/latest"
  local asset="warp-plus_linux-${arch}.zip"
  local url
  url="$(curl -fsSL "$api" | jq -r --arg A "$asset" '.assets[] | select(.name==$A) | .browser_download_url' | head -n1)"
  if [[ -z "${url}" || "${url}" == "null" ]]; then
    err "获取 warp-plus 下载链接失败（架构: ${arch}）"
    exit 1
  fi

  curl -fL "$url" -o "$asset"
  unzip -o "$asset" >/dev/null

  # zip 里通常就叫 warp-plus
  if [[ -f "warp-plus" ]]; then
    install -m 0755 "warp-plus" "$WARPPLUS_BIN"
  else
    # 兜底：找一个可执行文件
    local f
    f="$(find . -maxdepth 2 -type f -name 'warp-plus*' -perm -111 | head -n1 || true)"
    [[ -n "$f" ]] || { err "解压后未找到 warp-plus 可执行文件"; exit 1; }
    install -m 0755 "$f" "$WARPPLUS_BIN"
  fi

  ok "warp-plus 安装完成：$($WARPPLUS_BIN --help 2>/dev/null | head -n1 || echo OK)"
}

setup_cert() {
  local host="$1"
  local mode="$2"   # le/self
  local email="$3"
  local cert_path key_path

  mkdir -p /etc/ssl/sbox

  if [[ "$mode" == "le" ]]; then
    info "申请 Let's Encrypt 证书 (certbot standalone，需要 80/tcp 空闲)..."
    local pm; pm="$(detect_pm)"
    if [[ "$pm" == "apt" ]]; then
      apt-get install -y certbot
    else
      "$pm" -y install certbot || true
    fi

    systemctl stop nginx >/dev/null 2>&1 || true
    systemctl stop caddy >/dev/null 2>&1 || true
    systemctl stop apache2 >/dev/null 2>&1 || true
    systemctl stop httpd >/dev/null 2>&1 || true

    certbot certonly --standalone --agree-tos --non-interactive -m "$email" -d "$host"
    cert_path="/etc/letsencrypt/live/${host}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${host}/privkey.pem"

    [[ -f "$cert_path" && -f "$key_path" ]] || { err "证书文件不存在：${cert_path} / ${key_path}"; exit 1; }
    ok "证书申请成功：${cert_path}"
  else
    info "生成自签证书（客户端需跳过验证/允许不安全证书）..."
    cert_path="/etc/ssl/sbox/self.crt"
    key_path="/etc/ssl/sbox/self.key"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "$key_path" -out "$cert_path" \
      -subj "/CN=${host}"
    ok "自签证书生成：${cert_path}"
  fi

  echo "${cert_path}|${key_path}"
}

open_firewall() {
  local vless_port="$1" hy2_port="$2" tuic_port="$3"
  info "配置防火墙放行端口..."
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${vless_port}/tcp" || true
    ufw allow "${hy2_port}/udp" || true
    ufw allow "${tuic_port}/udp" || true
    ufw allow "22/tcp" || true
    ufw allow "80/tcp" || true
    ufw --force enable || true
    ok "ufw 已放行：${vless_port}/tcp, ${hy2_port}/udp, ${tuic_port}/udp"
  else
    warn "未检测到 ufw：请自行放行端口 ${vless_port}/tcp, ${hy2_port}/udp, ${tuic_port}/udp"
  fi
}

write_warpplus_service() {
  local country="$1" socks_port="$2"

  mkdir -p "$WARPPLUS_DIR"
  cat > "$WARPPLUS_ENV" <<EOF
# warp-plus env
COUNTRY=${country}
SOCKS_BIND=127.0.0.1:${socks_port}
EXTRA_FLAGS=--cfon
EOF

  cat > "$WARPPLUS_SERVICE" <<'EOF'
[Unit]
Description=warp-plus (WARP + Psiphon) local SOCKS5
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/warp-plus/warp-plus.env
ExecStart=/usr/local/bin/warp-plus ${EXTRA_FLAGS} --country ${COUNTRY} -b ${SOCKS_BIND}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now warp-plus
  ok "warp-plus 已启动（SOCKS5: 127.0.0.1:${socks_port}, 国家: ${country}）"
}

gen_keys() {
  info "生成 VLESS/TUIC UUID、HY2 密码、REALITY 密钥与 short_id..."
  local vless_uuid tuic_uuid tuic_pass hy2_pass hy2_obfs reality_json private_key public_key short_id

  vless_uuid="$(sing-box generate uuid)"
  tuic_uuid="$(sing-box generate uuid)"
  tuic_pass="$(openssl rand -base64 18 | tr -d '=+/ ' | head -c 16)"
  hy2_pass="$(openssl rand -base64 24 | tr -d '=+/ ' | head -c 20)"
  hy2_obfs="$(openssl rand -base64 24 | tr -d '=+/ ' | head -c 20)"

  reality_json="$(sing-box generate reality-keypair)"
  private_key="$(echo "$reality_json" | jq -r '.private_key')"
  public_key="$(echo "$reality_json" | jq -r '.public_key')"
  short_id="$(sing-box generate rand 8 --hex)"

  echo "${vless_uuid}|${tuic_uuid}|${tuic_pass}|${hy2_pass}|${hy2_obfs}|${private_key}|${public_key}|${short_id}"
}

write_singbox_config() {
  local host="$1"
  local vless_port="$2" hy2_port="$3" tuic_port="$4"
  local cert_path="$5" key_path="$6"
  local reality_server="$7"
  local vless_uuid="$8"
  local tuic_uuid="$9"
  local tuic_pass="${10}"
  local hy2_pass="${11}"
  local hy2_obfs="${12}"
  local reality_private="${13}"
  local short_id="${14}"
  local psi_socks_port="${15}"

  mkdir -p "$SB_CONFIG_DIR"

  # sing-box 入站：VLESS/REALITY + HY2 + TUIC
  # 出站：direct + socks(psiphon)；路由：TCP -> psiphon, UDP -> direct（更稳）
  cat > "$SB_CONFIG_FILE" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "in-vless-reality",
      "listen": "::",
      "listen_port": ${vless_port},
      "users": [
        {
          "name": "vless",
          "uuid": "${vless_uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${reality_server}",
            "server_port": 443
          },
          "private_key": "${reality_private}",
          "short_id": [
            "${short_id}"
          ],
          "max_time_difference": "1m"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "in-hy2",
      "listen": "::",
      "listen_port": ${hy2_port},
      "up_mbps": 0,
      "down_mbps": 0,
      "obfs": {
        "type": "salamander",
        "password": "${hy2_obfs}"
      },
      "users": [
        {
          "name": "hy2",
          "password": "${hy2_pass}"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "${cert_path}",
        "key_path": "${key_path}"
      }
    },
    {
      "type": "tuic",
      "tag": "in-tuic",
      "listen": "::",
      "listen_port": ${tuic_port},
      "users": [
        {
          "name": "tuic",
          "uuid": "${tuic_uuid}",
          "password": "${tuic_pass}"
        }
      ],
      "congestion_control": "bbr",
      "auth_timeout": "3s",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "${cert_path}",
        "key_path": "${key_path}"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    {
      "type": "socks",
      "tag": "psiphon",
      "server": "127.0.0.1",
      "server_port": ${psi_socks_port},
      "version": "5"
    }
  ],
  "route": {
    "rules": [
      { "network": "udp", "outbound": "direct" },
      { "network": "tcp", "outbound": "psiphon" }
    ],
    "final": "psiphon"
  }
}
EOF

  ok "sing-box 配置已写入：${SB_CONFIG_FILE}"
}

restart_singbox() {
  info "启动/重启 sing-box..."
  systemctl enable --now sing-box >/dev/null 2>&1 || true
  systemctl restart sing-box
  ok "sing-box 已启动"
}

print_client_info() {
  local host="$1"
  local vless_port="$2" hy2_port="$3" tuic_port="$4"
  local reality_server="$5"
  local vless_uuid="$6"
  local tuic_uuid="$7"
  local tuic_pass="$8"
  local hy2_pass="$9"
  local hy2_obfs="${10}"
  local reality_public="${11}"
  local short_id="${12}"
  local tls_mode="${13}"

  local insecure_hint=""
  if [[ "$tls_mode" != "le" ]]; then
    insecure_hint="（自签：客户端需要 skip-cert-verify / insecure=true）"
  fi

  echo ""
  echo "==================== 客户端参数（请妥善保存）===================="
  echo ""
  echo "[VLESS + REALITY]"
  echo "  地址: ${host}"
  echo "  端口: ${vless_port} (TCP)"
  echo "  UUID: ${vless_uuid}"
  echo "  Flow: xtls-rprx-vision"
  echo "  SNI/ServerName: ${reality_server}"
  echo "  Reality PublicKey (pbk): ${reality_public}"
  echo "  Reality ShortID (sid): ${short_id}"
  echo "  指纹(fp): chrome"
  echo ""
  echo "  参考分享链接格式(通用)："
  echo "  vless://${vless_uuid}@${host}:${vless_port}?encryption=none&security=reality&sni=${reality_server}&fp=chrome&pbk=${reality_public}&sid=${short_id}&type=tcp&flow=xtls-rprx-vision#vless-reality"
  echo ""
  echo "[Hysteria2] ${insecure_hint}"
  echo "  地址: ${host}"
  echo "  端口: ${hy2_port} (UDP)"
  echo "  密码: ${hy2_pass}"
  echo "  OBFS: salamander"
  echo "  OBFS密码: ${hy2_obfs}"
  echo "  ALPN: h3"
  echo "  SNI: ${host}"
  echo ""
  echo "[TUIC v5] ${insecure_hint}"
  echo "  地址: ${host}"
  echo "  端口: ${tuic_port} (UDP)"
  echo "  UUID: ${tuic_uuid}"
  echo "  密码: ${tuic_pass}"
  echo "  ALPN: h3"
  echo "  Congestion: bbr"
  echo ""
  echo "==============================================================="
  echo ""
  echo "管理命令："
  echo "  proxyctl status"
  echo "  proxyctl country US"
  echo "  proxyctl country-test US JP SG DE FR GB"
  echo "  proxyctl egress-test"
  echo ""
}

# -------------------- main --------------------
need_root
install_deps

HOST="$(read_input '请输入用于客户端连接的域名或IP（HOST）' 'example.com')"
VLESS_PORT="$(read_input 'VLESS+REALITY 端口(TCP)' "$DEFAULT_VLESS_PORT")"
HY2_PORT="$(read_input 'Hysteria2 端口(UDP)' "$DEFAULT_HY2_PORT")"
TUIC_PORT="$(read_input 'TUIC v5 端口(UDP)' "$DEFAULT_TUIC_PORT")"

REALITY_SERVER="$(read_input 'REALITY 伪装站点(需支持TLS1.3/H2，示例 www.microsoft.com)' 'www.microsoft.com')"

TLS_MODE="$(read_input 'HY2/TUIC TLS证书模式：le(自动申请) 或 self(自签)' 'self')"
EMAIL="admin@${HOST}"
if [[ "$TLS_MODE" == "le" ]]; then
  EMAIL="$(read_input 'Let'\''s Encrypt 邮箱（用于到期通知）' "$EMAIL")"
fi

PSI_COUNTRY="$(read_input 'Psiphon 出站国家(两位代码，如 US/JP/SG/DE...)' "$DEFAULT_PSI_COUNTRY")"
PSI_SOCKS_PORT="$(read_input 'warp-plus 本地 SOCKS5 端口' "$DEFAULT_PSI_SOCKS_PORT")"

open_firewall "$VLESS_PORT" "$HY2_PORT" "$TUIC_PORT"

install_singbox
install_warpplus

# cert
cert_pair="$(setup_cert "$HOST" "$TLS_MODE" "$EMAIL")"
CERT_PATH="${cert_pair%|*}"
KEY_PATH="${cert_pair#*|}"

# keys
keys="$(gen_keys)"
vless_uuid="$(echo "$keys" | cut -d'|' -f1)"
tuic_uuid="$(echo "$keys" | cut -d'|' -f2)"
tuic_pass="$(echo "$keys" | cut -d'|' -f3)"
hy2_pass="$(echo "$keys" | cut -d'|' -f4)"
hy2_obfs="$(echo "$keys" | cut -d'|' -f5)"
reality_private="$(echo "$keys" | cut -d'|' -f6)"
reality_public="$(echo "$keys" | cut -d'|' -f7)"
short_id="$(echo "$keys" | cut -d'|' -f8)"

write_warpplus_service "$PSI_COUNTRY" "$PSI_SOCKS_PORT"
write_singbox_config "$HOST" "$VLESS_PORT" "$HY2_PORT" "$TUIC_PORT" "$CERT_PATH" "$KEY_PATH" "$REALITY_SERVER" \
  "$vless_uuid" "$tuic_uuid" "$tuic_pass" "$hy2_pass" "$hy2_obfs" "$reality_private" "$short_id" "$PSI_SOCKS_PORT"

restart_singbox

# install proxyctl
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 0755 "${SCRIPT_DIR}/proxyctl" /usr/local/bin/proxyctl

print_client_info "$HOST" "$VLESS_PORT" "$HY2_PORT" "$TUIC_PORT" "$REALITY_SERVER" \
  "$vless_uuid" "$tuic_uuid" "$tuic_pass" "$hy2_pass" "$hy2_obfs" "$reality_public" "$short_id" "$TLS_MODE"

ok "完成"
