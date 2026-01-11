#!/usr/bin/env bash
set -euo pipefail

# ========= 可调默认值 =========
DEFAULT_HOST="example.com"
DEFAULT_VLESS_PORT="443"
DEFAULT_HY2_PORT="8443"
DEFAULT_TUIC_PORT="2053"
DEFAULT_REALITY_SNI="www.apple.com"
DEFAULT_CERT_MODE="self"   # self | le
DEFAULT_PSIPHON_REGION="US"
DEFAULT_PSIPHON_SOCKS="1081"
DEFAULT_PSIPHON_HTTP="8081"

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

# 确保 curl/wget 可用
ensure_downloader(){
  if command -v curl >/dev/null 2>&1; then
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    return 0
  fi
  ylw "[*] 检测到 curl/wget 未安装，正在安装..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl wget >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y install curl wget >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum -y install curl wget >/dev/null 2>&1
  else
    red "无法自动安装 curl/wget，请手动安装后重试"
    exit 1
  fi
  grn "[+] curl/wget 已安装"
}

# 入口点
need_root
ensure_downloader

detect_arch(){
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "x86_64" ;;
    i386|i686)    echo "i686" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv6l) echo "arm" ;;
    *) echo "unknown" ;;
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
    apt-get install -y curl wget jq unzip openssl ca-certificates socat cron
  else
    "$pm" -y install curl wget jq unzip openssl ca-certificates socat cronie || true
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

download_file(){
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  else
    wget -qO "$dest" "$url"
  fi
}

download_latest_github_release_asset(){
  local repo="$1" regex="$2"
  local api="https://api.github.com/repos/${repo}/releases/latest"
  local url
  if command -v curl >/dev/null 2>&1; then
    url="$(curl -fsSL "$api" | jq -r ".assets[].browser_download_url" | grep -E "$regex" | head -n1 || true)"
  else
    url="$(wget -qO- "$api" | jq -r ".assets[].browser_download_url" | grep -E "$regex" | head -n1 || true)"
  fi
  if [[ -z "$url" ]]; then
    red "找不到 ${repo} 的 release 资源：$regex"
    exit 1
  fi
  echo "$url"
}

# ========= Psiphon ConsoleClient (官方二进制) =========
install_psiphon(){
  local arch
  arch="$(detect_arch)"

  ylw "[*] 安装 Psiphon ConsoleClient..."
  mkdir -p /etc/psiphon /var/lib/psiphon

  if [[ "$arch" == "x86_64" || "$arch" == "i686" ]]; then
    # 官方二进制：psiphon-tunnel-core-binaries 仓库只有 x86_64 和 i686
    local url="https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/linux/psiphon-tunnel-core-${arch}"
    ylw "[*] 下载 Psiphon 二进制: $url"
    download_file "$url" /usr/local/bin/psiphon-tunnel-core
    chmod +x /usr/local/bin/psiphon-tunnel-core
  else
    # ARM 架构：需要 Go 编译
    ylw "[!] 架构=$arch：官方无预编译二进制，使用 Go 编译..."
    local pm
    pm="$(detect_pm)"
    if [[ "$pm" == "apt" ]]; then
      apt-get install -y git golang build-essential
    else
      "$pm" -y install git golang gcc make || true
    fi

    rm -rf /tmp/psiphon-tunnel-core
    git clone --depth 1 https://github.com/Psiphon-Labs/psiphon-tunnel-core.git /tmp/psiphon-tunnel-core
    cd /tmp/psiphon-tunnel-core/ConsoleClient
    go build -o /usr/local/bin/psiphon-tunnel-core .
    chmod +x /usr/local/bin/psiphon-tunnel-core
    cd /
  fi

  # 写配置文件
  cat >/etc/psiphon/psiphon.config <<EOF
{
  "LocalHttpProxyPort": ${PSIPHON_HTTP},
  "LocalSocksProxyPort": ${PSIPHON_SOCKS},
  "EgressRegion": "${PSIPHON_REGION}",
  "PropagationChannelId": "FFFFFFFFFFFFFFFF",
  "SponsorId": "FFFFFFFFFFFFFFFF",
  "RemoteServerListDownloadFilename": "/var/lib/psiphon/remote_server_list",
  "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
  "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
  "UseIndistinguishableTLS": true
}
EOF

  # systemd 服务
  cat >/etc/systemd/system/psiphon.service <<'EOF'
[Unit]
Description=Psiphon Tunnel Core (ConsoleClient)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/psiphon
ExecStart=/usr/local/bin/psiphon-tunnel-core -config /etc/psiphon/psiphon.config
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now psiphon
  grn "[+] Psiphon 已启动（SOCKS: 127.0.0.1:${PSIPHON_SOCKS}, HTTP: 127.0.0.1:${PSIPHON_HTTP}, 国家: ${PSIPHON_REGION}）"
}

# ========= Xray (VLESS + REALITY) =========
install_xray_vless_reality(){
  local arch
  arch="$(detect_arch)"

  ylw "[*] 安装 Xray-core（VLESS+REALITY）..."
  local url
  if [[ "$arch" == "x86_64" ]]; then
    url="$(download_latest_github_release_asset "XTLS/Xray-core" "Xray-linux-64.zip")"
  elif [[ "$arch" == "arm64" ]]; then
    url="$(download_latest_github_release_asset "XTLS/Xray-core" "Xray-linux-arm64-v8a.zip")"
  else
    url="$(download_latest_github_release_asset "XTLS/Xray-core" "Xray-linux-32.zip")"
  fi

  rm -rf /tmp/xray && mkdir -p /tmp/xray
  download_file "$url" /tmp/xray/xray.zip
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
After=network-online.target psiphon.service
Wants=network-online.target psiphon.service

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
  local arch
  arch="$(detect_arch)"

  ylw "[*] 安装 Hysteria2..."
  local url
  if [[ "$arch" == "x86_64" ]]; then
    url="$(download_latest_github_release_asset "apernet/hysteria" "hysteria-linux-amd64$")"
  elif [[ "$arch" == "arm64" ]]; then
    url="$(download_latest_github_release_asset "apernet/hysteria" "hysteria-linux-arm64$")"
  else
    url="$(download_latest_github_release_asset "apernet/hysteria" "hysteria-linux-386$")"
  fi

  download_file "$url" /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria

  local hy_pass obfs_pass
  hy_pass="$(rand_hex 12)"
  obfs_pass="$(rand_hex 12)"

  mkdir -p /etc/hysteria /etc/ssl/sbox

  # 生成自签证书
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
After=network-online.target psiphon.service
Wants=network-online.target psiphon.service

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

# ========= TUIC =========
install_tuic_server(){
  local arch
  arch="$(detect_arch)"

  ylw "[*] 安装 tuic-server..."
  local url
  if [[ "$arch" == "x86_64" ]]; then
    url="$(download_latest_github_release_asset "EAimTY/tuic" "tuic-server.*x86_64.*linux" || true)"
  elif [[ "$arch" == "arm64" ]]; then
    url="$(download_latest_github_release_asset "EAimTY/tuic" "tuic-server.*aarch64.*linux" || true)"
  fi

  if [[ -z "$url" ]]; then
    ylw "[!] 未能获取 tuic-server，尝试备用方式..."
    local api="https://api.github.com/repos/EAimTY/tuic/releases"
    if command -v curl >/dev/null 2>&1; then
      if [[ "$arch" == "x86_64" ]]; then
        url="$(curl -fsSL "$api" | jq -r '.[0].assets[].browser_download_url' | grep -i "tuic-server.*x86_64.*linux" | head -n1 || true)"
      else
        url="$(curl -fsSL "$api" | jq -r '.[0].assets[].browser_download_url' | grep -i "tuic-server.*aarch64.*linux" | head -n1 || true)"
      fi
    fi
  fi

  if [[ -z "$url" ]]; then
    ylw "[!] 跳过 TUIC 安装（未找到可用二进制）"
    TUIC_UUID=""
    TUIC_PASS=""
    return 0
  fi

  download_file "$url" /usr/local/bin/tuic-server
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
After=network-online.target psiphon.service
Wants=network-online.target psiphon.service

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

# ========= psictl (Psiphon 管理工具) =========
install_psictl(){
  ylw "[*] 安装 psictl..."
  cat > /usr/local/bin/psictl <<'PSICTL_EOF'
#!/usr/bin/env bash
set -euo pipefail

CFG="/etc/psiphon/psiphon.config"
SOCKS_PORT="$(jq -r '.LocalSocksProxyPort' "$CFG" 2>/dev/null || echo "1081")"
REGION="$(jq -r '.EgressRegion // ""' "$CFG" 2>/dev/null || echo "")"

# 常用可用国家码
ALL=(AT BE BG CA CH CZ DE DK EE ES FI FR GB HU IE IN IT JP LV NL NO PL RO RS SE SG SK US)

set_region() {
  local cc="$1"
  local tmp
  tmp="$(mktemp)"
  if [[ "${cc^^}" == "AUTO" || -z "$cc" ]]; then
    jq '.EgressRegion=""' "$CFG" >"$tmp"
  else
    jq --arg cc "${cc^^}" '.EgressRegion=$cc' "$CFG" >"$tmp"
  fi
  mv "$tmp" "$CFG"
  systemctl restart psiphon
  sleep 3
}

egress_test() {
  local json
  json="$(curl -fsS --max-time 12 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://ipinfo.io/json 2>/dev/null || true)"
  if [[ -z "$json" ]]; then
    echo "[-] FAIL: SOCKS 不通 (127.0.0.1:${SOCKS_PORT})"
    return 1
  fi
  echo "$json" | jq -r '"IP: \(.ip)\nCountry: \(.country)\nOrg: \(.org)\nCity: \(.city)"'
}

case "${1:-}" in
  status)
    echo "EgressRegion: ${REGION:-AUTO}"
    echo "SOCKS: 127.0.0.1:${SOCKS_PORT}"
    echo ""
    systemctl --no-pager -l status psiphon 2>/dev/null || echo "未运行"
    ;;
  country)
    [[ -n "${2:-}" ]] || { echo "用法: psictl country <CC|AUTO>"; exit 1; }
    set_region "$2"
    echo "[+] 已切换国家为: ${2^^}"
    ;;
  egress-test)
    egress_test
    ;;
  country-test)
    shift || true
    [[ $# -ge 1 ]] || { echo "用法: psictl country-test <CC...>"; exit 1; }
    ok=(); fail=(); mismatch=()
    for cc in "$@"; do
      echo "==> ${cc^^}"
      set_region "$cc" >/dev/null 2>&1
      json="$(curl -fsS --max-time 12 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://ipinfo.io/json 2>/dev/null || true)"
      if [[ -z "$json" ]]; then
        echo "  [-] FAIL (no response)"
        fail+=("${cc^^}")
        continue
      fi
      got="$(echo "$json" | jq -r '.country // empty' 2>/dev/null || true)"
      if [[ -z "$got" ]]; then
        echo "  [~] MISMATCH (no country field)"
        mismatch+=("${cc^^}")
        continue
      fi
      if [[ "${got^^}" == "${cc^^}" ]]; then
        echo "  [+] OK (country=${got^^})"
        ok+=("${cc^^}")
      else
        echo "  [~] MISMATCH (want=${cc^^} got=${got^^})"
        mismatch+=("${cc^^}")
      fi
    done
    echo ""
    echo "---- SUMMARY ----"
    echo "OK: ${ok[*]:-none}"
    echo "FAIL: ${fail[*]:-none}"
    echo "MISMATCH: ${mismatch[*]:-none}"
    ;;
  country-test-all)
    psictl country-test "${ALL[@]}"
    ;;
  restart)
    systemctl restart psiphon xray hysteria2 tuic 2>/dev/null || true
    echo "[+] 已重启所有服务"
    ;;
  logs)
    case "${2:-}" in
      psi|psiphon) journalctl -u psiphon -n 100 --no-pager ;;
      xray) journalctl -u xray -n 100 --no-pager ;;
      hy2|hysteria) journalctl -u hysteria2 -n 100 --no-pager ;;
      tuic) journalctl -u tuic -n 100 --no-pager ;;
      *) journalctl -u psiphon -u xray -u hysteria2 -u tuic -n 100 --no-pager ;;
    esac
    ;;
  *)
    echo "psictl - Psiphon + 多协议入站 管理工具"
    echo ""
    echo "用法:"
    echo "  psictl status               查看 Psiphon 状态"
    echo "  psictl country <CC|AUTO>    切换出口国家"
    echo "  psictl egress-test          测试当前出口 IP"
    echo "  psictl country-test <CC...> 批量测试国家"
    echo "  psictl country-test-all     测试所有常用国家"
    echo "  psictl restart              重启所有服务"
    echo "  psictl logs [psi|xray|hy2|tuic]"
    ;;
esac
PSICTL_EOF
  chmod +x /usr/local/bin/psictl
  grn "[+] psictl 已安装"
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
║   多协议入站 + Psiphon 出站 管理菜单                 ║
╠══════════════════════════════════════════════════════╣
║  1) 查看 Psiphon 状态     (psictl status)            ║
║  2) 查看当前出口 IP       (psictl egress-test)       ║
║  3) 切换出口国家          (psictl country <CC>)      ║
║  4) 批量测试国家可用性    (psictl country-test ...)  ║
║  5) 测试所有常用国家      (psictl country-test-all)  ║
║  6) 重启所有服务          (psictl restart)           ║
║  7) 查看日志              (psictl logs ...)          ║
║  0) 退出                                             ║
╚══════════════════════════════════════════════════════╝
MENU
  read -r -p "请选择 [0-7]: " c || true
  case "$c" in
    1) psictl status; read -r -p "回车继续..." _ ;;
    2) psictl egress-test; read -r -p "回车继续..." _ ;;
    3)
      echo "常用: US JP SG DE FR GB NL AT BE CA CH"
      read -r -p "国家代码(AUTO=自动): " cc
      [[ -n "$cc" ]] && psictl country "$cc"
      read -r -p "回车继续..." _
      ;;
    4)
      read -r -p "输入国家列表(空格分隔，如 US JP SG): " line
      # shellcheck disable=SC2086
      [[ -n "$line" ]] && psictl country-test $line
      read -r -p "回车继续..." _
      ;;
    5) psictl country-test-all; read -r -p "回车继续..." _ ;;
    6) psictl restart; read -r -p "回车继续..." _ ;;
    7)
      echo "psi=psiphon, xray, hy2=hysteria2, tuic"
      read -r -p "选择(默认全部): " t
      psictl logs "${t:-all}"
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

EOF

  if [[ -n "${TUIC_UUID:-}" ]]; then
    cat <<EOF
[TUIC v5]
  地址: ${HOST}
  端口: ${TUIC_PORT} (UDP)
  UUID: ${TUIC_UUID}
  密码: ${TUIC_PASS}
  Congestion: bbr
  ALPN: h3
  证书: self（客户端需 skip-cert-verify / insecure=true）

EOF
  fi

  cat <<EOF
===============================================================

管理命令：
  vpsmenu                  # 交互式菜单
  psictl status            # 查看 Psiphon 状态
  psictl country US        # 切换出口国家
  psictl egress-test       # 测试当前出口
  psictl country-test US JP SG DE
  psictl country-test-all  # 测试所有常用国家

EOF
}

# ========= main =========
main(){
  local arch
  arch="$(detect_arch)"
  install_deps

  prompt HOST "请输入用于客户端连接的域名或IP（HOST）" "$DEFAULT_HOST"
  prompt VLESS_PORT "VLESS+REALITY 端口(TCP)" "$DEFAULT_VLESS_PORT"
  prompt HY2_PORT "Hysteria2 端口(UDP)" "$DEFAULT_HY2_PORT"
  prompt TUIC_PORT "TUIC v5 端口(UDP)" "$DEFAULT_TUIC_PORT"
  prompt REALITY_SNI "REALITY 伪装站点(需TLS1.3/H2，示例 www.apple.com)" "$DEFAULT_REALITY_SNI"
  prompt CERT_MODE "HY2/TUIC TLS证书模式：le(自动申请) 或 self(自签)" "$DEFAULT_CERT_MODE"
  prompt PSIPHON_REGION "Psiphon 出站国家(两位代码，如 US/JP/SG/DE，AUTO=自动)" "$DEFAULT_PSIPHON_REGION"
  prompt PSIPHON_SOCKS "Psiphon 本地 SOCKS5 端口" "$DEFAULT_PSIPHON_SOCKS"
  prompt PSIPHON_HTTP "Psiphon 本地 HTTP 代理端口" "$DEFAULT_PSIPHON_HTTP"

  ylw "[*] 请确保放行端口：${VLESS_PORT}/tcp, ${HY2_PORT}/udp, ${TUIC_PORT}/udp"

  install_psiphon
  install_xray_vless_reality
  install_hysteria2
  install_tuic_server

  install_psictl
  install_menu

  print_client_info
  grn "[+] 安装完成！"
}

main "$@"
