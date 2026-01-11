#!/usr/bin/env bash
set -euo pipefail

# ========= 可调默认值 =========
# HOST 会在安装时自动探测公网 IP
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
  # 先下载到 /tmp，避免直接写 /usr/local/bin 导致 curl 23 错误
  local tmp
  tmp="$(mktemp -p /tmp download.XXXXXX)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$url" -o "$tmp"
  else
    wget -qO "$tmp" "$url"
  fi
  # 使用 install 命令移动到目标位置
  install -m 0755 "$tmp" "$dest"
  rm -f "$tmp"
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

  # 生成 REALITY keypair（兼容新旧版本 xray x25519 输出格式）
  local keypair priv pub sid uuid
  keypair="$(/usr/local/bin/xray x25519 2>&1)"
  
  # 新版本格式: PrivateKey: xxx / Password: yyy
  priv="$(echo "$keypair" | awk -F': *' '/^PrivateKey:/ {print $2; exit}')"
  pub="$(echo "$keypair" | awk -F': *' '/^Password:/ {print $2; exit}')"
  
  # 旧版本格式: Private key: xxx / Public key: yyy
  if [[ -z "$priv" ]]; then
    priv="$(echo "$keypair" | awk -F': *' '/^Private key:/ {print $2; exit}')"
  fi
  if [[ -z "$pub" ]]; then
    pub="$(echo "$keypair" | awk -F': *' '/^Public key:/ {print $2; exit}')"
  fi

  if [[ -z "$priv" || -z "$pub" || ${#priv} -lt 20 || ${#pub} -lt 20 ]]; then
    red "[!] REALITY 密钥解析失败，xray x25519 输出："
    echo "$keypair"
    red "[!] 请手动运行 /usr/local/bin/xray x25519 检查"
    exit 1
  fi

  sid="$(rand_hex 8)"
  uuid="$(gen_uuid)"

  grn "[+] REALITY 密钥生成成功"
  grn "    PrivateKey: ${priv:0:10}..."
  grn "    PublicKey:  ${pub:0:10}..."

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

# =========================
# 国家代码 -> 中文名 + 大洲（离线映射）
# =========================
declare -A CC_ZH CC_CONT

# --- 欧洲 ---
CC_ZH[AT]="奥地利";   CC_CONT[AT]="欧洲"
CC_ZH[BE]="比利时";   CC_CONT[BE]="欧洲"
CC_ZH[BG]="保加利亚"; CC_CONT[BG]="欧洲"
CC_ZH[CH]="瑞士";     CC_CONT[CH]="欧洲"
CC_ZH[CZ]="捷克";     CC_CONT[CZ]="欧洲"
CC_ZH[DE]="德国";     CC_CONT[DE]="欧洲"
CC_ZH[DK]="丹麦";     CC_CONT[DK]="欧洲"
CC_ZH[EE]="爱沙尼亚"; CC_CONT[EE]="欧洲"
CC_ZH[ES]="西班牙";   CC_CONT[ES]="欧洲"
CC_ZH[FI]="芬兰";     CC_CONT[FI]="欧洲"
CC_ZH[FR]="法国";     CC_CONT[FR]="欧洲"
CC_ZH[GB]="英国";     CC_CONT[GB]="欧洲"
CC_ZH[HU]="匈牙利";   CC_CONT[HU]="欧洲"
CC_ZH[IE]="爱尔兰";   CC_CONT[IE]="欧洲"
CC_ZH[IT]="意大利";   CC_CONT[IT]="欧洲"
CC_ZH[LV]="拉脱维亚"; CC_CONT[LV]="欧洲"
CC_ZH[NL]="荷兰";     CC_CONT[NL]="欧洲"
CC_ZH[NO]="挪威";     CC_CONT[NO]="欧洲"
CC_ZH[PL]="波兰";     CC_CONT[PL]="欧洲"
CC_ZH[RO]="罗马尼亚"; CC_CONT[RO]="欧洲"
CC_ZH[RS]="塞尔维亚"; CC_CONT[RS]="欧洲"
CC_ZH[SE]="瑞典";     CC_CONT[SE]="欧洲"
CC_ZH[SK]="斯洛伐克"; CC_CONT[SK]="欧洲"

# --- 亚洲 ---
CC_ZH[IN]="印度";     CC_CONT[IN]="亚洲"
CC_ZH[JP]="日本";     CC_CONT[JP]="亚洲"
CC_ZH[SG]="新加坡";   CC_CONT[SG]="亚洲"
CC_ZH[HK]="香港";     CC_CONT[HK]="亚洲"
CC_ZH[TW]="台湾";     CC_CONT[TW]="亚洲"
CC_ZH[KR]="韩国";     CC_CONT[KR]="亚洲"

# --- 北美洲 ---
CC_ZH[CA]="加拿大";   CC_CONT[CA]="北美洲"
CC_ZH[US]="美国";     CC_CONT[US]="北美洲"

# 国家代码转可读标签：US -> US 美国（北美洲）
cc_label() {
  local cc="${1^^}"
  local zh="${CC_ZH[$cc]:-}"
  local cont="${CC_CONT[$cc]:-}"
  if [[ -n "$zh" && -n "$cont" ]]; then
    echo "$cc $zh（$cont）"
  elif [[ -n "$zh" ]]; then
    echo "$cc $zh"
  else
    echo "$cc"
  fi
}

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
    if [[ -n "$REGION" ]]; then
      echo "EgressRegion: $(cc_label "$REGION")"
    else
      echo "EgressRegion: AUTO（自动选择）"
    fi
    echo "SOCKS: 127.0.0.1:${SOCKS_PORT}"
    echo ""
    systemctl --no-pager -l status psiphon 2>/dev/null || echo "未运行"
    ;;
  country)
    [[ -n "${2:-}" ]] || { echo "用法: psictl country <CC|AUTO>"; exit 1; }
    set_region "$2"
    if [[ "${2^^}" == "AUTO" ]]; then
      echo "[+] 已切换为: AUTO（自动选择最佳出口）"
    else
      echo "[+] 已切换为: $(cc_label "${2^^}")"
    fi
    ;;
  egress-test)
    egress_test
    ;;
  country-test)
    shift || true
    [[ $# -ge 1 ]] || { echo "用法: psictl country-test <CC...>"; exit 1; }
    ok=(); fail=(); mismatch=()
    for cc in "$@"; do
      echo "==> $(cc_label "${cc^^}")"
      set_region "$cc" >/dev/null 2>&1
      json="$(curl -fsS --max-time 12 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://ipinfo.io/json 2>/dev/null || true)"
      if [[ -z "$json" ]]; then
        echo "  [-] FAIL (无响应)"
        fail+=("${cc^^}")
        continue
      fi
      got="$(echo "$json" | jq -r '.country // empty' 2>/dev/null || true)"
      if [[ -z "$got" ]]; then
        echo "  [~] MISMATCH (无country字段)"
        mismatch+=("${cc^^}")
        continue
      fi
      if [[ "${got^^}" == "${cc^^}" ]]; then
        echo "  [+] OK (country=${got^^})"
        ok+=("${cc^^}")
      else
        echo "  [~] MISMATCH (期望=${cc^^} 实际=${got^^})"
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
  links)
    local f="/etc/psiphon-egress/client.json"
    if [[ ! -f "$f" ]]; then
      echo "[-] 未找到 $f，无法生成分享链接"
      echo "    请重新运行安装脚本"
      exit 1
    fi

    local host cert_mode
    host="$(jq -r '.host' "$f")"
    cert_mode="$(jq -r '.cert_mode' "$f")"

    # VLESS+REALITY
    local v_port v_uuid v_sni v_pbk v_sid
    v_port="$(jq -r '.vless.port' "$f")"
    v_uuid="$(jq -r '.vless.uuid' "$f")"
    v_sni="$(jq -r '.vless.sni' "$f")"
    v_pbk="$(jq -r '.vless.pbk' "$f")"
    v_sid="$(jq -r '.vless.sid' "$f")"
    local vless_link="vless://${v_uuid}@${host}:${v_port}?encryption=none&security=reality&sni=${v_sni}&fp=chrome&pbk=${v_pbk}&sid=${v_sid}&type=tcp&flow=xtls-rprx-vision#VLESS-Reality"

    # Hysteria2
    local h_port h_auth h_obfs insecure
    h_port="$(jq -r '.hy2.port' "$f")"
    h_auth="$(jq -r '.hy2.auth' "$f")"
    h_obfs="$(jq -r '.hy2.obfs_password' "$f")"
    [[ "$cert_mode" == "self" ]] && insecure=1 || insecure=0
    local hy2_link="hysteria2://${h_auth}@${host}:${h_port}/?obfs=salamander&obfs-password=${h_obfs}&sni=${host}&insecure=${insecure}#HY2"

    # TUIC
    local t_port t_uuid t_pass
    t_port="$(jq -r '.tuic.port // empty' "$f")"
    t_uuid="$(jq -r '.tuic.uuid // empty' "$f")"
    t_pass="$(jq -r '.tuic.password // empty' "$f")"
    local tuic_link=""
    if [[ -n "$t_uuid" && "$t_uuid" != "null" ]]; then
      tuic_link="tuic://${t_uuid}:${t_pass}@${host}:${t_port}?alpn=h3&udp_relay_mode=native&congestion_control=bbr&sni=${host}&allow_insecure=${insecure}#TUIC-v5"
    fi

    echo ""
    echo "==================== 分享链接 ===================="
    echo ""
    echo "[VLESS+REALITY]"
    echo "$vless_link"
    echo ""
    echo "[Hysteria2]"
    echo "$hy2_link"
    if [[ -n "$tuic_link" ]]; then
      echo ""
      echo "[TUIC v5]"
      echo "$tuic_link"
    fi
    echo ""
    echo "=================================================="
    ;;
  ok-list)
    # 运行 country-test-all 并只输出 OK 列表（给菜单用）
    out="$(psictl country-test-all 2>&1)"
    echo "$out" | grep -E '^OK:' | tail -n1 | sed 's/^OK:[[:space:]]*//'
    ;;
  smart-country)
    echo ""
    echo "[智能切换] 正在测试所有常用国家..."
    echo ""
    tmp="$(mktemp)"
    psictl country-test-all | tee "$tmp"
    ok_line="$(grep -E '^OK:' "$tmp" | tail -n1 | sed 's/^OK:[[:space:]]*//')"
    rm -f "$tmp"

    if [[ -z "${ok_line}" || "${ok_line}" == "none" ]]; then
      echo ""
      echo "[!] 没有检测到可用国家"
      exit 1
    fi

    read -r -a ok_arr <<<"$ok_line"
    echo ""
    echo "========== 可用国家（按编号选择）=========="
    i=1
    for cc in "${ok_arr[@]}"; do
      printf "  %2d) %s\n" "$i" "$(cc_label "$cc")"
      i=$((i+1))
    done
    echo "   0) 取消"
    echo "   A) AUTO（自动选择最佳出口）"
    echo "=========================================="
    read -r -p "请选择编号或国家码: " sel

    if [[ "${sel^^}" == "A" || "${sel^^}" == "AUTO" ]]; then
      psictl country AUTO
      psictl egress-test || true
      exit 0
    fi

    if [[ "$sel" =~ ^[0-9]+$ ]]; then
      if [[ "$sel" -eq 0 ]]; then
        exit 0
      fi
      idx=$((sel-1))
      if [[ $idx -ge 0 && $idx -lt ${#ok_arr[@]} ]]; then
        cc="${ok_arr[$idx]}"
        psictl country "$cc"
        psictl egress-test || true
      else
        echo "[!] 编号超出范围"
      fi
    else
      psictl country "${sel^^}"
      psictl egress-test || true
    fi
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
    echo "  psictl smart-country        智能切换(先测试后选择)"
    echo "  psictl links                查看分享链接"
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
║  3) 智能切换出口国家      (先测试后选择)               ║
║  4) 手动切换出口国家      (psictl country <CC>)      ║
║  5) 批量测试国家可用性    (psictl country-test ...)  ║
║  6) 查看分享链接          (psictl links)             ║
║  7) 重启所有服务          (psictl restart)           ║
║  8) 查看日志              (psictl logs ...)          ║
║  0) 退出                                             ║
╚══════════════════════════════════════════════════════╝
MENU
  read -r -p "请选择 [0-8]: " c || true
  case "$c" in
    1) psictl status; read -r -p "回车继续..." _ ;;
    2) psictl egress-test; read -r -p "回车继续..." _ ;;
    3) psictl smart-country; read -r -p "回车继续..." _ ;;
    4)
      echo "常用: US JP SG DE FR GB NL AT BE CA CH"
      read -r -p "国家代码(AUTO=自动): " cc
      [[ -n "$cc" ]] && psictl country "$cc"
      psictl egress-test || true
      read -r -p "回车继续..." _
      ;;
    5)
      read -r -p "输入国家列表(空格分隔，如 US JP SG)或回车测全部: " line
      if [[ -n "$line" ]]; then
        # shellcheck disable=SC2086
        psictl country-test $line
      else
        psictl country-test-all
      fi
      read -r -p "回车继续..." _
      ;;
    6) psictl links; read -r -p "回车继续..." _ ;;
    7) psictl restart; read -r -p "回车继续..." _ ;;
    8)
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

# ========= 保存客户端参数到 JSON =========
save_client_json(){
  mkdir -p /etc/psiphon-egress
  
  local insecure=0
  [[ "$CERT_MODE" == "self" ]] && insecure=1

  cat >/etc/psiphon-egress/client.json <<EOF
{
  "host": "${HOST}",
  "cert_mode": "${CERT_MODE}",
  "vless": {
    "port": ${VLESS_PORT},
    "uuid": "${XRAY_UUID}",
    "flow": "xtls-rprx-vision",
    "sni": "${REALITY_SNI}",
    "fp": "chrome",
    "pbk": "${XRAY_PUB}",
    "sid": "${XRAY_SID}"
  },
  "hy2": {
    "port": ${HY2_PORT},
    "auth": "${HY2_PASS}",
    "obfs": "salamander",
    "obfs_password": "${HY2_OBFS}",
    "insecure": ${insecure}
  },
  "tuic": {
    "port": ${TUIC_PORT},
    "uuid": "${TUIC_UUID:-}",
    "password": "${TUIC_PASS:-}",
    "congestion_control": "bbr",
    "alpn": "h3",
    "insecure": ${insecure}
  }
}
EOF
  chmod 600 /etc/psiphon-egress/client.json
}

# ========= 输出客户端信息 =========
print_client_info(){
  # 先保存参数到 JSON
  save_client_json

  local insecure=0
  [[ "$CERT_MODE" == "self" ]] && insecure=1

  # 生成分享链接
  local vless_link="vless://${XRAY_UUID}@${HOST}:${VLESS_PORT}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${XRAY_PUB}&sid=${XRAY_SID}&type=tcp&flow=xtls-rprx-vision#VLESS-Reality"
  local hy2_link="hysteria2://${HY2_PASS}@${HOST}:${HY2_PORT}/?obfs=salamander&obfs-password=${HY2_OBFS}&sni=${HOST}&insecure=${insecure}#HY2"
  local tuic_link=""
  if [[ -n "${TUIC_UUID:-}" ]]; then
    tuic_link="tuic://${TUIC_UUID}:${TUIC_PASS}@${HOST}:${TUIC_PORT}?alpn=h3&udp_relay_mode=native&congestion_control=bbr&sni=${HOST}&allow_insecure=${insecure}#TUIC-v5"
  fi

  cat <<EOF

==================== 客户端参数（请妥善保存）====================

[VLESS + REALITY] (Xray)
  地址: ${HOST}
  端口: ${VLESS_PORT} (TCP)
  UUID: ${XRAY_UUID}
  SNI: ${REALITY_SNI}
  pbk: ${XRAY_PUB}
  sid: ${XRAY_SID}

[Hysteria2]
  地址: ${HOST}
  端口: ${HY2_PORT} (UDP)
  密码: ${HY2_PASS}
  OBFS密码: ${HY2_OBFS}

EOF

  if [[ -n "${TUIC_UUID:-}" ]]; then
    cat <<EOF
[TUIC v5]
  地址: ${HOST}
  端口: ${TUIC_PORT} (UDP)
  UUID: ${TUIC_UUID}
  密码: ${TUIC_PASS}

EOF
  fi

  cat <<EOF
==================== 分享链接（可直接导入客户端）====================

[VLESS+REALITY]
${vless_link}

[Hysteria2]
${hy2_link}

EOF

  if [[ -n "$tuic_link" ]]; then
    cat <<EOF
[TUIC v5]
${tuic_link}

EOF
  fi

  cat <<EOF
===============================================================

管理命令：
  vpsmenu                  # 交互式菜单
  psictl links             # 查看分享链接
  psictl status            # 查看 Psiphon 状态
  psictl country US        # 切换出口国家
  psictl egress-test       # 测试当前出口
  psictl country-test-all  # 测试所有常用国家

EOF
}

# ========= main =========
main(){
  local arch
  arch="$(detect_arch)"
  install_deps

  # 自动探测公网 IP（IPv4 优先）
  ylw "[*] 正在探测本机公网 IP (IPv4 优先)..."
  local detected_ip=""
  # 先尝试 IPv4
  detected_ip="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  [[ -z "$detected_ip" ]] && detected_ip="$(curl -4 -fsS --max-time 6 https://ifconfig.me/ip 2>/dev/null || true)"
  [[ -z "$detected_ip" ]] && detected_ip="$(curl -4 -fsS --max-time 6 https://ipinfo.io/ip 2>/dev/null || true)"
  # 如果没有 IPv4，再尝试 IPv6
  [[ -z "$detected_ip" ]] && detected_ip="$(curl -6 -fsS --max-time 6 https://api6.ipify.org 2>/dev/null || true)"
  
  if [[ -n "$detected_ip" ]]; then
    grn "[+] 探测到公网 IP: $detected_ip"
    DEFAULT_HOST="$detected_ip"
  else
    ylw "[!] 无法自动探测公网 IP，请手动输入"
    DEFAULT_HOST="example.com"
  fi

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
