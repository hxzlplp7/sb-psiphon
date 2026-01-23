#!/usr/bin/env bash
set -euo pipefail

# ========= 可调默认值 =========
# HOST 会在安装时自动探测公网 IP
DEFAULT_VLESS_PORT="443"
DEFAULT_HY2_PORT="8443"
DEFAULT_TUIC_PORT="2053"
DEFAULT_REALITY_SNI="www.apple.com"
DEFAULT_QUIC_SNI="www.bing.com"    
DEFAULT_CERT_MODE="self"   # self | le
DEFAULT_PSIPHON_REGION="US"
DEFAULT_PSIPHON_SOCKS="1081"
DEFAULT_PSIPHON_HTTP="8081"
DEFAULT_EGRESS_MODE="direct"   # direct | psiphon | freeproxy

# ========= 全局临时目录管理（防止 set -u 报 unbound variable）=========
_tmpd=""
_cleanup_tmpd() {
  if [[ -n "${_tmpd:-}" && -d "${_tmpd:-}" ]]; then
    rm -rf -- "$_tmpd"
  fi
}
trap _cleanup_tmpd EXIT

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

# 检测 OS 类型（用于 Psiphon 二进制选择）
detect_os(){
  local os
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux)   echo "linux" ;;
    freebsd) echo "freebsd" ;;
    *)       echo "unsupported" ;;
  esac
}

# 检测架构（返回统一格式，与 release 资产命名一致）
detect_arch(){
  local arch
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$arch" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    armv7l|armv7)   echo "armv7" ;;
    armv6l)         echo "armv7" ;;  # armv6 fallback to armv7
    i386|i686)      echo "386" ;;
    *)              echo "unknown" ;;
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

  # 配置 IPv4 优先出站（避免 IPv6 导致的连接问题）
  if ! grep -q 'precedence ::ffff:0:0/96' /etc/gai.conf 2>/dev/null; then
    echo 'precedence ::ffff:0:0/96  100' >> /etc/gai.conf
    ylw "[*] 已配置 IPv4 优先出站"
  fi
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

# ========= Psiphon ConsoleClient (优先 hxzlplp7 releases) =========
# 配置变量
PSI_REPO_OWNER="hxzlplp7"
PSI_REPO_NAME="psiphon-tunnel-core"
PSI_TAG_DEFAULT="v1.0.0"
PSI_OFFICIAL_FALLBACK_LINUX_AMD64="https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/linux/psiphon-tunnel-core-x86_64"

install_psiphon(){
  local os arch
  os="$(detect_os)"
  arch="$(detect_arch)"

  ylw "[*] 安装 Psiphon ConsoleClient..."
  ylw "[*] 检测到平台: ${os}/${arch}"
  mkdir -p /etc/psiphon /var/lib/psiphon /usr/local/bin

  if [[ "$os" == "unsupported" ]]; then
    red "[!] 不支持的操作系统: $(uname -s)"
    red "    目前仅支持 Linux 和 FreeBSD"
    exit 1
  fi

  if [[ "$arch" == "unknown" ]]; then
    red "[!] 不支持的架构: $(uname -m)"
    exit 1
  fi

  # 创建临时目录（使用全局 _tmpd，由 EXIT trap 清理）
  _tmpd="$(mktemp -d)"

  local tag="${PSI_TAG_DEFAULT}"
  local base="https://github.com/${PSI_REPO_OWNER}/${PSI_REPO_NAME}/releases/download/${tag}"
  local asset="psiphon-tunnel-core-${os}-${arch}.tar.gz"
  local url="${base}/${asset}"
  local sha_url="${url}.sha256"

  ylw "[*] 尝试从 hxzlplp7 releases 下载: ${url}"

  local download_success=false

  # 检查 release 资产是否存在
  if curl -fsI "$url" >/dev/null 2>&1; then
    # 下载 tar.gz
    ylw "[*] 正在下载..."
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$url" -o "${_tmpd}/${asset}"
    else
      wget -qO "${_tmpd}/${asset}" "$url"
    fi

    # 尝试下载并校验 SHA256
    if curl -fsI "$sha_url" >/dev/null 2>&1; then
      ylw "[*] 下载 SHA256 校验文件..."
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$sha_url" -o "${_tmpd}/${asset}.sha256"
      else
        wget -qO "${_tmpd}/${asset}.sha256" "$sha_url"
      fi

      local expected actual
      expected="$(grep -Eo '[0-9a-fA-F]{64}' "${_tmpd}/${asset}.sha256" | head -n1 | tr '[:upper:]' '[:lower:]')"

      # 计算实际 SHA256（兼容 Linux 和 FreeBSD）
      if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${_tmpd}/${asset}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
      elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "${_tmpd}/${asset}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
      else
        ylw "[!] 未找到 sha256sum/shasum，跳过校验"
        expected=""
      fi

      if [[ -n "$expected" && "$expected" != "$actual" ]]; then
        red "[!] SHA256 校验失败!"
        red "    期望: ${expected}"
        red "    实际: ${actual}"
        exit 1
      fi

      if [[ -n "$expected" ]]; then
        grn "[+] SHA256 校验通过"
      fi
    else
      ylw "[!] 未找到 SHA256 文件，跳过校验（建议 releases 一定带 .sha256）"
    fi

    # 解压
    ylw "[*] 解压中..."
    tar -xzf "${_tmpd}/${asset}" -C "$_tmpd"

    # 查找解压后的二进制文件
    local extracted=""
    if [[ -f "${_tmpd}/psiphon-tunnel-core" ]]; then
      extracted="${_tmpd}/psiphon-tunnel-core"
    else
      # 兼容 tar 包里二进制名不固定的情况
      extracted="$(find "$_tmpd" -maxdepth 2 -type f -name 'psiphon-tunnel-core*' ! -name '*.tar.gz' ! -name '*.sha256' | head -n1)"
    fi

    if [[ -z "$extracted" || ! -f "$extracted" ]]; then
      red "[!] 解压后未找到 psiphon-tunnel-core 可执行文件"
      exit 1
    fi

    install -m 0755 "$extracted" /usr/local/bin/psiphon-tunnel-core
    download_success=true
    grn "[+] Psiphon 已从 hxzlplp7 releases 安装"

  else
    ylw "[!] 你的 releases 暂无 ${os}/${arch} 资产"
  fi

  # Fallback 到官方二进制（仅 linux/amd64）
  if [[ "$download_success" != "true" ]]; then
    if [[ "$os" == "linux" && "$arch" == "amd64" ]]; then
      ylw "[*] Fallback 到官方 psiphon-tunnel-core-binaries..."
      ylw "[*] 下载: ${PSI_OFFICIAL_FALLBACK_LINUX_AMD64}"
      download_file "$PSI_OFFICIAL_FALLBACK_LINUX_AMD64" /usr/local/bin/psiphon-tunnel-core
      chmod +x /usr/local/bin/psiphon-tunnel-core
      grn "[+] Psiphon（官方二进制）已安装"
    else
      red "[!] 你的 releases 不包含该平台资产（${os}/${arch}），且无 fallback"
      red "    请发布: psiphon-tunnel-core-${os}-${arch}.tar.gz"
      exit 1
    fi
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
  if [[ "$arch" == "amd64" ]]; then
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

  # 根据出站模式生成不同的 outbounds 和 routing
  local xray_outbounds xray_routing xray_sniffing
  
  case "$EGRESS_MODE" in
    direct)
      # 直连模式：所有流量直连
      xray_outbounds='
    { "protocol": "freedom", "tag": "direct", "settings": {} }
  '
      xray_routing='"domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "direct", "network": "tcp,udp" }
    ]'
      xray_sniffing='"sniffing": { "enabled": true, "destOverride": ["http","tls"] }'
      ;;
    psiphon)
      # 全局 Psiphon: TCP+UDP 都走 Psiphon socks5
      xray_outbounds='
    {
      "protocol": "socks",
      "tag": "psiphon",
      "settings": {
        "servers": [
          { "address": "127.0.0.1", "port": '"${PSIPHON_SOCKS}"' }
        ]
      }
    }
  '
      xray_routing='"domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "psiphon", "network": "tcp,udp" }
    ]'
      xray_sniffing='"sniffing": { "enabled": true, "destOverride": ["http","tls"] }'
      ;;
  esac

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
      ${xray_sniffing}
    }
  ],
  "outbounds": [${xray_outbounds}],
  "routing": {
    ${xray_routing}
  }
}
EOF

  # systemd unit: psiphon 模式依赖 psiphon.service
  local unit_after unit_wants
  if [[ "$EGRESS_MODE" != "direct" ]]; then
    unit_after="After=network-online.target psiphon.service"
    unit_wants="Wants=network-online.target psiphon.service"
  else
    unit_after="After=network-online.target"
    unit_wants="Wants=network-online.target"
  fi

  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray-core (VLESS+REALITY) Server
${unit_after}
${unit_wants}

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
  if [[ "$arch" == "amd64" ]]; then
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
    # Let's Encrypt 模式 - 基础配置
    cat > /etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
acme:
  domains:
    - ${HOST}
  email: admin@${HOST}
tls:
  sniGuard: strict
auth:
  type: password
  password: ${hy_pass}
obfs:
  type: salamander
  salamander:
    password: ${obfs_pass}
EOF
  else
    # 自签证书模式 - 基础配置
    cat > /etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
tls:
  cert: /etc/ssl/sbox/self.crt
  key: /etc/ssl/sbox/self.key
  sniGuard: disable
auth:
  type: password
  password: ${hy_pass}
obfs:
  type: salamander
  salamander:
    password: ${obfs_pass}
EOF
  fi

  # 根据出站模式追加 outbounds 和 ACL 配置
  case "$EGRESS_MODE" in
    direct)
      # 直连模式：不添加 outbounds（Hysteria2 默认直连）
      ;;
    psiphon)
      # 全局 Psiphon: TCP+UDP 都走 Psiphon socks5
      cat >> /etc/hysteria/config.yaml <<EOF

outbounds:
  - name: psiphon
    type: socks5
    socks5:
      addr: 127.0.0.1:${PSIPHON_SOCKS}

acl:
  inline:
    - psiphon(all)
EOF
      ;;
  esac

  # systemd unit: psiphon 模式依赖 psiphon.service
  local unit_after unit_wants
  if [[ "$EGRESS_MODE" != "direct" ]]; then
    unit_after="After=network-online.target psiphon.service"
    unit_wants="Wants=network-online.target psiphon.service"
  else
    unit_after="After=network-online.target"
    unit_wants="Wants=network-online.target"
  fi

  cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
${unit_after}
${unit_wants}

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
  local url=""
  if [[ "$arch" == "amd64" ]]; then
    url="$(download_latest_github_release_asset "tuic-protocol/tuic" "tuic-server-.*x86_64-unknown-linux-gnu$" || true)"
  elif [[ "$arch" == "arm64" ]]; then
    url="$(download_latest_github_release_asset "tuic-protocol/tuic" "tuic-server-.*aarch64-unknown-linux-gnu$" || true)"
  fi

  if [[ -z "$url" ]]; then
    ylw "[!] 未能获取 tuic-server，尝试备用方式..."
    local api="https://api.github.com/repos/tuic-protocol/tuic/releases"
    if command -v curl >/dev/null 2>&1; then
      if [[ "$arch" == "amd64" ]]; then
        url="$(curl -fsSL "$api" | jq -r '.[0].assets[].browser_download_url' | grep -E 'tuic-server-.*x86_64-unknown-linux-gnu$' | head -n1 || true)"
      elif [[ "$arch" == "arm64" ]]; then
        url="$(curl -fsSL "$api" | jq -r '.[0].assets[].browser_download_url' | grep -E 'tuic-server-.*aarch64-unknown-linux-gnu$' | head -n1 || true)"
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

  local tuic_uuid="" tuic_pass=""

  # 如果已有配置，优先复用，避免节点信息每次安装都变
  if [[ -f /etc/tuic/config.json ]]; then
    tuic_uuid="$(jq -r '.users | to_entries[0].key // empty' /etc/tuic/config.json 2>/dev/null || true)"
    tuic_pass="$(jq -r '.users | to_entries[0].value // empty' /etc/tuic/config.json 2>/dev/null || true)"
  fi

  # 没取到再生成新的（首次安装）
  if [[ -z "${tuic_uuid:-}" || -z "${tuic_pass:-}" ]]; then
    tuic_uuid="$(gen_uuid)"
    tuic_pass="$(rand_hex 10)"
  fi

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
  "udp_relay_ipv6": true,
  "zero_rtt_handshake": false,
  "auth_timeout": "10s",
  "max_idle_time": "60s",
  "max_external_packet_size": 1200,
  "gc_interval": "3s",
  "gc_lifetime": "15s",
  "log_level": "warn"
}
EOF

  # TUIC 固定直连（不支持服务端分流），不依赖 psiphon.service
  cat > /etc/systemd/system/tuic.service <<'EOF'
[Unit]
Description=tuic-server
After=network-online.target
Wants=network-online.target

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

# 分享链接生成函数
show_links() {
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
  local h_port h_auth h_obfs h_sni insecure
  h_port="$(jq -r '.hy2.port' "$f")"
  h_auth="$(jq -r '.hy2.auth' "$f")"
  h_obfs="$(jq -r '.hy2.obfs_password' "$f")"
  h_sni="$(jq -r '.hy2.sni // "www.bing.com"' "$f")"
  [[ "$cert_mode" == "self" ]] && insecure=1 || insecure=0
  local hy2_link="hysteria2://${h_auth}@${host}:${h_port}/?obfs=salamander&obfs-password=${h_obfs}&sni=${h_sni}&insecure=${insecure}&alpn=h3#HY2"

  # TUIC
  local t_port t_uuid t_pass t_sni
  t_port="$(jq -r '.tuic.port // empty' "$f")"
  t_uuid="$(jq -r '.tuic.uuid // empty' "$f")"
  t_pass="$(jq -r '.tuic.password // empty' "$f")"
  t_sni="$(jq -r '.tuic.sni // "www.bing.com"' "$f")"
  local tuic_link=""
  if [[ -n "$t_uuid" && "$t_uuid" != "null" ]]; then
    tuic_link="tuic://${t_uuid}:${t_pass}@${host}:${t_port}?alpn=h3&udp_relay_mode=native&congestion_control=bbr&sni=${t_sni}&allow_insecure=${insecure}#TUIC-v5"
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
    show_links
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

# ========= proxyctl (Free Proxy List 管理工具) =========
install_proxyctl(){
  ylw "[*] 安装 proxyctl (免费代理管理工具)..."
  
  mkdir -p /etc/freeproxy /var/lib/freeproxy
  
  # 初始化配置文件
  if [[ ! -f /etc/freeproxy/config.json ]]; then
    cat > /etc/freeproxy/config.json <<'FPCFG'
{
  "enabled": false,
  "country": "US",
  "protocol": "socks5",
  "health_interval_min": 10,
  "current_proxy": null
}
FPCFG
  fi
  
  cat > /usr/local/bin/proxyctl <<'PROXYCTL_EOF'
#!/usr/bin/env bash
set -euo pipefail

CFG="/etc/freeproxy/config.json"
CACHE="/var/lib/freeproxy/proxies.json"
CDN_BASE="https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies"

# 颜色输出
red(){ echo -e "\033[31m$*\033[0m" >&2; }
grn(){ echo -e "\033[32m$*\033[0m" >&2; }
ylw(){ echo -e "\033[33m$*\033[0m" >&2; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# 国家代码中文映射
declare -A CC_ZH
CC_ZH[US]="美国"; CC_ZH[JP]="日本"; CC_ZH[SG]="新加坡"; CC_ZH[DE]="德国"
CC_ZH[FR]="法国"; CC_ZH[GB]="英国"; CC_ZH[NL]="荷兰"; CC_ZH[CA]="加拿大"
CC_ZH[KR]="韩国"; CC_ZH[HK]="香港"; CC_ZH[TW]="台湾"; CC_ZH[AU]="澳大利亚"
CC_ZH[RU]="俄罗斯"; CC_ZH[BR]="巴西"; CC_ZH[IN]="印度"; CC_ZH[IT]="意大利"

cc_label() {
  local cc="${1^^}"
  local zh="${CC_ZH[$cc]:-}"
  if [[ -n "$zh" ]]; then echo "$cc ($zh)"; else echo "$cc"; fi
}

# 读取配置
read_cfg() {
  local key="$1" default="${2:-}"
  jq -r ".${key} // empty" "$CFG" 2>/dev/null || echo "$default"
}

# 写入配置
write_cfg() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  if [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" == "null" ]] || [[ "$value" == "true" ]] || [[ "$value" == "false" ]]; then
    jq --argjson v "$value" ".$key = \$v" "$CFG" > "$tmp"
  else
    jq --arg v "$value" ".$key = \$v" "$CFG" > "$tmp"
  fi
  mv "$tmp" "$CFG"
}

# 获取代理列表
fetch_proxies() {
  local country="${1:-US}" protocol="${2:-all}"
  country="${country^^}"
  
  ylw "[*] 正在获取 $country 的代理列表 (协议: $protocol)..."
  
  local url proxies
  if [[ "$protocol" == "all" ]]; then
    url="${CDN_BASE}/countries/${country}/data.json"
  else
    url="${CDN_BASE}/protocols/${protocol}/data.json"
  fi
  
  proxies="$(curl -fsSL --max-time 30 "$url" 2>/dev/null || true)"
  
  if [[ -z "$proxies" ]]; then
    red "[-] 无法获取代理列表"
    return 1
  fi
  
  # 按国家过滤（如果是协议模式）
  if [[ "$protocol" != "all" ]]; then
    proxies="$(echo "$proxies" | jq -c "[.[] | select(.geolocation.country == \"$country\")]")"
  fi
  
  local count
  count="$(echo "$proxies" | jq 'length')"
  
  if [[ "$count" -eq 0 ]]; then
    red "[-] 没有找到 $country 的 $protocol 代理"
    return 1
  fi
  
  grn "[+] 获取到 $count 个代理"
  echo "$proxies" > "$CACHE"
  
  write_cfg "country" "$country"
  [[ "$protocol" != "all" ]] && write_cfg "protocol" "$protocol"
  
  echo "$count"
}

# 测试单个代理连通性和延迟
test_proxy() {
  local ip="$1" port="$2" protocol="$3" timeout="${4:-5}"
  local start end latency
  
  start="$(date +%s%3N)"
  
  case "$protocol" in
    socks5|socks4)
      if curl -fsS --max-time "$timeout" --socks5-hostname "${ip}:${port}" https://ipinfo.io/ip >/dev/null 2>&1; then
        end="$(date +%s%3N)"
        latency=$((end - start))
        echo "$latency"
        return 0
      fi
      ;;
    http|https)
      if curl -fsS --max-time "$timeout" --proxy "http://${ip}:${port}" https://ipinfo.io/ip >/dev/null 2>&1; then
        end="$(date +%s%3N)"
        latency=$((end - start))
        echo "$latency"
        return 0
      fi
      ;;
  esac
  
  echo "-1"
  return 1
}

# 测试所有代理并排序
test_all_proxies() {
  local max="${1:-10}"
  
  if [[ ! -f "$CACHE" ]]; then
    red "[-] 代理缓存为空，请先运行 proxyctl fetch <country>"
    return 1
  fi
  
  local proxies count
  proxies="$(cat "$CACHE")"
  count="$(echo "$proxies" | jq 'length')"
  
  [[ "$count" -gt "$max" ]] && count="$max"
  
  ylw "[*] 正在测试 $count 个代理..."
  
  local results=()
  for i in $(seq 0 $((count - 1))); do
    local ip port protocol
    ip="$(echo "$proxies" | jq -r ".[$i].ip")"
    port="$(echo "$proxies" | jq -r ".[$i].port")"
    protocol="$(echo "$proxies" | jq -r ".[$i].protocol")"
    
    printf "  测试 %s:%s (%s)... " "$ip" "$port" "$protocol"
    
    local latency
    latency="$(test_proxy "$ip" "$port" "$protocol" 5 || echo "-1")"
    
    if [[ "$latency" -ge 0 ]]; then
      grn "${latency}ms"
      results+=("$latency|$ip|$port|$protocol")
    else
      red "失败"
    fi
  done
  
  if [[ ${#results[@]} -eq 0 ]]; then
    red "[-] 没有可用的代理"
    return 1
  fi
  
  # 按延迟排序
  IFS=$'\n' sorted=($(sort -t'|' -k1 -n <<<"${results[*]}")); unset IFS
  
  echo ""
  grn "[+] 可用代理列表（按延迟排序）:"
  local idx=1
  for r in "${sorted[@]}"; do
    IFS='|' read -r lat ip port proto <<< "$r"
    printf "  %2d) %s:%s [%s] - %sms\n" "$idx" "$ip" "$port" "$proto" "$lat"
    ((idx++))
  done
  
  # 保存排序结果
  printf '%s\n' "${sorted[@]}" > /var/lib/freeproxy/tested.txt
  
  echo "${#sorted[@]}"
}

# 选择并应用代理
select_proxy() {
  if [[ ! -f /var/lib/freeproxy/tested.txt ]]; then
    red "[-] 请先运行 proxyctl test 测试代理"
    return 1
  fi
  
  mapfile -t sorted < /var/lib/freeproxy/tested.txt
  
  if [[ ${#sorted[@]} -eq 0 ]]; then
    red "[-] 没有可用代理"
    return 1
  fi
  
  echo ""
  echo "可用代理:"
  local idx=1
  for r in "${sorted[@]}"; do
    IFS='|' read -r lat ip port proto <<< "$r"
    printf "  %2d) %s:%s [%s] - %sms\n" "$idx" "$ip" "$port" "$proto" "$lat"
    ((idx++))
  done
  echo "   0) 取消"
  echo "   A) 自动选择最低延迟"
  
  read -r -p "选择编号: " sel
  
  if [[ "${sel^^}" == "A" ]]; then
    sel=1
  elif [[ "$sel" == "0" ]]; then
    return 0
  fi
  
  if ! [[ "$sel" =~ ^[0-9]+$ ]] || [[ "$sel" -lt 1 ]] || [[ "$sel" -gt ${#sorted[@]} ]]; then
    red "[-] 无效选择"
    return 1
  fi
  
  local chosen="${sorted[$((sel-1))]}"
  IFS='|' read -r lat ip port proto <<< "$chosen"
  
  apply_proxy "$ip" "$port" "$proto"
}

# 应用代理到系统
apply_proxy() {
  local ip="$1" port="$2" protocol="$3"
  
  ylw "[*] 应用代理: $ip:$port ($protocol)"
  
  # 保存到配置
  local tmp
  tmp="$(mktemp)"
  jq --arg ip "$ip" --argjson port "$port" --arg proto "$protocol" \
    '.current_proxy = {"ip": $ip, "port": $port, "protocol": $proto}' "$CFG" > "$tmp"
  mv "$tmp" "$CFG"
  
  # 更新 Xray 配置
  if [[ -f /etc/xray/config.json ]]; then
    local outbound
    case "$protocol" in
      socks5|socks4)
        outbound='[{"protocol":"socks","tag":"freeproxy","settings":{"servers":[{"address":"'"$ip"'","port":'"$port"'}]}}]'
        ;;
      http|https)
        outbound='[{"protocol":"http","tag":"freeproxy","settings":{"servers":[{"address":"'"$ip"'","port":'"$port"'}]}}]'
        ;;
    esac
    
    local routing='{"domainStrategy":"AsIs","rules":[{"type":"field","outboundTag":"freeproxy","network":"tcp,udp"}]}'
    tmp="$(mktemp)"
    jq --argjson ob "$outbound" --argjson rt "$routing" \
      '.outbounds=$ob | .routing=$rt' /etc/xray/config.json > "$tmp"
    mv "$tmp" /etc/xray/config.json
    
    systemctl restart xray 2>/dev/null || true
    grn "[+] Xray 配置已更新"
  fi
  
  # 更新 Hysteria2 配置
  if [[ -f /etc/hysteria/config.yaml ]]; then
    local tmp2
    tmp2="$(mktemp)"
    awk '
      BEGIN{skip=0}
      /^outbounds:/{skip=1; next}
      /^acl:/{skip=1; next}
      /^[a-z]/ && skip{skip=0}
      {if(!skip) print}
    ' /etc/hysteria/config.yaml > "$tmp2"
    
    case "$protocol" in
      socks5|socks4)
        cat >> "$tmp2" <<EOF

outbounds:
  - name: freeproxy
    type: socks5
    socks5:
      addr: ${ip}:${port}

acl:
  inline:
    - freeproxy(all)
EOF
        ;;
      http|https)
        cat >> "$tmp2" <<EOF

outbounds:
  - name: freeproxy
    type: http
    http:
      url: http://${ip}:${port}

acl:
  inline:
    - freeproxy(all)
EOF
        ;;
    esac
    
    mv "$tmp2" /etc/hysteria/config.yaml
    systemctl restart hysteria2 2>/dev/null || true
    grn "[+] Hysteria2 配置已更新"
  fi
  
  write_cfg "enabled" "true"
  grn "[+] 代理已启用: $ip:$port ($protocol)"
}

# 健康检查
health_check() {
  local enabled current_ip current_port current_proto
  enabled="$(read_cfg "enabled" "false")"
  
  if [[ "$enabled" != "true" ]]; then
    echo "[i] Free Proxy 未启用"
    return 0
  fi
  
  current_ip="$(jq -r '.current_proxy.ip // empty' "$CFG")"
  current_port="$(jq -r '.current_proxy.port // empty' "$CFG")"
  current_proto="$(jq -r '.current_proxy.protocol // empty' "$CFG")"
  
  if [[ -z "$current_ip" ]]; then
    ylw "[!] 没有当前代理配置"
    return 0
  fi
  
  echo "[*] 健康检查: $current_ip:$current_port ($current_proto)"
  
  local latency
  latency="$(test_proxy "$current_ip" "$current_port" "$current_proto" 10 || echo "-1")"
  
  if [[ "$latency" -ge 0 ]]; then
    grn "[+] 代理正常 - ${latency}ms"
    return 0
  fi
  
  red "[-] 当前代理不可用，正在切换..."
  
  # 重新获取并测试
  local country
  country="$(read_cfg "country" "US")"
  
  fetch_proxies "$country" "all" >/dev/null 2>&1 || true
  test_all_proxies 20 >/dev/null 2>&1 || {
    red "[-] 没有可用代理"
    return 1
  }
  
  # 自动选择最低延迟
  if [[ -f /var/lib/freeproxy/tested.txt ]]; then
    local first
    first="$(head -1 /var/lib/freeproxy/tested.txt)"
    if [[ -n "$first" ]]; then
      IFS='|' read -r lat ip port proto <<< "$first"
      apply_proxy "$ip" "$port" "$proto"
      grn "[+] 已自动切换到: $ip:$port ($proto) - ${lat}ms"
    fi
  fi
}

# 设置健康检查间隔
set_interval() {
  local minutes="$1"
  
  if ! [[ "$minutes" =~ ^[0-9]+$ ]] || [[ "$minutes" -lt 1 ]]; then
    red "[-] 无效间隔，请输入大于0的分钟数"
    return 1
  fi
  
  write_cfg "health_interval_min" "$minutes"
  
  # 更新 systemd timer
  if [[ -f /etc/systemd/system/freeproxy-health.timer ]]; then
    cat > /etc/systemd/system/freeproxy-health.timer <<EOF
[Unit]
Description=Free Proxy Health Check Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${minutes}min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl restart freeproxy-health.timer 2>/dev/null || true
  fi
  
  grn "[+] 健康检查间隔已设置为 ${minutes} 分钟"
}

# 显示状态
show_status() {
  echo ""
  echo "========== Free Proxy 状态 =========="
  echo ""
  
  local enabled country proto interval
  enabled="$(read_cfg "enabled" "false")"
  country="$(read_cfg "country" "US")"
  proto="$(read_cfg "protocol" "all")"
  interval="$(read_cfg "health_interval_min" "10")"
  
  echo "启用状态: $([[ "$enabled" == "true" ]] && echo "✓ 已启用" || echo "✗ 未启用")"
  echo "出口国家: $(cc_label "$country")"
  echo "协议过滤: $proto"
  echo "检查间隔: ${interval} 分钟"
  echo ""
  
  local current_ip current_port current_proto
  current_ip="$(jq -r '.current_proxy.ip // empty' "$CFG" 2>/dev/null)"
  current_port="$(jq -r '.current_proxy.port // empty' "$CFG" 2>/dev/null)"
  current_proto="$(jq -r '.current_proxy.protocol // empty' "$CFG" 2>/dev/null)"
  
  if [[ -n "$current_ip" ]]; then
    echo "当前代理: $current_ip:$current_port ($current_proto)"
    
    echo -n "连通性: "
    local latency
    latency="$(test_proxy "$current_ip" "$current_port" "$current_proto" 5 || echo "-1")"
    if [[ "$latency" -ge 0 ]]; then
      grn "正常 (${latency}ms)"
    else
      red "不可用"
    fi
  else
    echo "当前代理: 未设置"
  fi
  
  echo ""
  echo "====================================="
}

# 禁用代理
disable_proxy() {
  write_cfg "enabled" "false"
  
  # 恢复 Xray 直连
  if [[ -f /etc/xray/config.json ]]; then
    local tmp
    tmp="$(mktemp)"
    jq '.outbounds=[{"protocol":"freedom","tag":"direct","settings":{}}] | .routing={"domainStrategy":"AsIs","rules":[{"type":"field","outboundTag":"direct","network":"tcp,udp"}]}' \
      /etc/xray/config.json > "$tmp"
    mv "$tmp" /etc/xray/config.json
    systemctl restart xray 2>/dev/null || true
  fi
  
  # 恢复 Hysteria2
  if [[ -f /etc/hysteria/config.yaml ]]; then
    local tmp2
    tmp2="$(mktemp)"
    awk '
      BEGIN{skip=0}
      /^outbounds:/{skip=1; next}
      /^acl:/{skip=1; next}
      /^[a-z]/ && skip{skip=0}
      {if(!skip) print}
    ' /etc/hysteria/config.yaml > "$tmp2"
    mv "$tmp2" /etc/hysteria/config.yaml
    systemctl restart hysteria2 2>/dev/null || true
  fi
  
  grn "[+] Free Proxy 已禁用，已恢复直连"
}

# 主命令
case "${1:-}" in
  fetch)
    country="${2:-US}"
    protocol="${3:-all}"
    fetch_proxies "$country" "$protocol"
    ;;
  test)
    max="${2:-15}"
    test_all_proxies "$max"
    ;;
  switch)
    select_proxy
    ;;
  health)
    health_check
    ;;
  interval)
    [[ -n "${2:-}" ]] || { echo "用法: proxyctl interval <分钟>"; exit 1; }
    set_interval "$2"
    ;;
  status)
    show_status
    ;;
  disable)
    disable_proxy
    ;;
  *)
    echo "proxyctl - Free Proxy List 管理工具"
    echo ""
    echo "用法:"
    echo "  proxyctl fetch <country> [protocol]  获取代理列表 (protocol: http/socks4/socks5/all)"
    echo "  proxyctl test [max]                  测试代理可用性 (默认测试15个)"
    echo "  proxyctl switch                      选择并切换代理"
    echo "  proxyctl health                      健康检查 (会自动切换)"
    echo "  proxyctl interval <分钟>             设置健康检查间隔"
    echo "  proxyctl status                      查看状态"
    echo "  proxyctl disable                     禁用代理，恢复直连"
    echo ""
    echo "常用国家: US JP SG DE FR GB NL CA KR HK TW"
    ;;
esac
PROXYCTL_EOF

  chmod +x /usr/local/bin/proxyctl
  grn "[+] proxyctl 已安装"
}

# ========= freeproxy-health.timer (健康检查定时器) =========
install_freeproxy_timer(){
  local interval="${1:-10}"
  
  ylw "[*] 安装 Free Proxy 健康检查定时器 (间隔: ${interval}分钟)..."
  
  cat > /etc/systemd/system/freeproxy-health.service <<'EOF'
[Unit]
Description=Free Proxy Health Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/proxyctl health
EOF

  cat > /etc/systemd/system/freeproxy-health.timer <<EOF
[Unit]
Description=Free Proxy Health Check Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${interval}min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable freeproxy-health.timer
  grn "[+] 健康检查定时器已安装"
}


install_menu(){
  ylw "[*] 安装菜单命令 vpsmenu (纯文本菜单)..."
  
  # 统一菜单：无论 direct/psiphon，都用同一份脚本
  # 运行时根据 psictl 是否存在来决定功能可用性
  # 支持 whiptail 美化（没装就降级文本版）
  cat > /usr/local/bin/vpsmenu <<'MENU_EOF'
#!/usr/bin/env bash
set -euo pipefail

SERVICES_IN=("xray" "hysteria2" "tuic")
SERVICE_PSI="psiphon"
CLIENT_JSON="/etc/psiphon-egress/client.json"
PSI_CFG="/etc/psiphon/psiphon.config"

have_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

pause() { read -r -p $'\n回车继续...' _; }

# ==================== 文本版菜单（取消 whiptail）====================
show_text_menu() {
  clear
  local mode="unknown" psi_status="未安装" fp_status="未安装"
  [[ -f "$CLIENT_JSON" ]] && have_cmd jq && mode="$(jq -r '.egress_mode // "unknown"' "$CLIENT_JSON" 2>/dev/null || echo unknown)"
  have_cmd psictl && psi_status="已安装"
  have_cmd proxyctl && fp_status="已安装"

  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║   多协议入站 + 多出站 管理菜单 (合并版)                  ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  egress_mode=${mode} | psictl=${psi_status} | proxyctl=${fp_status}"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  入站(通用)                                              ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║   1) 查看分享链接                                        ║"
  echo "║   2) 重启所有服务                                        ║"
  echo "║   3) 查看服务状态                                        ║"
  echo "║   4) 查看日志                                            ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  Psiphon(赛风)                                           ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║   5) Psiphon 状态                                        ║"
  echo "║   6) 切换出口国家                                        ║"
  echo "║   7) 测试当前出口 IP                                     ║"
  echo "║   8) 智能选出口                                          ║"
  echo "║   9) Psiphon 日志                                        ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  Free Proxy (免费代理)                                   ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  20) 选择国家/协议 + 获取代理                            ║"
  echo "║  21) 测试代理可用性                                      ║"
  echo "║  22) 切换代理节点                                        ║"
  echo "║  23) 查看状态                                            ║"
  echo "║  24) 设置检查间隔                                        ║"
  echo "║  25) 禁用代理(恢复直连)                                  ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  出站模式                                                ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  10) 出口 IP 检测 (direct / psiphon / freeproxy)         ║"
  echo "║  11) 切换出站模式 (direct/psiphon/freeproxy)             ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║   A) 安装/更新 Psiphon 组件                              ║"
  echo "║   B) 安装/更新 Free Proxy 组件                           ║"
  echo "║   0) 退出                                                ║"
  echo "╚══════════════════════════════════════════════════════════╝"
}

# ==================== 菜单入口（强制文本版）====================
show_menu() {
  show_text_menu
}

# ==================== 功能函数 ====================
view_links() {
  if have_cmd psictl; then
    psictl links
  else
    if [[ ! -f "$CLIENT_JSON" ]]; then
      echo "[-] 未找到 $CLIENT_JSON，无法生成分享链接"
      echo "    请重新运行安装脚本"
      return 1
    fi

    local host cert_mode insecure
    host="$(jq -r '.host' "$CLIENT_JSON")"
    cert_mode="$(jq -r '.cert_mode' "$CLIENT_JSON")"
    [[ "$cert_mode" == "self" ]] && insecure=1 || insecure=0

    local v_port v_uuid v_sni v_pbk v_sid
    v_port="$(jq -r '.vless.port' "$CLIENT_JSON")"
    v_uuid="$(jq -r '.vless.uuid' "$CLIENT_JSON")"
    v_sni="$(jq -r '.vless.sni' "$CLIENT_JSON")"
    v_pbk="$(jq -r '.vless.pbk' "$CLIENT_JSON")"
    v_sid="$(jq -r '.vless.sid' "$CLIENT_JSON")"

    local h_port h_auth h_obfs h_sni
    h_port="$(jq -r '.hy2.port' "$CLIENT_JSON")"
    h_auth="$(jq -r '.hy2.auth' "$CLIENT_JSON")"
    h_obfs="$(jq -r '.hy2.obfs_password' "$CLIENT_JSON")"
    h_sni="$(jq -r '.hy2.sni // "www.bing.com"' "$CLIENT_JSON")"

    local t_port t_uuid t_pass t_sni
    t_port="$(jq -r '.tuic.port // empty' "$CLIENT_JSON")"
    t_uuid="$(jq -r '.tuic.uuid // empty' "$CLIENT_JSON")"
    t_pass="$(jq -r '.tuic.password // empty' "$CLIENT_JSON")"
    t_sni="$(jq -r '.tuic.sni // "www.bing.com"' "$CLIENT_JSON")"

    echo ""
    echo "==================== 分享链接 ===================="
    echo ""
    echo "[VLESS+REALITY]"
    echo "vless://${v_uuid}@${host}:${v_port}?encryption=none&security=reality&sni=${v_sni}&fp=chrome&pbk=${v_pbk}&sid=${v_sid}&type=tcp&flow=xtls-rprx-vision#VLESS-Reality"
    echo ""
    echo "[Hysteria2]"
    echo "hysteria2://${h_auth}@${host}:${h_port}/?obfs=salamander&obfs-password=${h_obfs}&sni=${h_sni}&insecure=${insecure}&alpn=h3#HY2"
    if [[ -n "$t_uuid" && "$t_uuid" != "null" ]]; then
      echo ""
      echo "[TUIC v5]"
      echo "tuic://${t_uuid}:${t_pass}@${host}:${t_port}?alpn=h3&udp_relay_mode=native&congestion_control=bbr&sni=${t_sni}&allow_insecure=${insecure}#TUIC-v5"
    fi
    echo ""
    echo "=================================================="
  fi
}

restart_all() {
  echo "重启入站服务: ${SERVICES_IN[*]}"
  systemctl restart "${SERVICES_IN[@]}" 2>/dev/null || true

  if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_PSI}\.service"; then
    echo "重启 Psiphon: ${SERVICE_PSI}"
    systemctl restart "${SERVICE_PSI}" 2>/dev/null || true
  else
    echo "未发现 psiphon.service，跳过。"
  fi
  echo "[+] 完成。"
}

status_all() {
  echo "===== 入站服务状态 ====="
  for svc in "${SERVICES_IN[@]}"; do
    echo ""
    echo "--- $svc ---"
    systemctl --no-pager status "$svc" 2>/dev/null || echo "$svc 未安装或未运行"
  done
  echo ""
  echo "--- psiphon ---"
  systemctl --no-pager status "${SERVICE_PSI}" 2>/dev/null || echo "psiphon 未安装或未运行"
}

logs_menu() {
  echo "可选：xray | hy2 | tuic | psi | all"
  read -r -p "选择(默认 all): " s
  s="${s:-all}"
  case "$s" in
    xray) journalctl -u xray -n 200 --no-pager ;;
    hy2|hysteria2) journalctl -u hysteria2 -n 200 --no-pager ;;
    tuic) journalctl -u tuic -n 200 --no-pager ;;
    psi|psiphon)
      if have_cmd psictl; then psictl logs psi; else journalctl -u psiphon -n 200 --no-pager; fi
      ;;
    all|"")
      if have_cmd psictl; then psictl logs; else
        for u in xray hysteria2 tuic psiphon; do
          echo -e "\n===== $u ====="
          journalctl -u "$u" -n 120 --no-pager 2>/dev/null || echo "$u 未运行"
        done
      fi
      ;;
    *) echo "未知选择: $s" ;;
  esac
}

psi_guard() {
  if ! have_cmd psictl; then
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  未检测到 psictl（Psiphon 组件未安装）               ║"
    echo "║  请先选择 'A' 安装 Psiphon 组件                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    return 1
  fi
  return 0
}

psi_status() { psi_guard || return 0; psictl status; }

psi_country() {
  psi_guard || return 0
  echo "常用: US JP SG DE FR GB NL AT BE CA CH"
  read -r -p "输入国家代码(如 JP/SG/US) 或 AUTO: " c
  c="${c:-AUTO}"
  psictl country "$c"
  psictl egress-test || true
}

psi_egress_test() { psi_guard || return 0; psictl egress-test; }
psi_smart_country() { psi_guard || return 0; psictl smart-country; }

# ==================== 新增：出口 IP 检测 & 模式切换 ====================
read_psi_ports() {
  local socks http
  socks="$(jq -r '.LocalSocksProxyPort // 1081' "$PSI_CFG" 2>/dev/null || echo 1081)"
  http="$(jq -r '.LocalHttpProxyPort // 8081' "$PSI_CFG" 2>/dev/null || echo 8081)"
  echo "$socks $http"
}

direct_egress_test() {
  echo "===== Direct 出口 IP ====="
  curl -fsS --max-time 10 https://ipinfo.io/json | jq -r '"IP: \(.ip)\nCountry: \(.country)\nOrg: \(.org)\nCity: \(.city)"' || echo "[-] 检测失败"
  echo ""
}

psiphon_egress_test() {
  echo "===== Psiphon 出口 IP ====="
  if have_cmd psictl; then
    psictl egress-test || echo "[-] Psiphon出口检测失败"
  else
    local socks
    read -r socks _ < <(read_psi_ports)
    curl -fsS --max-time 12 --socks5-hostname "127.0.0.1:${socks}" https://ipinfo.io/json \
      | jq -r '"IP: \(.ip)\nCountry: \(.country)\nOrg: \(.org)\nCity: \(.city)"' || echo "[-] Psiphon出口检测失败"
  fi
  echo ""
}

egress_ip_detect() {
  direct_egress_test
  if systemctl list-unit-files 2>/dev/null | grep -q '^psiphon\.service'; then
    psiphon_egress_test
  else
    echo "[-] 未安装 psiphon.service，跳过 Psiphon 出口检测。"
    echo ""
  fi
}

ensure_client_json() {
  mkdir -p /etc/psiphon-egress
  if [[ ! -f "$CLIENT_JSON" ]]; then
    cat >"$CLIENT_JSON" <<'EOF'
{ "egress_mode": "direct" }
EOF
  fi
}

set_client_mode() {
  local mode="$1"
  ensure_client_json
  local tmp
  tmp="$(mktemp)"
  jq --arg m "$mode" '.egress_mode=$m' "$CLIENT_JSON" >"$tmp" && mv "$tmp" "$CLIENT_JSON"
}

xray_apply_mode() {
  local mode="$1"
  local socks
  read -r socks _ < <(read_psi_ports)

  local outbounds routing sniffing

  case "$mode" in
    direct)
      outbounds='[{"protocol":"freedom","tag":"direct","settings":{}}]'
      routing='{"domainStrategy":"AsIs","rules":[{"type":"field","outboundTag":"direct","network":"tcp,udp"}]}'
      sniffing='{"enabled":true,"destOverride":["http","tls"]}'
      ;;
    psiphon)
      # 全局 Psiphon: TCP+UDP 都走 Psiphon socks5
      outbounds='[
        {"protocol":"socks","tag":"psiphon","settings":{"servers":[{"address":"127.0.0.1","port":'"$socks"'}]}}
      ]'
      routing='{"domainStrategy":"AsIs","rules":[{"type":"field","outboundTag":"psiphon","network":"tcp,udp"}]}'
      sniffing='{"enabled":true,"destOverride":["http","tls"]}'
      ;;
    *)
      echo "[-] 未知 mode: $mode"; return 1 ;;
  esac

  if [[ ! -f /etc/xray/config.json ]]; then
    echo "[-] 未找到 /etc/xray/config.json，跳过 Xray 配置更新"
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  jq --argjson ob "$outbounds" --argjson rt "$routing" --argjson sn "$sniffing" '
    .outbounds=$ob
    | .routing=$rt
    | (.inbounds[] |= (.sniffing=$sn))
  ' /etc/xray/config.json >"$tmp" && mv "$tmp" /etc/xray/config.json
  echo "[+] Xray 配置已更新"
}

hy2_apply_mode() {
  local mode="$1"
  local socks
  read -r socks _ < <(read_psi_ports)

  local f="/etc/hysteria/config.yaml"
  [[ -f "$f" ]] || { echo "[-] 未找到 $f，跳过 Hysteria2 配置更新"; return 0; }

  local tmp
  tmp="$(mktemp)"
  # 删除旧的 outbounds/acl 段，再按 mode 重新追加
  awk '
    BEGIN{skip=0}
    /^outbounds:/{skip=1}
    /^acl:/{skip=1}
    {if(!skip) print}
  ' "$f" >"$tmp"

  case "$mode" in
    direct)
      ;;
    psiphon)
      # 全局 Psiphon: TCP+UDP 都走 Psiphon socks5
      cat >>"$tmp" <<EOF

outbounds:
  - name: psiphon
    type: socks5
    socks5:
      addr: 127.0.0.1:${socks}

acl:
  inline:
    - psiphon(all)
EOF
      ;;
  esac

  mv "$tmp" "$f"
  echo "[+] Hysteria2 配置已更新"
}

rewrite_units_by_mode() {
  local mode="$1"

  # 非 direct 就 Wants/After psiphon.service
  local unit_after unit_wants
  if [[ "$mode" != "direct" ]]; then
    unit_after="After=network-online.target psiphon.service"
    unit_wants="Wants=network-online.target psiphon.service"
  else
    unit_after="After=network-online.target"
    unit_wants="Wants=network-online.target"
  fi

  if [[ -f /etc/systemd/system/xray.service ]]; then
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray-core (VLESS+REALITY) Server
${unit_after}
${unit_wants}

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    echo "[+] xray.service 已更新"
  fi

  if [[ -f /etc/systemd/system/hysteria2.service ]]; then
    cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
${unit_after}
${unit_wants}

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    echo "[+] hysteria2.service 已更新"
  fi

  systemctl daemon-reload
}

switch_egress_mode() {
  local current_mode
  current_mode="$(jq -r '.egress_mode // "direct"' "$CLIENT_JSON" 2>/dev/null || echo direct)"
  echo ""
  echo "当前模式: $current_mode"
  echo ""
  echo "1) direct    (全直连)"
  echo "2) psiphon   (全走 Psiphon)"
  echo "3) freeproxy (全走免费代理)"
  echo "0) 取消"
  read -r -p "选择 [0-3]: " n

  local mode
  case "$n" in
    1) mode="direct" ;;
    2) mode="psiphon" ;;
    3) mode="freeproxy" ;;
    0) return 0 ;;
    *) echo "[-] 无效选择"; return 0 ;;
  esac

  # psiphon 模式必须要有 psictl / Psiphon
  if [[ "$mode" == "psiphon" ]] && ! have_cmd psictl; then
    echo ""
    echo "[-] 未检测到 psictl / Psiphon 组件。"
    echo "    请先在菜单里选 'A' 安装 Psiphon 组件，然后再切换模式。"
    return 0
  fi

  # freeproxy 模式必须要有 proxyctl
  if [[ "$mode" == "freeproxy" ]] && ! have_cmd proxyctl; then
    echo ""
    echo "[-] 未检测到 proxyctl / Free Proxy 组件。"
    echo "    请先在菜单里选 'B' 安装 Free Proxy 组件，然后再切换模式。"
    return 0
  fi

  set_client_mode "$mode"
  
  if [[ "$mode" == "freeproxy" ]]; then
    # freeproxy 模式：检查是否有配置好的代理
    local fp_enabled
    fp_enabled="$(jq -r '.enabled // false' /etc/freeproxy/config.json 2>/dev/null || echo false)"
    if [[ "$fp_enabled" != "true" ]]; then
      echo ""
      echo "[!] Free Proxy 尚未配置。请先使用菜单 20-22 获取并选择代理。"
      echo "    或者运行: proxyctl fetch US && proxyctl test && proxyctl switch"
    else
      echo "[+] Free Proxy 已启用"
    fi
    # 启动健康检查定时器
    systemctl enable --now freeproxy-health.timer 2>/dev/null || true
    systemctl stop psiphon 2>/dev/null || true
  else
    xray_apply_mode "$mode"
    hy2_apply_mode "$mode"
    rewrite_units_by_mode "$mode"

    if [[ "$mode" == "direct" ]]; then
      systemctl stop psiphon 2>/dev/null || true
      systemctl stop freeproxy-health.timer 2>/dev/null || true
      echo "[*] psiphon.service 已停止"
    else
      systemctl enable --now psiphon 2>/dev/null || systemctl start psiphon 2>/dev/null || true
      systemctl stop freeproxy-health.timer 2>/dev/null || true
      echo "[*] psiphon.service 已启动"
    fi

    systemctl restart xray hysteria2 2>/dev/null || true
  fi

  echo ""
  echo "[+] 已切换为: $mode"
  echo "    注意：TUIC 在这套方案里不跟随模式切换（固定 direct）"
}

psi_logs() {
  if have_cmd psictl; then
    psictl logs psi
  else
    journalctl -u psiphon -n 200 --no-pager 2>/dev/null || echo "psiphon.service 不存在"
  fi
}

# ==================== Free Proxy 菜单函数 ====================
fp_guard() {
  if ! have_cmd proxyctl; then
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  未检测到 proxyctl（Free Proxy 组件未安装）          ║"
    echo "║  请先选择 'B' 安装 Free Proxy 组件                   ║"
    echo "╚══════════════════════════════════════════════════════╝"
    return 1
  fi
  return 0
}

fp_fetch() {
  fp_guard || return 0
  echo ""
  echo "常用国家: US JP SG DE FR GB NL CA KR HK TW"
  read -r -p "输入国家代码 [US]: " country
  country="${country:-US}"
  
  echo ""
  echo "协议选择:"
  echo "  1) all (全部)"
  echo "  2) socks5"
  echo "  3) socks4"
  echo "  4) http"
  read -r -p "选择 [1]: " proto_sel
  local protocol
  case "$proto_sel" in
    2) protocol="socks5" ;;
    3) protocol="socks4" ;;
    4) protocol="http" ;;
    *) protocol="all" ;;
  esac
  
  proxyctl fetch "$country" "$protocol"
}

fp_test() { fp_guard || return 0; proxyctl test; }
fp_switch() { fp_guard || return 0; proxyctl switch; }
fp_status() { fp_guard || return 0; proxyctl status; }
fp_disable() { fp_guard || return 0; proxyctl disable; }

fp_interval() {
  fp_guard || return 0
  local current
  current="$(jq -r '.health_interval_min // 10' /etc/freeproxy/config.json 2>/dev/null || echo 10)"
  echo ""
  echo "当前检查间隔: ${current} 分钟"
  read -r -p "输入新间隔 (分钟): " mins
  if [[ -n "$mins" ]]; then
    proxyctl interval "$mins"
  fi
}

# ==================== Free Proxy 组件安装 ====================
fp_setup() {
  if ! is_root; then
    echo "[-] 请用 root 运行"
    return 1
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║  安装/更新 Free Proxy 组件                           ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo ""
  
  # 安装依赖
  if have_cmd apt-get; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl jq >/dev/null 2>&1 || true
  elif have_cmd dnf; then
    dnf -y install curl jq >/dev/null 2>&1 || true
  elif have_cmd yum; then
    yum -y install curl jq >/dev/null 2>&1 || true
  fi

  mkdir -p /etc/freeproxy /var/lib/freeproxy
  
  # 初始化配置文件
  if [[ ! -f /etc/freeproxy/config.json ]]; then
    local interval
    read -r -p "健康检查间隔 (分钟) [10]: " interval
    interval="${interval:-10}"
    cat > /etc/freeproxy/config.json <<EOF
{
  "enabled": false,
  "country": "US",
  "protocol": "socks5",
  "health_interval_min": $interval,
  "current_proxy": null
}
EOF
  else
    echo "[*] 配置文件已存在，保留现有配置"
  fi
  
  # 安装 proxyctl (从 install.sh 中提取)
  # 这里我们用简化版 - 只需确保 proxyctl 命令可用
  if ! have_cmd proxyctl; then
    echo "[!] proxyctl 需要通过完整安装脚本安装"
    echo "    请运行: bash install.sh"
    return 1
  fi
  
  # 安装健康检查定时器
  cat > /etc/systemd/system/freeproxy-health.service <<'EOF'
[Unit]
Description=Free Proxy Health Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/proxyctl health
EOF

  local interval
  interval="$(jq -r '.health_interval_min // 10' /etc/freeproxy/config.json 2>/dev/null || echo 10)"
  cat > /etc/systemd/system/freeproxy-health.timer <<EOF
[Unit]
Description=Free Proxy Health Check Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${interval}min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable freeproxy-health.timer
  
  echo ""
  echo "[+] Free Proxy 组件安装完成！"
  echo "    使用菜单 20-22 获取并选择代理"
  echo "    使用菜单 11 切换到 freeproxy 模式"
}


psi_setup() {
  if ! is_root; then
    echo "[-] 请用 root 运行"
    return 1
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║  安装/更新 Psiphon 组件 (不动入站配置)               ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo ""

  # 安装依赖
  if have_cmd apt-get; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl wget jq unzip ca-certificates >/dev/null 2>&1 || true
  elif have_cmd dnf; then
    dnf -y install curl wget jq unzip ca-certificates >/dev/null 2>&1 || true
  elif have_cmd yum; then
    yum -y install curl wget jq unzip ca-certificates >/dev/null 2>&1 || true
  fi

  # 检测平台
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in linux) os="linux";; freebsd) os="freebsd";; *) echo "不支持的 OS: $os"; return 1;; esac
  
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$arch" in x86_64|amd64) arch="amd64";; aarch64|arm64) arch="arm64";; armv7l|armv7|armv6l) arch="armv7";; i386|i686) arch="386";; *) echo "不支持的架构: $arch"; return 1;; esac

  echo "[*] 平台: ${os}/${arch}"

  # 读取已有配置或使用默认值
  local REGION="US" SOCKS="1081" HTTP="8081"
  if [[ -f "$PSI_CFG" ]] && have_cmd jq; then
    REGION="$(jq -r '.EgressRegion // "US"' "$PSI_CFG" 2>/dev/null || echo "US")"
    [[ -z "$REGION" ]] && REGION="US"
    SOCKS="$(jq -r '.LocalSocksProxyPort // 1081' "$PSI_CFG" 2>/dev/null || echo "1081")"
    HTTP="$(jq -r '.LocalHttpProxyPort // 8081' "$PSI_CFG" 2>/dev/null || echo "8081")"
  fi

  read -r -p "Psiphon 出口国家 (如 US/JP/SG，AUTO=自动) [${REGION}]: " r || true
  REGION="${r:-$REGION}"
  [[ "${REGION^^}" == "AUTO" ]] && REGION=""
  
  read -r -p "Psiphon SOCKS5 端口 [${SOCKS}]: " s || true
  SOCKS="${s:-$SOCKS}"
  
  read -r -p "Psiphon HTTP 端口 [${HTTP}]: " h || true
  HTTP="${h:-$HTTP}"

  mkdir -p /etc/psiphon /var/lib/psiphon /usr/local/bin

  # 下载 psiphon-tunnel-core
  local TAG="v1.0.0" OWNER="hxzlplp7" REPO="psiphon-tunnel-core"
  local ASSET="psiphon-tunnel-core-${os}-${arch}.tar.gz"
  local URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}/${ASSET}"
  local FALLBACK="https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/linux/psiphon-tunnel-core-x86_64"

  local tmpd
  tmpd="$(mktemp -d)"
  trap "rm -rf '$tmpd'" RETURN

  local success=false
  if curl -fsI "$URL" >/dev/null 2>&1; then
    echo "[*] 下载: $URL"
    curl -fsSL "$URL" -o "$tmpd/$ASSET"
    tar -xzf "$tmpd/$ASSET" -C "$tmpd"
    local BIN
    BIN="$(find "$tmpd" -maxdepth 2 -type f -name 'psiphon-tunnel-core*' ! -name '*.tar.gz' | head -n1)"
    if [[ -n "$BIN" && -f "$BIN" ]]; then
      install -m 0755 "$BIN" /usr/local/bin/psiphon-tunnel-core
      success=true
    fi
  fi

  if [[ "$success" != "true" && "$os" == "linux" && "$arch" == "amd64" ]]; then
    echo "[*] Fallback 到官方二进制..."
    curl -fsSL "$FALLBACK" -o "$tmpd/psiphon-tunnel-core"
    install -m 0755 "$tmpd/psiphon-tunnel-core" /usr/local/bin/psiphon-tunnel-core
    success=true
  fi

  if [[ "$success" != "true" ]]; then
    echo "[-] 无法获取 Psiphon 二进制: ${os}/${arch}"
    return 1
  fi

  echo "[+] psiphon-tunnel-core 已安装"

  # 写配置
  cat >/etc/psiphon/psiphon.config <<JSON
{
  "LocalHttpProxyPort": ${HTTP},
  "LocalSocksProxyPort": ${SOCKS},
  "EgressRegion": "${REGION}",
  "PropagationChannelId": "FFFFFFFFFFFFFFFF",
  "SponsorId": "FFFFFFFFFFFFFFFF",
  "RemoteServerListDownloadFilename": "/var/lib/psiphon/remote_server_list",
  "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
  "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
  "UseIndistinguishableTLS": true
}
JSON

  # systemd 服务
  cat >/etc/systemd/system/psiphon.service <<'UNIT'
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
UNIT

  systemctl daemon-reload
  systemctl enable --now psiphon

  # 安装精简版 psictl（如果不存在或版本较旧）
  if ! have_cmd psictl || [[ "$(psictl 2>&1 | grep -c 'smart-country')" -eq 0 ]]; then
    echo "[*] 安装 psictl..."
    cat >/usr/local/bin/psictl <<'PSICTL'
#!/usr/bin/env bash
set -euo pipefail
CFG="/etc/psiphon/psiphon.config"
SOCKS_PORT="$(jq -r '.LocalSocksProxyPort' "$CFG" 2>/dev/null || echo "1081")"
REGION="$(jq -r '.EgressRegion // ""' "$CFG" 2>/dev/null || echo "")"

case "${1:-}" in
  status)
    echo "EgressRegion: ${REGION:-AUTO}"
    echo "SOCKS: 127.0.0.1:${SOCKS_PORT}"
    systemctl --no-pager -l status psiphon 2>/dev/null || true
    ;;
  country)
    [[ -n "${2:-}" ]] || { echo "用法: psictl country <CC|AUTO>"; exit 1; }
    tmp="$(mktemp)"
    if [[ "${2^^}" == "AUTO" ]]; then jq '.EgressRegion=""' "$CFG" >"$tmp"; else jq --arg cc "${2^^}" '.EgressRegion=$cc' "$CFG" >"$tmp"; fi
    mv "$tmp" "$CFG"
    systemctl restart psiphon
    sleep 3
    echo "[+] 已切换为: ${2^^}"
    ;;
  egress-test)
    curl -fsS --max-time 12 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://ipinfo.io/json | jq -r '"IP: \(.ip)\nCountry: \(.country)\nOrg: \(.org)\nCity: \(.city)"'
    ;;
  logs)
    case "${2:-}" in
      psi|psiphon) journalctl -u psiphon -n 200 --no-pager ;;
      xray) journalctl -u xray -n 200 --no-pager ;;
      hy2|hysteria) journalctl -u hysteria2 -n 200 --no-pager ;;
      tuic) journalctl -u tuic -n 200 --no-pager ;;
      *) journalctl -u psiphon -u xray -u hysteria2 -u tuic -n 200 --no-pager ;;
    esac
    ;;
  links)
    f="/etc/psiphon-egress/client.json"
    [[ -f "$f" ]] || { echo "[-] 未找到 $f"; exit 1; }
    host="$(jq -r '.host' "$f")"
    cert_mode="$(jq -r '.cert_mode' "$f")"
    insecure=0; [[ "$cert_mode" == "self" ]] && insecure=1
    echo ""
    echo "==================== 分享链接 ===================="
    v_port="$(jq -r '.vless.port' "$f")"; v_uuid="$(jq -r '.vless.uuid' "$f")"; v_sni="$(jq -r '.vless.sni' "$f")"; v_pbk="$(jq -r '.vless.pbk' "$f")"; v_sid="$(jq -r '.vless.sid' "$f")"
    echo "[VLESS+REALITY]"
    echo "vless://${v_uuid}@${host}:${v_port}?encryption=none&security=reality&sni=${v_sni}&fp=chrome&pbk=${v_pbk}&sid=${v_sid}&type=tcp&flow=xtls-rprx-vision#VLESS-Reality"
    h_port="$(jq -r '.hy2.port' "$f")"; h_auth="$(jq -r '.hy2.auth' "$f")"; h_obfs="$(jq -r '.hy2.obfs_password' "$f")"; h_sni="$(jq -r '.hy2.sni // "www.bing.com"' "$f")"
    echo "[Hysteria2]"
    echo "hysteria2://${h_auth}@${host}:${h_port}/?obfs=salamander&obfs-password=${h_obfs}&sni=${h_sni}&insecure=${insecure}&alpn=h3#HY2"
    t_uuid="$(jq -r '.tuic.uuid // empty' "$f")"
    if [[ -n "$t_uuid" && "$t_uuid" != "null" ]]; then
      t_port="$(jq -r '.tuic.port' "$f")"; t_pass="$(jq -r '.tuic.password' "$f")"; t_sni="$(jq -r '.tuic.sni // "www.bing.com"' "$f")"
      echo "[TUIC v5]"
      echo "tuic://${t_uuid}:${t_pass}@${host}:${t_port}?alpn=h3&udp_relay_mode=native&congestion_control=bbr&sni=${t_sni}&allow_insecure=${insecure}#TUIC-v5"
    fi
    echo "=================================================="
    ;;
  smart-country)
    echo "[智能切换] 选择国家..."
    PS3="请选择编号: "
    select cc in US JP SG DE FR GB NL AT BE CA CH AUTO 取消; do
      case "$cc" in
        取消) break ;;
        AUTO) psictl country AUTO; psictl egress-test || true; break ;;
        *) [[ -n "$cc" ]] && { psictl country "$cc"; psictl egress-test || true; break; } ;;
      esac
    done
    ;;
  *)
    echo "psictl status | country <CC|AUTO> | egress-test | links | logs [svc] | smart-country"
    ;;
esac
PSICTL
    chmod +x /usr/local/bin/psictl
    echo "[+] psictl 已安装"
  fi

  echo ""
  echo "[+] Psiphon 组件安装完成！"
  echo "    SOCKS: 127.0.0.1:${SOCKS}"
  echo "    HTTP:  127.0.0.1:${HTTP}"
  echo "    国家:  ${REGION:-AUTO}"
  echo ""
  echo "现在可以使用 Psiphon 相关菜单选项了。"
}

# ==================== 主循环 ====================
main() {
  while true; do
    show_text_menu
    read -r -p "请选择 [0-25/A/B]: " choice || true

    case "${choice:-}" in
      1) view_links; pause ;;
      2) restart_all; pause ;;
      3) status_all; pause ;;
      4) logs_menu; pause ;;
      5) psi_status; pause ;;
      6) psi_country; pause ;;
      7) psi_egress_test; pause ;;
      8) psi_smart_country; pause ;;
      9) psi_logs; pause ;;
      10) egress_ip_detect; pause ;;
      11) switch_egress_mode; pause ;;
      20) fp_fetch; pause ;;
      21) fp_test; pause ;;
      22) fp_switch; pause ;;
      23) fp_status; pause ;;
      24) fp_interval; pause ;;
      25) fp_disable; pause ;;
      [Aa]) psi_setup; pause ;;
      [Bb]) fp_setup; pause ;;
      0) exit 0 ;;
      *) [[ -n "${choice:-}" ]] && echo "无效输入: $choice" && pause ;;
    esac
  done
}

main
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
  "egress_mode": "${EGRESS_MODE}",
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
    "sni": "${QUIC_SNI}",
    "insecure": ${insecure}
  },
  "tuic": {
    "port": ${TUIC_PORT},
    "uuid": "${TUIC_UUID:-}",
    "password": "${TUIC_PASS:-}",
    "congestion_control": "bbr",
    "alpn": "h3",
    "sni": "${QUIC_SNI}",
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

  # 生成分享链接（HY2/TUIC 使用伪装站点 SNI）
  local vless_link="vless://${XRAY_UUID}@${HOST}:${VLESS_PORT}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${XRAY_PUB}&sid=${XRAY_SID}&type=tcp&flow=xtls-rprx-vision#VLESS-Reality"
  local hy2_link="hysteria2://${HY2_PASS}@${HOST}:${HY2_PORT}/?obfs=salamander&obfs-password=${HY2_OBFS}&sni=${QUIC_SNI}&insecure=${insecure}&alpn=h3#HY2"
  local tuic_link=""
  if [[ -n "${TUIC_UUID:-}" ]]; then
    tuic_link="tuic://${TUIC_UUID}:${TUIC_PASS}@${HOST}:${TUIC_PORT}?alpn=h3&udp_relay_mode=native&congestion_control=bbr&sni=${QUIC_SNI}&allow_insecure=${insecure}#TUIC-v5"
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

出站模式: ${EGRESS_MODE}
EOF

  if [[ "$EGRESS_MODE" == "direct" ]]; then
    cat <<EOF

管理命令：
  vpsmenu                  # 交互式菜单

EOF
  else
    cat <<EOF

管理命令：
  vpsmenu                  # 交互式菜单
  psictl links             # 查看分享链接
  psictl status            # 查看 Psiphon 状态
  psictl country US        # 切换出口国家
  psictl egress-test       # 测试当前出口
  psictl country-test-all  # 测试所有常用国家

EOF
  fi
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
  prompt QUIC_SNI "HY2/TUIC 伪装站点SNI" "$DEFAULT_QUIC_SNI"
  prompt CERT_MODE "HY2/TUIC TLS证书模式：le(自动申请) 或 self(自签)" "$DEFAULT_CERT_MODE"

  # 出站模式选择
  prompt EGRESS_MODE "出站模式: direct(直连) psiphon(全走Psiphon) freeproxy(免费代理)" "$DEFAULT_EGRESS_MODE"
  EGRESS_MODE="${EGRESS_MODE,,}"  # 转小写
  if [[ ! "$EGRESS_MODE" =~ ^(direct|psiphon|freeproxy)$ ]]; then
    ylw "[!] 无效的出站模式，使用默认值: direct"
    EGRESS_MODE="direct"
  fi

  # psiphon 模式需要 Psiphon 参数
  if [[ "$EGRESS_MODE" != "direct" ]]; then
    prompt PSIPHON_REGION "Psiphon 出站国家(两位代码，如 US/JP/SG/DE，AUTO=自动)" "$DEFAULT_PSIPHON_REGION"
    prompt PSIPHON_SOCKS "Psiphon 本地 SOCKS5 端口" "$DEFAULT_PSIPHON_SOCKS"
    prompt PSIPHON_HTTP "Psiphon 本地 HTTP 代理端口" "$DEFAULT_PSIPHON_HTTP"
  else
    # direct 模式不需要 Psiphon，设置默认值避免 unbound variable
    PSIPHON_REGION=""
    PSIPHON_SOCKS="1081"
    PSIPHON_HTTP="8081"
  fi

  ylw "[*] 请确保放行端口：${VLESS_PORT}/tcp, ${HY2_PORT}/udp, ${TUIC_PORT}/udp"
  ylw "[*] 出站模式: ${EGRESS_MODE}"

  # psiphon 模式安装 Psiphon
  if [[ "$EGRESS_MODE" != "direct" ]]; then
    install_psiphon
  fi

  install_xray_vless_reality
  install_hysteria2
  install_tuic_server

  # 始终安装 psictl 和 proxyctl 以便菜单使用
  install_psictl
  install_proxyctl
  
  # freeproxy 模式安装定时器
  if [[ "$EGRESS_MODE" == "freeproxy" ]]; then
    install_freeproxy_timer 10
    ylw "[*] freeproxy 模式：请运行 vpsmenu 后选择 20-22 配置代理"
  fi
  
  install_menu

  save_client_json
  print_client_info
  grn "[+] 安装完成！"
}

main "$@"
