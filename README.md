# 多协议入站 + Psiphon 出站（一键部署）

## 功能概述

在一台 Linux VPS 上部署：

- **入站协议**（使用各协议官方/主流实现）：
  - **VLESS + REALITY**（Xray-core）
  - **Hysteria2**（apernet/hysteria）
  - **TUIC v5**（EAimTY/tuic）

- **出站链路**（统一出口）：
  - **Psiphon**（通过 warp-plus 的 Psiphon 模式提供本地 SOCKS5）
  - 所有入站协议的流量都通过 SOCKS5 转发到 Psiphon 隧道

- **管理功能**：
  - 国家选择（切换 Psiphon 出口国家）
  - 国家可用性测试
  - 交互式菜单

```
┌─────────────────────────────────────────────────────────────┐
│                         客户端                              │
│   (VLESS/Reality, Hysteria2, TUIC v5)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      VPS 服务端                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Xray (VLESS+Reality)  :443 TCP                     │   │
│  │  Hysteria2             :8443 UDP                    │   │
│  │  TUIC                  :2053 UDP                    │   │
│  │                                                      │   │
│  │  ↓ 所有协议出站统一指向 ↓                           │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐   │
│  │      warp-plus (Psiphon 模式)                       │   │
│  │      SOCKS5 127.0.0.1:1081                          │   │
│  │      -4 --cfon --country US                         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                    目标网站 (落地IP: Psiphon 节点)
```

## 为什么用各协议官方实现

| 协议 | 实现 | 优势 |
|------|------|------|
| VLESS+REALITY | Xray-core (XTLS) | REALITY 协议原作者实现，最稳定 |
| Hysteria2 | apernet/hysteria | 官方实现，原生支持 socks5 outbound |
| TUIC v5 | EAimTY/tuic | 协议作者实现 |

## 适用系统

- **发行版**：Debian / Ubuntu / Rocky / Alma / CentOS（需 systemd）
- **架构**：amd64 / arm64

## 快速开始

### 方式一：一键安装（推荐）

**使用 curl：**
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hxzlplp7/sb-psiphon/main/install.sh)
```

**使用 wget（如果没有 curl）：**
```bash
bash <(wget -qO- https://raw.githubusercontent.com/hxzlplp7/sb-psiphon/main/install.sh)
```

> **提示**：脚本会自动检测并安装 curl（后续步骤需要），如果系统没有 curl 也没关系。

### 方式二：克隆仓库

```bash
sudo -i
git clone https://github.com/hxzlplp7/sb-psiphon.git
cd sb-psiphon
chmod +x install.sh uninstall.sh
bash install.sh
```

### 安装过程中的配置项

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| HOST | 客户端连接的域名或IP | example.com |
| VLESS端口 | VLESS+REALITY (TCP) | 443 |
| HY2端口 | Hysteria2 (UDP) | 8443 |
| TUIC端口 | TUIC v5 (UDP) | 2053 |
| REALITY伪装站点 | 需支持TLS1.3/H2 | www.apple.com |
| TLS证书模式 | `self`(自签) / `le`(Let's Encrypt) | self |
| Psiphon国家 | 两位国家代码 | US |
| SOCKS5端口 | warp-plus 本地端口 | 1081 |

## 管理命令

### 交互式菜单（推荐新手）

```bash
vpsmenu
```

### 命令行管理

```bash
# 查看所有服务状态
proxyctl status

# 切换 Psiphon 出口国家
proxyctl country US
proxyctl country JP
proxyctl country SG

# 测试当前出口 IP
proxyctl egress-test

# 批量测试多个国家可用性
proxyctl country-test US JP SG DE FR GB NL

# 重启所有服务
proxyctl restart

# 查看日志
proxyctl logs          # 全部
proxyctl logs wp       # warp-plus
proxyctl logs xray     # xray
proxyctl logs hy2      # hysteria2
proxyctl logs tuic     # tuic
```

## 配置文件位置

| 服务 | 配置文件 |
|------|----------|
| warp-plus | `/etc/warp-plus/config.json` |
| Xray | `/etc/xray/config.json` |
| Hysteria2 | `/etc/hysteria/config.yaml` |
| TUIC | `/etc/tuic/config.json` |
| 自签证书 | `/etc/ssl/sbox/` |

## 客户端配置示例

### VLESS + REALITY (Xray)

```
地址: <你的HOST>
端口: 443 (TCP)
UUID: <安装时生成>
Flow: xtls-rprx-vision
SNI: www.apple.com
Reality PublicKey: <安装时显示>
Reality ShortID: <安装时显示>
指纹: chrome
```

### Hysteria2

```
地址: <你的HOST>
端口: 8443 (UDP)
密码: <安装时生成>
OBFS: salamander
OBFS密码: <安装时生成>
（自签证书需要 skip-cert-verify / insecure=true）
```

### TUIC v5

```
地址: <你的HOST>
端口: 2053 (UDP)
UUID: <安装时生成>
密码: <安装时生成>
Congestion: bbr
ALPN: h3
（自签证书需要 skip-cert-verify / insecure=true）
```

## 常见问题

### Q: warp-plus 出口测试失败？

A: 
1. 检查 warp-plus 是否已加 `-4` 强制 IPv4
2. 尝试切换国家：`proxyctl country JP`
3. 查看日志：`proxyctl logs wp`

### Q: 某些国家测试失败？

A: Psiphon 对不同国家的支持程度不同，部分国家可能无法连接。用 `proxyctl country-test US JP SG DE` 测试哪些国家可用。

### Q: 客户端连接超时？

A:
1. 检查防火墙是否放行端口
2. 检查服务状态：`proxyctl status`
3. 确认 warp-plus 正常运行

## 卸载

**使用 curl：**
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hxzlplp7/sb-psiphon/main/uninstall.sh)
```

**使用 wget：**
```bash
bash <(wget -qO- https://raw.githubusercontent.com/hxzlplp7/sb-psiphon/main/uninstall.sh)
```

或本地执行：

```bash
bash uninstall.sh
```

## 参考文档

- [Xray-core (XTLS)](https://github.com/XTLS/Xray-core)
- [Hysteria2](https://v2.hysteria.network/)
- [TUIC](https://github.com/EAimTY/tuic)
- [warp-plus (bepass-org)](https://github.com/bepass-org/warp-plus)
- [Psiphon](https://psiphon.ca/)

## License

MIT
