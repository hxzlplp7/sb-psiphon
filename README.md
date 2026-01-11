# 多协议入站 + Psiphon 出站（一键部署）

## 功能概述

在一台 Linux VPS 上部署：

- **入站协议**（使用各协议官方/主流实现）：
  - **VLESS + REALITY**（Xray-core）
  - **Hysteria2**（apernet/hysteria）
  - **TUIC v5**（EAimTY/tuic）

- **出站链路**：
  - **Psiphon 官方 ConsoleClient**（tunnel-core）
  - 提供本地 SOCKS5/HTTP 代理，支持 `EgressRegion` 切换出口国家

- **管理功能**：
  - 国家选择（支持 28+ 个国家）
  - 批量国家可用性测试
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
│  │      Psiphon ConsoleClient (官方)                   │   │
│  │      SOCKS5 127.0.0.1:1081                          │   │
│  │      HTTP   127.0.0.1:8081                          │   │
│  │      EgressRegion: US/JP/SG/DE/...                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                    目标网站 (落地IP: Psiphon 节点)
```

## 适用系统

- **发行版**：Debian / Ubuntu / Rocky / Alma / CentOS（需 systemd）
- **架构**：
  - x86_64 / i686：直接下载官方预编译二进制
  - arm64 / arm：自动使用 Go 编译

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

### 方式二：克隆仓库

```bash
sudo -i
git clone https://github.com/hxzlplp7/sb-psiphon.git
cd sb-psiphon
chmod +x install.sh uninstall.sh
bash install.sh
```

## 管理命令

### 交互式菜单（推荐新手）

```bash
vpsmenu
```

### 命令行管理 (psictl)

```bash
# 查看 Psiphon 状态
psictl status

# 切换出口国家
psictl country US
psictl country JP
psictl country AUTO    # 自动选择最佳出口

# 测试当前出口 IP
psictl egress-test

# 批量测试国家可用性
psictl country-test US JP SG DE FR GB

# 测试所有常用国家（28个）
psictl country-test-all

# 重启所有服务
psictl restart

# 查看分享链接（用于客户端导入）
psictl links

# 智能切换出口（先测试后选择可用国家）
psictl smart-country

# 查看日志
psictl logs          # 全部
psictl logs psi      # psiphon
psictl logs xray     # xray
psictl logs hy2      # hysteria2
psictl logs tuic     # tuic
```

## 支持的出口国家

Psiphon 支持以下国家（使用两位国家代码）：

| 代码 | 国家 | 代码 | 国家 | 代码 | 国家 |
|------|------|------|------|------|------|
| AT | 奥地利 | BE | 比利时 | BG | 保加利亚 |
| CA | 加拿大 | CH | 瑞士 | CZ | 捷克 |
| DE | 德国 | DK | 丹麦 | EE | 爱沙尼亚 |
| ES | 西班牙 | FI | 芬兰 | FR | 法国 |
| GB | 英国 | HU | 匈牙利 | IE | 爱尔兰 |
| IN | 印度 | IT | 意大利 | JP | 日本 |
| LV | 拉脱维亚 | NL | 荷兰 | NO | 挪威 |
| PL | 波兰 | RO | 罗马尼亚 | RS | 塞尔维亚 |
| SE | 瑞典 | SG | 新加坡 | SK | 斯洛伐克 |
| US | 美国 | | | | |

使用 `AUTO` 让 Psiphon 自动选择最佳/最快的出口。

## 配置文件位置

| 服务 | 配置文件 |
|------|----------|
| Psiphon | `/etc/psiphon/psiphon.config` |
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

### Q: Psiphon 出口测试失败？

A: 
1. 先用 `psictl country AUTO` 让 Psiphon 自动选择出口
2. 再用 `psictl egress-test` 测试
3. 某些国家可能暂时不可用，用 `psictl country-test-all` 找可用国家

### Q: ARM 架构安装很慢？

A: ARM 设备（如树莓派）需要在本机编译 Psiphon，可能需要 5-10 分钟，请耐心等待。

### Q: 如何切换到其他国家？

A: 使用 `psictl country <国家代码>`，例如：
```bash
psictl country JP    # 切换到日本
psictl country SG    # 切换到新加坡
psictl country AUTO  # 自动选择
```

### Q: 证书模式选择？

> **⚠️ 重要提示**：选择 `le`（Let's Encrypt）模式时，`HOST` 必须填写域名且已解析到本机 IP，不能填 IP 地址。

A:
- `self`（默认）：自签证书，适用于任何 VPS，客户端需启用 `insecure=true`
- `le`：Let's Encrypt 自动证书，需要域名且 80/443 端口可用

## 快速排障

当服务不正常时，按以下步骤排查：

### 1. 检查服务状态
```bash
systemctl status psiphon xray hysteria2 tuic
```

### 2. 查看详细日志
```bash
# 查看 Psiphon 日志（最常见问题来源）
journalctl -u psiphon -n 200 --no-pager

# 查看所有服务日志
psictl logs
```

### 3. 检查端口监听
```bash
ss -lntup | grep -E '443|8443|2053|1081|8081'
```

### 4. 常见问题及解决

| 问题 | 可能原因 | 解决方案 |
|------|----------|----------|
| `egress-test` 失败 | Psiphon 未连接成功 | 等待 30s 后重试，或 `psictl country AUTO` |
| 端口已被占用 | 其他服务占用端口 | `ss -lntup \| grep <端口>` 查看并停止冲突服务 |
| REALITY 连接失败 | SNI 被阻断 | 尝试更换 `REALITY_SNI`（如 `www.microsoft.com`） |
| Hysteria2/TUIC 无法连接 | UDP 被阻断 | 检查防火墙是否放行 UDP 端口 |

## 卸载

**使用 curl：**
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hxzlplp7/sb-psiphon/main/uninstall.sh)
```

**使用 wget：**
```bash
bash <(wget -qO- https://raw.githubusercontent.com/hxzlplp7/sb-psiphon/main/uninstall.sh)
```

## 安全提示

> **⚠️ 注意**：本脚本会从 GitHub 下载第三方二进制文件（Xray、Hysteria2、TUIC）。建议在受控环境中使用。

- Psiphon 二进制优先使用 [hxzlplp7/psiphon-tunnel-core](https://github.com/hxzlplp7/psiphon-tunnel-core/releases) 的预编译版本（带 SHA256 校验）
- 其他组件从官方 GitHub releases 下载

## 参考文档

- [Psiphon Tunnel Core](https://github.com/Psiphon-Labs/psiphon-tunnel-core)
- [Psiphon Binaries](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries)
- [Xray-core (XTLS)](https://github.com/XTLS/Xray-core)
- [Hysteria2](https://v2.hysteria.network/)
- [TUIC](https://github.com/EAimTY/tuic)

## License

MIT
