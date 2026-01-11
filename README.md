# sb-psiphon-egress

**sing-box 三协议入站 + 赛风(Psiphon)出站** 一键部署脚本

## 功能概述

这套脚本在一台 Linux VPS 上部署：

- **入站协议**：VLESS + REALITY、Hysteria2、TUIC v5（同机共存）
- **出站链路**：warp-plus 的 Psiphon 模式提供本机 SOCKS5，sing-box 用 socks 出站把 TCP 流量"落地"到 Psiphon
- **管理功能**：国家选择（重启 warp-plus 切换国家）、国家可用性测试（逐个国家验证出口归属）

```
┌─────────────────────────────────────────────────────────────┐
│                         客户端                              │
│   (VLESS/Reality, Hysteria2, TUIC v5)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      VPS (sing-box)                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  入站: VLESS+Reality(:443) HY2(:8443) TUIC(:2053)   │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                            │                                │
│            ┌───────────────┴───────────────┐               │
│            │         路由策略               │               │
│            │   TCP → psiphon (SOCKS5)      │               │
│            │   UDP → direct                │               │
│            └───────────────┬───────────────┘               │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐   │
│  │      warp-plus (Psiphon模式)                        │   │
│  │      SOCKS5 127.0.0.1:1081                          │   │
│  │      --cfon --country US                            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                    目标网站 (落地IP: Psiphon节点)
```

## 适用系统

- **发行版**：Debian / Ubuntu / Rocky / Alma / CentOS（需 systemd）
- **架构**：amd64 / arm64

## 快速开始

### 一键安装

```bash
sudo -i
git clone https://github.com/hxzlplp7/sb-psiphon.git
cd sb-psiphon
chmod +x install.sh proxyctl uninstall.sh
bash install.sh
```

### 安装过程中的配置项

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| HOST | 客户端连接的域名或IP | example.com |
| VLESS端口 | VLESS+REALITY (TCP) | 443 |
| HY2端口 | Hysteria2 (UDP) | 8443 |
| TUIC端口 | TUIC v5 (UDP) | 2053 |
| REALITY伪装站点 | 需支持TLS1.3/H2 | www.microsoft.com |
| TLS证书模式 | `self`(自签) / `le`(Let's Encrypt) | self |
| Psiphon国家 | 两位国家代码 | US |
| SOCKS5端口 | warp-plus 本地端口 | 1081 |

## 管理命令

安装完成后，`proxyctl` 命令会自动安装到 `/usr/local/bin/`：

```bash
# 查看服务状态
proxyctl status

# 切换 Psiphon 出站国家
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
proxyctl logs          # 同时查看两个服务
proxyctl logs sb       # 只看 sing-box
proxyctl logs wp       # 只看 warp-plus
```

## 配置文件位置

| 文件 | 路径 |
|------|------|
| sing-box 配置 | `/etc/sing-box/config.json` |
| warp-plus 环境变量 | `/etc/warp-plus/warp-plus.env` |
| warp-plus 服务 | `/etc/systemd/system/warp-plus.service` |
| 自签证书 | `/etc/ssl/sbox/` |
| LE证书 | `/etc/letsencrypt/live/<domain>/` |

## 客户端配置示例

### VLESS + REALITY

```
地址: <你的HOST>
端口: 443 (TCP)
UUID: <安装时生成>
Flow: xtls-rprx-vision
SNI: www.microsoft.com
Reality PublicKey: <安装时显示>
Reality ShortID: <安装时显示>
指纹: chrome
```

**分享链接格式**：
```
vless://<UUID>@<HOST>:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=<PublicKey>&sid=<ShortID>&type=tcp&flow=xtls-rprx-vision#vless-reality
```

### Hysteria2

```
地址: <你的HOST>
端口: 8443 (UDP)
密码: <安装时生成>
OBFS: salamander
OBFS密码: <安装时生成>
ALPN: h3
SNI: <你的HOST>
（自签证书需要 skip-cert-verify / insecure=true）
```

### TUIC v5

```
地址: <你的HOST>
端口: 2053 (UDP)
UUID: <安装时生成>
密码: <安装时生成>
ALPN: h3
Congestion: bbr
（自签证书需要 skip-cert-verify / insecure=true）
```

## 关于 UDP 流量

**默认路由策略**：
- TCP → psiphon SOCKS5
- UDP → direct

**原因**：很多 SOCKS5 实现对 UDP 转发（UDP Associate）支持不一致，强行全量 UDP 可能导致 DNS/游戏/QUIC 出问题。

如需 UDP 也走 Psiphon，可手动修改 `/etc/sing-box/config.json`：

```json
"route": {
  "rules": [],
  "final": "psiphon"
}
```

## 常见问题

### Q: Let's Encrypt 申请失败？

A: 确保：
1. 域名正确解析到本机 IP
2. 80 端口未被占用（nginx/apache 等需先停止）
3. 域名未超过 LE 的频率限制

### Q: warp-plus 连接失败？

A: 
1. 检查国家是否支持：`proxyctl country-test US JP SG`
2. 查看日志：`proxyctl logs wp`
3. 某些 VPS 可能屏蔽了 Cloudflare WARP 的连接

### Q: 客户端连接超时？

A:
1. 检查防火墙：`ufw status`
2. 确认端口开放：`ss -tlnp | grep sing-box`
3. 检查 sing-box 状态：`proxyctl status`

## 卸载

```bash
sudo -i
bash uninstall.sh
```

## 参考文档

- [sing-box 官方文档](https://sing-box.sagernet.org/)
- [warp-plus (bepass-org)](https://github.com/bepass-org/warp-plus)
- [Hysteria2 协议](https://v2.hysteria.network/)
- [TUIC 协议](https://github.com/EAimTY/tuic)

## License

MIT
