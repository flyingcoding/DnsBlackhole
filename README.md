# DnsBlackhole

DnsBlackhole 是一个面向个人电脑和家庭/小型网络的 DNS 转发与过滤工具，使用 Rust、TypeScript 和 Tauri 2 构建。

[下载最新版](https://github.com/wanwan-doudou/DnsBlackhole/releases/latest) · [发布记录](https://github.com/wanwan-doudou/DnsBlackhole/releases) · [MIT License](LICENSE)

它可以覆盖两种范围，范围取决于谁把 DNS 指向它，而不是取决于安装包属于哪个操作系统：

- **保护一台设备**：接管本机 DNS，或在这台设备上手工填写 DnsBlackhole 的地址。
- **保护多台设备或整个局域网**：让路由器/DHCP 下发 DnsBlackhole 的地址，或在各设备上手工填写。

Windows、macOS 或 Linux 主机只要长期在线、允许局域网访问并被其它设备选作 DNS，都可以服务整个局域网。不同发布物的主要区别是安装、管理和系统集成方式；它们共用同一套 DNS 内核，包括远程黑名单、自定义规则、DNS 重写、加密上游、缓存、查询日志、统计和客户端访问控制。

## 选择发布物

| 发布物 | 适合场景 | 运行要求 | 当前验证范围 |
| --- | --- | --- | --- |
| Windows NSIS/MSI（x64） | 本机使用或常开电脑上的局域网 DNS | Windows x64 | Windows CI、Windows 11 x64 |
| macOS Universal DMG | 本机使用或常开电脑上的局域网 DNS | Apple 芯片或 Intel Mac | Universal 构建、实机安装/升级与后台服务 |
| Linux 容器 | 本机或局域网使用；适合 NAS、小主机和服务器 | amd64 Linux + Docker | Ubuntu 26.04 amd64；镜像基底为 Debian bookworm |
| Ubuntu Server DEB（amd64） | 宿主直装；本机或局域网使用 | Ubuntu 26.04 amd64 + systemd | Ubuntu 26.04 amd64 |

## 快速开始

### Windows / macOS 桌面版

1. 打开 [最新 Release](https://github.com/wanwan-doudou/DnsBlackhole/releases/latest)。
2. Windows 下载 `DnsBlackhole_<版本>_x64-setup.exe`；需要企业部署时可使用 MSI。
3. macOS 下载 Universal DMG，将应用拖入“应用程序”。
4. 启动应用并安装后台 DNS 服务。
5. 在“DNS 黑名单”更新已启用的远程清单。
6. 在“设置”中接管本机 DNS。

Windows 和 macOS 桌面版也能为局域网设备提供 DNS：让后台服务监听局域网地址，按系统要求允许实际 DNS 端口的 UDP/TCP 入站流量，再把路由器或设备的 DNS 指向这台电脑。Windows 当前不会自动创建防火墙规则。若电脑本来就常年在线，可以直接承担局域网 DNS；NAS、小主机或服务器场景通常更适合 Linux 容器或 Server DEB。

### Linux 容器（推荐）

下面的方式不需要 clone 仓库，并在第一次启动前通过 Docker secret 设置管理密码。

先在 `compose.yaml` 同目录创建 `dnsblackhole-admin-password.txt`，内容为至少 8 个字符的管理密码。Compose 的本地 secret 会保留宿主文件的属主和权限，因此要让镜像内固定的 UID 10001 独占读取：

```bash
sudo chown 10001:10001 dnsblackhole-admin-password.txt
sudo chmod 400 dnsblackhole-admin-password.txt
```

然后保存以下 `compose.yaml`：

```yaml
name: dnsblackhole

services:
  dnsblackhole:
    # 生产环境建议改成 Release 页中的具体版本标签
    image: ghcr.io/wanwan-doudou/dnsblackhole:latest
    restart: unless-stopped
    environment:
      DNSBLACKHOLE_CONTAINER: "1"
    command:
      - serve
      - --data-dir
      - /var/lib/dnsblackhole
      - --web-listen
      - 0.0.0.0:3000
      - --admin-password-file
      - /run/secrets/dnsblackhole_admin_password
    ports:
      - "0.0.0.0:53:53/udp"
      - "0.0.0.0:53:53/tcp"
      - "0.0.0.0:3000:3000/tcp"
    volumes:
      - dnsblackhole-data:/var/lib/dnsblackhole
    secrets:
      - dnsblackhole_admin_password
    tmpfs:
      - /run/dnsblackhole:mode=0755,uid=10001,gid=10001
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    stop_grace_period: 20s

volumes:
  dnsblackhole-data:

secrets:
  dnsblackhole_admin_password:
    file: ./dnsblackhole-admin-password.txt
```

启动并查看状态：

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs dnsblackhole
```

浏览器打开 `http://<宿主地址>:3000`，使用预设密码登录。数据卷里已有密码时，密码文件不会覆盖它；密码文件无效时 DNS 会继续运行，但 Web 管理不会启动，修正文件后重启容器即可。

生产环境应把镜像固定到具体版本，并把三个端口的 `0.0.0.0` 换成实际需要监听的宿主地址。host network、IPv6、升级、反向代理、首次配置和数据持久化见 [Docker 部署文档](docs/deployment/docker.md)。

### Ubuntu Server DEB

从 Release 下载 amd64 Server 包。安装前先创建仅 root 可读的首启密码文件，避免服务启动到首次设置状态后被局域网内其它设备抢先设置：

```bash
sudo install -d -m 700 /etc/dnsblackhole
read -rsp "DnsBlackhole 管理密码：" dnsblackhole_admin_password
echo
printf '%s\n' "$dnsblackhole_admin_password" \
  | sudo tee /etc/dnsblackhole/admin-password >/dev/null
unset dnsblackhole_admin_password
sudo chmod 600 /etc/dnsblackhole/admin-password
sudo dpkg -i dnsblackhole-server_<版本>_amd64.deb
```

服务会自动启用并启动，Web 管理地址默认为 `http://<主机地址>:3000`。确认能够使用预设密码登录后，可以删除首启文件；密码已经保存在独立凭据表中：

```bash
sudo rm /etc/dnsblackhole/admin-password
```

如果安装时没有提供有效密码文件，DNS 仍会运行，但 Web 管理不会监听。此时可从本机设置密码并重启服务：

```bash
sudo dnsblackhole-cli web-auth set-password
sudo systemctl restart dnsblackhole
```

安装不会自动接管宿主 DNS；需要时在后台操作，或使用本机 CLI：

```bash
sudo dnsblackhole-cli system-dns takeover
sudo dnsblackhole-cli system-dns status
sudo dnsblackhole-cli system-dns restore
```

Ubuntu 默认的 `systemd-resolved` stub 通常会先占用回环地址的 53 端口。首次安装后、尚未接管系统 DNS 时，systemd 服务与 Web 管理可以正常运行，但默认的 `0.0.0.0:53` DNS 监听会显示端口被占用；执行上面的 `takeover` 后会关闭 stub 监听并启动 DNS。若只想服务局域网而不接管宿主，请先在 Web 后台把监听地址收窄为主机的局域网 IP，再启动 DNS。

忘记 Web 管理密码时：

```bash
sudo dnsblackhole-cli web-auth status
sudo dnsblackhole-cli web-auth reset
```

查看服务日志：

```bash
sudo journalctl -u dnsblackhole -f
```

## 主要能力

### DNS 上游

- 支持普通 UDP DNS、DoH、DoT 和 DoQ。
- 支持独立的 Fallback 与 Bootstrap DNS。
- 可按查询域名或客户端 IP/CIDR 选择上游。
- 支持负载均衡、并行请求和“最快的 IP 地址”模式。
- 可请求上游执行 DNSSEC 验证，并检查 AD/SERVFAIL 结果。

常见上游格式：

| 类型 | 示例 |
| --- | --- |
| UDP DNS | `223.5.5.5`、`[2400:3200::1]:53` |
| DoH | `https://dns.alidns.com/dns-query` |
| DoT | `tls://dns.example.com:853` |
| DoQ | `quic://dns.example.com:853` |

Bootstrap DNS 只接受 IP 或 `IP:端口`，避免解析上游主机名时形成依赖循环。

### 过滤与重写

- 管理远程过滤清单，并在更新失败时保留上一份有效缓存。
- 支持本地黑名单、allowlist、`important`、`badfilter`、DNS 类型限制和 `denyallow`。
- 支持 A、AAAA、CNAME、TXT、MX、SRV、PTR 和 RCODE 类型的 DNS 重写。
- 支持零地址、NXDOMAIN、REFUSED 和自定义 IP 拦截响应。
- 可选把系统 hosts 文件并入重写表。
- 规则和重写保存后热更新，不需要重启 DNS 服务。

### 查询与客户端

- 查询日志支持筛选、排序、稳定游标分页、保存视图和导出。
- 仪表盘提供趋势、拦截率、域名、客户端、过滤器、上游和缓存统计。
- 支持客户端名称映射、客户端策略组、周期计划和常用服务分类拦截。
- 支持允许/拒绝客户端列表、每客户端限速和客户端 IP 匿名化。
- 查询日志、统计数据库和过滤器缓存可迁移到自定义目录。

### 安全与运行维护

- Linux Web 管理使用独立密码、内存会话和登录失败限速。
- DNS Rebinding Protection 与 CNAME cloaking 检测默认启用。
- 私有地址反查默认在本地返回 NXDOMAIN，避免把内网地址泄漏给公共 DNS。
- 远程清单和 DoH 默认只允许 HTTPS；HTTP 需要显式开启。
- 支持健康检查、异常恢复、只读 REST 状态和 Prometheus 指标。
- 容器以固定非 root 用户运行，根文件系统可保持只读，不需要 `privileged` 或 `NET_ADMIN`。

## 默认边界

DnsBlackhole 默认监听 `0.0.0.0:53` 和 `[::]:53`，并允许回环、私有 IPv4、ULA IPv6 与链路本地 IPv6 客户端。这适合可信家庭网络，但不代表可以暴露到公网。

- 只保护当前机器时，把 IPv4 监听地址改为 `127.0.0.1`，IPv6 改为 `::1` 或关闭。
- 服务局域网时，限制宿主防火墙、管理端口和允许客户端网段。
- Web 管理密码不能替代 HTTPS。跨越不可信网络时应使用可信反向代理或 VPN。
- DnsBlackhole 是 DNS 转发器，不是权威 DNS，也不在本地完成完整 DNSSEC 信任链验证。
- 容器不会修改宿主的 `/etc/resolv.conf`、systemd-resolved 或 NetworkManager。

## 规则语法

当前支持常见 AdGuard Home 规则子集：

| 写法 | 行为 |
| --- | --- |
| `||example.org^` | 拦截域名及其子域名 |
| `@@||example.org^` | 放行域名及其子域名 |
| `0.0.0.0 example.org` | hosts 风格黑名单 |
| `*.example.org` | 拦截域名及其子域名 |
| `example.org` | 只拦截当前域名 |
| `$important` | 提高规则优先级 |
| `$badfilter` | 禁用完全匹配的目标规则 |
| `$dnstype=A|AAAA` | 限制 DNS 查询类型 |
| `$denyallow=safe.example.org` | 从父域匹配中排除指定域名 |
| `$dnsrewrite=1.2.3.4` | 返回指定重写结果 |
| `$dnsrewrite=NOERROR;TXT;hello` | 使用完整 DNS 重写格式 |

正则表达式和未知高级修饰符暂不支持，会被忽略并计入规则分析统计。

## 测试 DNS

不修改系统 DNS 时，可以直接查询本机监听地址：

```powershell
nslookup -port=53 example.com 127.0.0.1
```

```bash
dig @127.0.0.1 -p 53 example.com
```

从其它设备测试时，把 `127.0.0.1` 换成运行 DnsBlackhole 的主机地址。局域网查询超时而本机正常，通常说明宿主防火墙、端口映射或网络配置阻止了入站流量。

## 本地开发

需要 Node.js、pnpm、Rust 工具链和 Tauri 2 对应的系统依赖。

```bash
pnpm install
pnpm tauri:dev
```

常用检查：

```bash
pnpm test
pnpm build
cargo test --manifest-path src-tauri/Cargo.toml
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
```

DNS 热路径基准：

```bash
cargo bench --manifest-path src-tauri/Cargo.toml --features bench --bench dns_hot_path
```

## License

本项目采用 [MIT License](LICENSE)。
