# Docker 部署

Docker 镜像封装 Server 版 headless binary 和同一套内嵌 Web 管理后台。容器只运行一个固定 uid/gid `10001:10001` 的非 root 进程，不使用 `privileged` 或 `NET_ADMIN`。官方镜像发布在 `ghcr.io/wanwan-doudou/dnsblackhole`。

镜像基底是 `debian:bookworm-slim`，与宿主发行版无关：任意能跑 Docker 的 amd64 Linux 都可以部署。Ubuntu 26.04 amd64 是发布前的构建与验收基线，不是运行要求。

## 不用 clone 仓库的部署方式

先创建只保存在本机的管理密码文件：

```bash
read -rsp '管理密码（至少 8 个字符）: ' dbh_admin_password
printf '\n'
printf '%s\n' "${dbh_admin_password}" > dnsblackhole-admin-password.txt
unset dbh_admin_password
sudo chown 10001:10001 dnsblackhole-admin-password.txt
sudo chmod 400 dnsblackhole-admin-password.txt
```

Compose 在普通 Linux 上会把本地 secret 实现为只读 bind mount，文件的属主和权限不会自动改写。官方镜像固定以 `10001:10001` 运行，所以上述属主不能省略；如果仍是 `root:root 0600`，DNS 会正常运行，但 Web 管理会因无法读取首启密码而保持关闭。

这里的 `10001` 是镜像内专用账号的固定 UID/GID。密码首次写入数据卷后，后续启动不会再用文件覆盖它；仍建议保留这个受限文件，保证 `docker compose up` 替换容器时 secret 源文件存在。

再把下面这段存成同目录的 `compose.yaml`；它和 DnsBlackhole 的源码目录没有任何关系：

```yaml
name: dnsblackhole

services:
  dnsblackhole:
    # 试用用 latest；生产改成 Release 页上的具体版本号，例如 :0.2.6
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
    # 这个示例绑定全部网卡以便服务局域网；只供本机或固定网卡使用时，
    # 把下面的宿主地址收窄为 127.0.0.1 或实际局域网地址
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

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs dnsblackhole
```

把 `image:` 固定成具体版本号。`latest` 会随正式发布更新，只适合试用：生产环境用它会让一次 `docker compose pull` 变成一次未计划的升级。

宿主没有可用 IPv6 时上面的片段可以直接用；需要同时监听宿主 IPv6 地址时，改成 Compose 的长语法并为每个端口补一项 `host_ip`，仓库里的 `compose.yaml` 就是这种写法。

## 从仓库部署（源码构建回退）

仓库里的 `compose.yaml` 额外带 `build:` 上下文，供开发和自行构建使用。镜像引用由 `.env` 的两个变量拼成，不再硬编码版本：

```bash
git clone https://github.com/wanwan-doudou/DnsBlackhole.git
cd DnsBlackhole
docker compose pull
docker compose up -d --no-build
```

`.env` 里的 `DNSBLACKHOLE_VERSION` 是仓库 Compose 的默认容器版本，`DNSBLACKHOLE_IMAGE_REPO` 是镜像仓库。首次启动前仍需按上文创建 `dnsblackhole-admin-password.txt`。确实需要自行构建时，改成本地镜像名，避免覆盖官方镜像引用：

```bash
DNSBLACKHOLE_IMAGE_REPO=dnsblackhole DNSBLACKHOLE_VERSION=dev docker compose build --pull
DNSBLACKHOLE_IMAGE_REPO=dnsblackhole DNSBLACKHOLE_VERSION=dev docker compose up -d --no-build
```

自行构建且所在网络不能直连 Docker Hub 时，可在构建命令中通过 `NODE_IMAGE`、`RUST_IMAGE` 和 `RUNTIME_IMAGE` build arg 指向可信的 Docker Official Images 镜像仓库；正式 Dockerfile 默认仍使用 Docker Hub。

## bridge 模式

先确保宿主的 TCP/UDP 53 与 TCP 3000 可用，再执行 `docker compose up -d`。只想绑定指定地址时，把片段里的 `0.0.0.0` 换成具体地址；用仓库内的 `compose.yaml` 时，同一命令前设置 `DNSBLACKHOLE_BIND_ADDRESS` 和 `DNSBLACKHOLE_BIND_ADDRESS_V6`：

```bash
DNSBLACKHOLE_BIND_ADDRESS=192.168.1.10 \
DNSBLACKHOLE_BIND_ADDRESS_V6=fd00::10 \
docker compose up -d --no-build
```

宿主没有可用 IPv6 时，可删除仓库 Compose 中三个 `host_ip: "${DNSBLACKHOLE_BIND_ADDRESS_V6:-::}"` 端口项。

## Web 管理认证

按本文推荐的 Compose 启动后，浏览器打开 `http://<宿主地址>:3000`，使用密码文件中的管理密码登录。未登录时不能读取状态或修改配置。

如果没有提供 `--admin-password-file`，首次打开会进入设置密码页；未设置密码时除静态资源、认证接口与 `/health` 之外的管理接口一律拒绝。这个模式存在首次设置抢占窗口，只适合先把 3000 端口限制在可信来源的部署。

有了密码不等于可以裸奔到公网：管理端口只应向可信内网开放，跨越不可信网络仍然需要 HTTPS。

### 首启预设密码（Docker secret）

推荐 Compose 已使用下面这组配置。`--admin-password-file` 从挂载的文件读取首启密码，配合 Docker secret 使用；**不提供环境变量方式**，`docker inspect` 能看到环境变量。

```yaml
services:
  dnsblackhole:
    command:
      - serve
      - --data-dir
      - /var/lib/dnsblackhole
      - --web-listen
      - 0.0.0.0:3000
      - --admin-password-file
      - /run/secrets/dnsblackhole_admin_password
    secrets:
      - dnsblackhole_admin_password

secrets:
  dnsblackhole_admin_password:
    file: ./dnsblackhole-admin-password.txt
```

行为要点：

- **只在首启生效。** 数据卷里已经设置过密码时，这个参数被忽略并在日志里记录原因，不会覆盖现有密码。
- 密码文件内容就是密码本身，只去掉文件末尾的换行；密码本身的首尾空格会保留。使用本地 Compose secret 时，文件应保持 `10001:10001 0400`，使容器内的非 root 进程可以读取，同时避免对其它宿主用户开放。
- 读取失败（文件不存在、内容为空、长度不达标）**不会终止 DNS**，但 Web 管理不会监听，避免退回到可被抢占的首次设置状态。修正密码文件后重启容器即可恢复 Web 管理。

### 忘记密码

在宿主上用容器内的 CLI 重置，重置会清除密码与全部会话，下次打开回到首次设置页：

```bash
docker compose exec dnsblackhole dnsblackhole-service web-auth status
docker compose exec dnsblackhole dnsblackhole-service web-auth reset
```

### 已经在反向代理上做了 Basic Auth

那会出现两层认证（代理一层、应用一层）。两层都留着可以正常工作，但没必要：

- 保留应用内认证、去掉代理的 Basic Auth：推荐，应用侧的会话、限速与安全事件都还在。
- 保留代理的 Basic Auth、也仍然要设应用密码：应用密码不能跳过，因为容器的 3000 端口一旦被绕过代理直连就没有别的防线了。反向代理仍然负责 HTTPS。

反向代理终止 HTTPS 时，把 Cookie 的 `Secure` 属性打开（配置项在“安全防护”页的 Web 管理认证区块）。这里不无条件信任 `X-Forwarded-Proto`：那个头可以被伪造，所以由显式配置项控制，默认关闭。

## 首次配置

需要在新数据卷中应用一份导出的完整配置时，可以使用 `compose.init.yaml`：

```bash
# 从另一套 DnsBlackhole 导出的完整配置放到这里
cp /path/to/exported-config.json docker/bootstrap-config.json

docker compose pull
docker compose -f compose.yaml -f compose.init.yaml up -d --no-build
```

`bootstrap-config` 只在数据卷中尚无 SQLite 数据库时应用；已有数据库时只记录忽略原因，
不覆盖运行配置。不需要导入配置时直接使用基础 `compose.yaml`。导出的配置里不含管理密码与会话，
所以导入别处的配置不会带来别人的密码，仍然要单独设置。

## Linux host network 模式

host 模式通常更容易保留局域网客户端的真实源地址，但会直接占用宿主的 53 和 3000 端口：

```bash
docker compose -f compose.host.yaml pull
docker compose -f compose.host.yaml up -d --no-build
```

宿主原先若有 systemd-resolved stub 或其它 DNS 服务监听 53，必须先由管理员妥善释放。对于使用 systemd-resolved 的宿主，可由管理员关闭 stub listener，并让宿主继续读取 resolved 的非 stub 运行时结果：

```bash
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/disable-stub-for-dnsblackhole-container.conf
sudo ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

这属于宿主部署配置，不由容器自动执行。移除 host 模式后，应按宿主原先的 DNS 管理方式恢复该 drop-in 与 `/etc/resolv.conf`；DnsBlackhole 容器不会停用、修改或恢复这些宿主设置。

VPN/TUN 软件可能安装针对目标端口 53 的策略路由，从而在 bridge DNAT 之后、进入容器 bridge 之前截走 DNS 包。遇到“3000 可访问但 bridge 的 53 超时”时，应先检查宿主 `ip rule`；为对应 bridge 网段添加可信排除规则，或改用 host network，不能在容器里申请 `NET_ADMIN` 绕过宿主策略。

## 数据、健康检查与停止

- SQLite、配置与过滤器缓存保存在命名卷 `dnsblackhole-data`。
- `/run/dnsblackhole` 是带 uid/gid 的 tmpfs，只保存运行时 Unix socket。
- 根文件系统只读；镜像健康检查调用自身的 `healthcheck` 子命令，不依赖 curl 或 shell。
- `docker compose down` 删除容器但保留命名卷；只有显式加 `--volumes` 才会删除数据。
- 容器收到 SIGTERM 后会优雅停止 DNS runtime 并关闭数据库。容器从不声称能够恢复宿主 DNS；如果宿主或路由器已把 DNS 指向该容器，停止前应先把客户端 DNS 改回其它可用解析器。

查看状态与配置：

```bash
docker compose exec dnsblackhole dnsblackhole-service status --json
docker compose exec dnsblackhole dnsblackhole-service config export -
```

## 升级

先把客户端 DNS 临时切到其它可用解析器，再把 `image:` 的版本号改成新版本，拉取镜像并替换容器：

```bash
docker compose pull
docker compose up -d
docker compose ps
```

从仓库部署时改 `.env` 的 `DNSBLACKHOLE_VERSION`，并在 `up` 时加 `--no-build`。升级不需要 `git fetch --tags` 或 `git checkout`：容器版本由镜像标签决定，与本地源码是哪个 commit 无关。

Compose 会替换容器但继续挂载 `dnsblackhole-data`，配置、查询日志和统计数据会保留。确认 Web、DNS 查询和 healthcheck 正常后再把客户端 DNS 切回。不要使用 `docker compose down --volumes`，该命令会删除数据卷。

**从 v0.2.5 升级到 v0.2.6 时**：Web 管理后台开始要求管理密码。首次打开进入的是**设置密码页**，不是被锁在外面；已有配置、查询日志和统计都不受影响。想在开放端口之前就把密码定下来，用上文的 `--admin-password-file`。
