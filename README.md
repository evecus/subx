# Subx

支持订阅管理、节点解析/转换、组合订阅、令牌分享、账号密码登录。

## 功能

- **订阅管理**：远程 URL / 本地内容、自定义 UA、cron 定时刷新、缓存快照、手工更新、节点预览。
- **组合订阅**：按顺序聚合多个订阅，各自应用自己的操作符后再应用集合操作符。
- **节点解析**：SS / SSR / VMess / VLESS / Trojan / Hysteria / Hysteria2 / TUIC / WireGuard / AnyTLS / SOCKS5 / HTTP 的 URI，Clash/Mihomo YAML、Surge / Loon / Quantumult X 行、SSD、Base64 订阅、FullConfig 段。
- **产出格式**：`mihomo`、`clash`、`stash`、`surge`、`surge-mac`、`surfboard`、`loon`、`shadowrocket`、`qx`、`sing-box`、`v2ray`、`egern`、`json`、`uri`（含别名 `meta` / `clashmeta` / `clash.meta` / `surgemac` / `singbox` / `v2`）。
- **操作符**：Useless / Region / Regex / Type / Conditional 过滤，Quick Setting / Flag / Sort / Regex Sort / Regex Rename / Regex Delete / Handle Duplicate / Resolve Domain / Add Proxies From Subscription。
- **分享**：时间限制 / 次数限制 / 永久令牌，`sub` / `col` / `file` 三类公开链接，支持 `?preview=1` 纯文本预览。
- **安全**：JWT 登录、常量时间凭据比较、登录 10 次/15 分钟与公开下载 120 次/分钟的 per-IP 限流、`Retry-After`、基础安全响应头、`base_path` 隐藏面板。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | `0.0.0.0` | 监听地址 |
| `port` | `3000` | 监听端口 |
| `base_path` | 空 | 面板的私密 URL 前缀，如 `/mypanel`；设置后根路径返回 404 |
| `data_dir` | `./data` | 数据目录（SQLite + JWT secret） |
| `jwt_secret` | 自动生成 | 未设置时生成随机值并持久化到 `$data_dir/jwt_secret` |
| `token_ttl_hours` | `168` | JWT 有效期（小时） |
| `auth` | `admin:admin` | 管理员账号密码，格式 `用户名:密码` |
| `user` / `password` | `admin` / `admin` | 分别设置账号与密码（仅当 `auth` 未设置时生效） |

> 管理员账号不入库，每次启动都从环境变量读取；修改凭据只需用新值重启。使用默认凭据时启动会打印警告。

## 构建与运行

前端产物已经预构建在 `web/dist/` 并会在编译时嵌入二进制，直接编译即可：

```sh
cargo build --release
user=admin password=secret ./target/release/subx
```

如果需要重新构建前端：

```sh
cd web && npm ci && npm run build && cd ..
cargo build --release
```

> `rust-embed` 在编译期读取 `web/dist`，因此该目录必须存在（仓库中已附带构建好的产物）。

隐藏面板：

```sh
user=admin password=secret base_path=/mypanel ./target/release/subx
# 面板: http://host:3000/mypanel/   根路径: 404
```

## Docker

```sh
docker build -t subx .
docker run -p 3000:3000 \
  -e auth=myuser:strongpass \
  -e base_path=/mypanel \
  -v subx-data:/app/data \
  subx
```

## API

需要 `Authorization: Bearer <jwt>`：

- `POST /api/login` → `{token, username}`
- `GET /api/me`
- `GET|POST /api/subs`、`GET|PATCH|DELETE /api/sub/:name`、`POST /api/sub/:name/update`
- `GET|POST /api/collections`、`GET|PATCH|DELETE /api/col/:name`
- `GET|POST /api/files`、`GET|PATCH|DELETE /api/file/:name`
- `GET /api/node-info/:name`、`GET /api/targets`
- `GET /api/tokens`、`POST /api/token`、`DELETE /api/token/:token`
- `GET|PATCH /api/settings`

公开（Bearer 或 `?token=`）：

- `GET /download/:name?target=mihomo`
- `GET /api/file/:name/raw?token=...`
- `GET /share/sub/:name?token=...&target=...`
- `GET /share/col/:name?token=...&target=...`
- `GET /share/file/:name?token=...`

所有路由在设置 `base_path` 时自动挂到该前缀下。
