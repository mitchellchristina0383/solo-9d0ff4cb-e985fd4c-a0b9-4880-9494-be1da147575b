# 受控出口代理 · Controlled Egress Proxy

一个只允许经**受控 HTTP CONNECT 代理**访问指定目标的网页应用。管理员在网页上配置
允许的域名 / 端口 / IPv4 网段，代理解析域名后**必须用通过校验的同一地址拨号**；不
合规的请求在连接目标之前就被拒绝。每次建连都按**一版已提交规则**判断，规则变更与
建连交错时互不影响；隧道支持双向半关闭，单侧关闭后另一方向的数据仍会送完。

技术栈：Python 3.11+、asyncio、FastAPI、SQLite（aiosqlite）、Docker Compose。

---

## 快速开始

### Docker Compose

```bash
docker compose up --build
```

- Web 界面：<http://127.0.0.1:8000>
- CONNECT 代理：`127.0.0.1:3128`
- 容器内演示服务：`demo:8080`（不对外发布端口）
- 数据库：命名卷 `proxy-data` 中的 `/srv/data/proxy.db`

首次启动会写入一条引导规则 `demo:8080 ∈ 172.30.0.0/24`，因此打开网页点击「试连」
即可看到经代理建立隧道并取回演示服务页面的完整过程。若不需要，可在网页上删除后
提交新版本。

### 本地运行（不使用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# 另开一个终端运行演示服务
python -m uvicorn demo.demo_app:app --host 127.0.0.1 --port 8080
# 启动代理 + 网页
DEMO_HOST=127.0.0.1 DEMO_PORT=8080 DEMO_CIDR=127.0.0.0/8 \
  python -m app.main
```

可用环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `PROXY_HOST` / `PROXY_PORT` | `0.0.0.0` / `3128` | CONNECT 监听地址 |
| `WEB_HOST` / `WEB_PORT` | `0.0.0.0` / `8000` | 网页监听地址 |
| `APP_DB_PATH` | `data/proxy.db` | SQLite 文件 |
| `DEMO_HOST` / `DEMO_PORT` / `DEMO_CIDR` | `127.0.0.1` / `8080` / `127.0.0.0/8` | 试连目标与首条引导规则 |
| `BOOTSTRAP_RULES_JSON` | 空 | 覆盖引导规则（JSON 数组，仅首次建库时生效） |
| `DNS_TIMEOUT` | `3.0` | 域名解析超时（秒） |
| `CONNECT_TIMEOUT` | `5.0` | 连接目标超时（秒） |
| `HEADER_TIMEOUT` | `5.0` | 读取 CONNECT 请求头的超时 |
| `IDLE_TIMEOUT` | `120.0` | 隧道双向均无流量多久后释放 |
| `MAX_HEADER_BYTES` | `8192` | 请求头上限 |

示例——让代理把 `api.example.com:443` 限制在 `10.20.0.0/16`：

```bash
curl -X PUT http://127.0.0.1:8000/api/rules \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"host":"api.example.com","ports":[443],"networks":["10.20.0.0/16"],"description":"prod api"}],"note":"init"}'
```

客户端使用：

```bash
curl -x http://127.0.0.1:3128 https://api.example.com/   # curl 自动发 CONNECT
```

---

## 规则模型

每条规则有三个维度，**必须同时满足**才放行：

```json
{
  "host": "*.example.com",          // 精确域名、*.example.com 通配、或 IPv4 字面量
  "ports": [443, 8443],
  "networks": ["10.20.0.0/16"],     // IPv4 CIDR，可多条
  "description": "可读备注"
}
```

- `host` 通配只支持 `*.example.com` 形式，且**不**匹配裸域 `example.com`。
- 只支持 IPv4；IPv6 目标、IPv6 网段一律拒绝（解析结果里出现非 IPv4 地址也会拒绝）。
- 规则之间不会合并：**同一条规则**必须覆盖目标主机、端口和解析出的全部地址。这样
  多地址 DNS 应答里夹带一个越权地址时，整条连接会被拒绝，而不是被拆分到不同规则里。
- 提交前整体校验。任何一条不合法，整个提交被拒绝（HTTP 422），**不会发生部分生效**。

### 版本化与并发语义

- 每次 `PUT /api/rules` 都在一个 `BEGIN IMMEDIATE` 事务里追加一个新版本
  （`rule_revisions` 表，只增不改）。
- 代理处理每个 CONNECT 时，用单独只读连接执行**一条** `SELECT ... ORDER BY revision
  DESC LIMIT 1`，得到一个不可变的 `RuleSetSnapshot`，之后解析、拨号、准入全用它。
- 因此：规则提交与建连可以任意交错，每条连接只对应一个版本；提交之后的规则变更
  **不会**影响已经建立的隧道，也不会回头重判隧道里的字节。
- 准入记录里写着 `revision`，审计时可以还原“这条连接当时按哪版规则放行/拒绝”。

---

## 地址钉扎（不二次解析）

这是安全上最关键的一条：

1. 每个 CONNECT 只解析一次域名（`getaddrinfo(AF_INET)`），得到一组 IPv4 字面量。
2. 规则快照对这组地址做准入判断；**任一**地址越权即拒绝，且在拨号前拒绝。
3. 拨号器 `PinnedDialer` 只接受 IPv4 字面量：它用 `socket.AI_NUMERICHOST` 调
   `getaddrinfo`（明确禁止解析名字），再用 `sock_connect` 连接到该字面量地址。
4. 因此不存在“校验 A 地址、连接 B 地址”的窗口：解析结果与拨号目标是同一组字面量。
5. 若目标主机没有匹配的规则，连 DNS 都不会触发（直接 403）。

测试 `tests/test_dialer.py`、`tests/test_proxy.py` 覆盖：第二次解析结果变化不影响本次拨号、
拨号器拒绝域名、多地址部分越权被拒、拒绝时目标从未被连接。

---

## 隧道与半关闭

- 连接建立后维持两条独立的数据泵：客户端→目标、目标→客户端。
- 某一侧 `read` 到 EOF（半关闭）时，代理把 EOF **传递**给另一侧
  （`write_eof`），并继续把反方向的数据泵完，**不**立即拆连接。
- 只有两方向都结束后才释放连接；关闭原因记录为 `both_closed` / `client_closed` /
  `target_closed`。
- 双向都空闲超过 `IDLE_TIMEOUT` 时，看门狗中止传输并记为 `idle_timeout`。
- 错误、客户端重置、进程关闭都会走同一套收尾逻辑，把字节数与关闭原因写回准入记录。

已用真实进程验证（见下文「验证」）：客户端只发不收、目标只发不收两种半关闭都把
另一方向的数据完整送达；空闲隧道在约 `IDLE_TIMEOUT` 后释放。

---

## 网页界面

单页（`app/static/index.html`，无外部依赖）：

- **允许规则**：编辑 JSON、校验、提交为新版本；错误逐条显示。
- **试连演示服务**：经代理 CONNECT 演示服务，显示代理应答与服务响应；成功/失败都有结论。
- **准入记录**：按结果筛选、关键字搜索、分页，显示时间、目标、解析地址、规则版本、
  命中规则、拨号地址、隧道状态、上下行字节、关闭原因。
- **规则版本历史**：可把任一历史版本载入编辑器（提交后才会生效）。
- **运行配置**与健康状态。

HTTP API 见 `/api/docs`。

---

## 项目结构

```
app/
  config.py       环境变量 → Settings
  rules.py        规则校验、规范化、不可变规则快照与准入判断
  storage.py      SQLite：版本化规则 + 准入记录（读写连接分离，WAL）
  proxy.py        CONNECT 代理：解析一次、地址钉扎拨号、隧道与半关闭
  probe.py        网页「试连」：自己发 CONNECT 并请求演示服务
  web.py          FastAPI 路由、请求体上限、页面
  static/index.html  单页界面
  main.py         进程入口（代理在 FastAPI 生命周期内启动）
demo/demo_app.py  容器内演示服务
tests/            规则、代理、拨号、端到端测试
```

---

## 验证

```bash
pip install -r requirements.txt pytest pytest-asyncio httpx
PYTHONPATH=. python -m pytest -q
```

测试覆盖：

- **规则**：三维度必须同时满足、通配语义、多地址部分越权、端口按规则隔离、非法输入全集。
- **地址**：解析只调用一次；解析结果变化不改变拨号；拨号器用 `AI_NUMERICHOST`；拒绝时目标零连接。
- **交错**：撤销/恢复规则的同时并发建连，既有隧道继续传输、新连接按新版本判定；
  连接在解析中途规则被撤销时仍按其已读取的版本放行。
- **断开**：客户端半关闭、目标半关闭、空闲超时、进程关闭、50 路并发隧道。
- **端到端**：真实 uvicorn + 真实上游 HTTP 服务，覆盖网页、试连、规则原子提交、413 上限。

本次实现后实际执行结果：**55 个测试全部通过**。另外用真实进程手工验证了：
试连成功/被拒、半关闭双向送达、空闲隧道约 2 秒释放、规则多次翻转时既有隧道不受影响。

---

## 已知限制 / 未完成

- 目前只做 **HTTP CONNECT**（即可承载任意 TCP，包括 TLS），**没有**实现代理认证、
  基于用户的配额或速率限制。
- 没有实现 TLS 中间人解密（不检查隧道内内容），因此准入粒度是“主机 + 端口 + 地址”，
  不是 URL。
- DNS 只取 IPv4（`AF_INET`），**不支持 IPv6**；这是刻意的限制。
- 规则的“任一地址越权即拒绝”策略偏严格：对返回多 A 记录且跨网段的域名，需要把这些
  网段放进**同一条**规则。这是有意的安全取舍。
- 运行期无热加载配置文件：规则只能经网页/API 提交并立即生效于新连接。
- 演示服务的 `GET /slow` 是流式响应：若客户端在请求后立即半关闭写方向，Uvicorn/Starlette
  的流式响应会把这次半关闭当作断开而不写正文（直连演示服务也是同样行为，与代理无关）。
  代理侧半关闭语义由独立的上游测试服务验证，见 `tests/test_proxy.py`。
- 本环境**没有 Docker daemon**，`docker compose up` 未在本机实际跑过；
  Dockerfile 与 compose 已按最小镜像编写并做了静态校验，请在目标机器上首次启动时确认。
- 未做压力测试与长期稳定性测试；并发测试规模为 50 条隧道。
- SQLite 使用单写连接（写操作串行化）。对当前规模足够；若需要更高写入吞吐，应换
  PostgreSQL 或引入写队列。
