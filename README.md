# probe-dashboard

v2node 探测日志的分析面板。

> **必须与 [Miku-programm/v2node](https://github.com/Miku-programm/v2node) 配套使用。**
> 本项目自己不采集任何数据，只读取 v2node 的 ProbeLog 功能写入 ClickHouse 的 `probe_events` 表。
> 没有开启 ProbeLog 的 v2node 节点，面板里不会有任何数据。

## 配套关系

```
v2node 节点（开启 ProbeLog） ──写入──► ClickHouse: v2node.probe_events ──读取──► probe-dashboard ──► 浏览器
```

| 组件 | 仓库 | 职责 |
|---|---|---|
| 采集端 | [Miku-programm/v2node](https://github.com/Miku-programm/v2node)（`probelog/`） | 在节点上记录扫端口、主动探测、连接行为，写入 ClickHouse |
| 表结构 | [v2node/probelog/schema.sql](https://github.com/Miku-programm/v2node/blob/main/probelog/schema.sql) | 两者之间唯一的约定 |
| 面板 | 本仓库 | 只读 ClickHouse，展示和分析 |

两者是独立的程序，代码互不依赖，可以部署在不同机器上；但面板的查询是按 v2node 写入的表结构和字段含义编写的，不能用于其他数据源。升级时请保持两边版本对应：v2node 的表结构有变化时，面板需要同步更新。

## 版本对应

| probe-dashboard | v2node ProbeLog 表结构 |
|---|---|
| 当前版本 | `schema_version` 2（需要 `flow_id`、`revision`、`emitted_at`、`tls_state`、`auth_assoc` 等列） |

- 旧表（v2node 第一版 ProbeLog 建的表）先执行 v2node 的 [`probelog/migrations/002_v2.sql`](https://github.com/Miku-programm/v2node/blob/main/probelog/migrations/002_v2.sql)，否则查询会因缺列报错。
- 一个连接可能有多条记录（`snapshot` / `final` / `correction`），面板所有连接统计都先按 `flow_id` 取 `revision` 最大的一行再计数；v1 旧行没有 `flow_id`，每行单独计。
- “未关联认证”= `auth` 不是 `accepted` / `not_applicable`（包括 v2 的 `unknown`、`rejected` 和 v1 的 `none`）。它只表示没观察到认证成功，不等于主动探测，更不等于 GFW。
- SNI / JA4 只用 `tls_state = complete` 的行（v1 旧行按原样显示）。
- “相同客户端前缀”页用重组后的 `prefix_len:prefix_hash`，并排除重组冲突的连接；v1 旧行退回首段哈希。

## 使用步骤

1. 部署 ClickHouse，用 v2node 仓库的 [`probelog/schema.sql`](https://github.com/Miku-programm/v2node/blob/main/probelog/schema.sql) 建表，并按文件末尾示例创建写入账号和只读账号。
2. 在每个 v2node 节点的配置里开启 `ProbeLog` 并填写 ClickHouse 写入账号（见 [v2node/probelog/README.md](https://github.com/Miku-programm/v2node/blob/main/probelog/README.md)）。
3. 用只读账号运行本面板（见下文）。

## 特点

- 只有标准库依赖，单个二进制，前端（`static/`）用 `go:embed` 打包
- 浏览器只访问本服务；ClickHouse 账号只在服务端使用
- 只执行 `queries.go` 中预定义的查询，用户输入全部作为 ClickHouse 查询参数传入
- `-raw-sql` 打开后可在面板里执行只读 SQL

## 构建

```bash
go build -o probe-dashboard .
```

## 运行

```bash
CH_PASSWORD=... DASH_PASSWORD=... ./probe-dashboard \
  -listen 127.0.0.1:8088 \
  -ch-url http://127.0.0.1:8123 -ch-db v2node -ch-table probe_events \
  -ch-user v2node_reader \
  -auth-user admin
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-listen` | `127.0.0.1:8088` | 监听地址 |
| `-ch-url` | `http://127.0.0.1:8123` | ClickHouse HTTP 地址 |
| `-ch-db` / `-ch-table` | `v2node` / `probe_events` | 库名 / 表名 |
| `-ch-user` / `-ch-password` | `default` / 空 | ClickHouse 账号，建议用只读账号；密码也可用环境变量 `CH_PASSWORD` |
| `-auth-user` / `-auth-password` | 空 | 面板 Basic Auth；密码也可用环境变量 `DASH_PASSWORD`。不设置时任何能访问监听地址的人都能看数据 |
| `-raw-sql` | 关 | 允许在面板执行自定义只读 SQL |

对外开放时请放在 HTTPS 反向代理后面并设置 Basic Auth。前端从 jsdelivr 加载 ECharts。

## 页面

- **探测流量**：按来源聚合的未认证 TCP 流（“已认证=0”的来源最可疑）和每条流的明细
- **扫端口**：扫描源和扫描器 SYN 指纹
- **重放检测**：同一首包哈希出现在多个 IP 上
- **指纹聚类**：按 TTL / 窗口 / TCP 选项 / JA4 聚合探测器
- **长度与时机**：探测首包长度分布；探测距同端口上一次用户连接的时间
- **SNI / 端口 / 地区**、**UDP**、**Xray 日志**、**IP 查询**、**SQL**、**采集状态**
