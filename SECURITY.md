# 安全策略 / Security Policy

## 报告漏洞 / Reporting a Vulnerability

**请不要用公开 issue 报告安全漏洞。** 公开 issue 会在补丁发布前把细节暴露给所有人。

请改用 GitHub 的私密通道：仓库 **Security → Report a vulnerability**（GitHub Private
Vulnerability Reporting）。

*Please do not open a public issue for security bugs.* Use GitHub's
**Security → Report a vulnerability** (Private Vulnerability Reporting) instead.

报告请尽量包含：受影响的版本或 commit、复现步骤、影响面（能读到什么／能伪造什么／能让谁收不到警报）。

响应目标（尽力而为的开源项目，非商业 SLA）：

| 阶段 | 目标 |
|---|---|
| 收到确认 | 3 个工作日内 |
| 初步定性 | 10 个工作日内 |
| 修复或缓解方案 | 视严重程度，高危优先 |

## 受支持的版本 / Supported Versions

本项目尚未发布带版本号的稳定版。**只有 `main` 分支接受安全修复**；请始终基于最新 `main` 部署。

## 威胁模型要点 / Threat Model

理解这些边界有助于判断某个行为是不是漏洞：

- **接收设备被视为可能已被攻陷。** 因此告警用 **Ed25519 非对称签名**——客户端只能验签、永远不能签发。任何让**客户端**得以伪造或篡改告警／心跳的问题都是高危漏洞。
- **broker ACL 是纵深防御的第二道墙**：`client` 角色只能写自己的 `status/<deviceId>` 和 ack，**永远不能写 `alerts/*` 或 `system/*`**。绕过它属于漏洞。
- **心跳的 `health` 字段在签名覆盖内**：能把 `degraded` 改回 `ok` 而不使签名失效，属于高危（会消掉 fail-loud 告警）。
- **多租户隔离**：控制面（发布／历史／服务账号）按 `org_id` 隔离，Postgres 档另有 RLS 兜底。跨租户读写属于高危。
- **已知且已记录的边界，不必报告**（见 SPEC.md §0 / SPEC-SAFETY.md §11）：
  - **设备与广播面仍是单租户** —— `alerts/active`、`alerts/events` 是全局 topic，`GET /api/devices` 返回全局名册。这是已知架构缺口，不是漏洞。
  - 缺少外部 dead-man switch，服务器整体宕机时无第二方告警。
  - 浏览器客户端无法唤醒睡眠／锁屏设备（需原生端）。
  - `ALERTHUB_ADMIN_TOKEN` 的默认值 `dev-admin-token` 仅用于本地开发，README 已标注生产必改。

## 加固部署 / Hardening

生产部署请至少做到：

- 改掉 `ALERTHUB_ADMIN_TOKEN`、`ALERTHUB_MQTT_PW`、`ALERTHUB_CLIENT_PW` 的默认值。
- 用最小权限数据库角色连接 Postgres，使 RLS 真正生效（超级用户会绕过 RLS）——见 [docs/POSTGRES.md](docs/POSTGRES.md)。
- 通过 TLS 暴露 HTTP 与 MQTT/WS（反向代理或 MQTTS）；`/pubkey` 会下发浏览器客户端的 broker 口令。
- 用反向代理时，把它的地址告诉 `ALERTHUB_TRUSTED_PROXIES`（默认 `loopback`，即同机代理）。限流与审计都按客户端地址取值：代理不受信时所有请求看起来来自同一个地址，5 个凭证端点共享的限流器会塌成全站配额，反过来成为拒绝服务的杠杆。代理与服务不同机时**必须**显式填它的地址或网段。
- 备份并严格保护 `keys/`：Ed25519 私钥是签发告警的唯一凭据，JWT secret 与 KEK 也在其中。
- 保持依赖更新：CI 的 `vuln` job 会跑 `govulncheck` 与 `npm audit`。
