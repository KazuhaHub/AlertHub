# AlertHub HTTP API 参考

本文逐条对照 `server/internal/api/` 的实际路由表编写，覆盖当前注册的**全部 38 条路由**。

- 协议层（信封字段、规范化、Ed25519 签名、接受门、MQTT 拓扑）见 [SPEC.md](../SPEC.md)，那里才是**权威契约**；本文只描述 HTTP 表面。
- 存储/RLS 见 [docs/POSTGRES.md](POSTGRES.md)。

---

## 1. 通用约定

### 1.1 三种鉴权机制

三者都走 `Authorization: Bearer <…>` 这一个头，由中间件按前缀/内容区分：

| 机制 | 凭证 | 说明 |
|---|---|---|
| **会话 JWT** | `Bearer <access_token>`，或 `ah_access` Cookie | HS256。access 有效期 2 小时，refresh 7 天，2FA pending token 5 分钟。每个用户带一个 `TokenVersion` 计数器，递增即吊销该用户全部已签发 token。校验时还会重查用户是否 `enabled`。 |
| **静态管理 token** | `Bearer $ALERTHUB_ADMIN_TOKEN` | 给脚本/自动化用。常数时间比对，**绕过 RBAC 与组织成员检查**（等同超级管理员）。默认值 `dev-admin-token`，生产必改。 |
| **服务账号 API Key** | `Bearer ahk_<random>` | 机器调用。按 SHA-256 摘要查库，携带逗号分隔的 scope 列表（`*` 表示全部），并自带所属组织。**仅在 `scope:` 类端点上被识别**——发给其他端点时会被当成无效 JWT，返回 401。 |

下文用三种标记描述每条路由的门禁：

- **公开** — 无需任何凭证。
- **会话** — `requireRole(user)`：任意有效 JWT（用户须 enabled）或静态管理 token。判定用的是 `users.role`（全局角色）。
- **`perm:X`** — `requirePerm`：静态管理 token 与 `is_superadmin` 直接放行；否则调用者必须是**活动组织的成员**，且其**成员角色**（`memberships.base_role`）授予权限 X。
- **`scope:X`** — `requireScope`：带 scope X 的 `ahk_` key 放行；否则回退到 `requireRole(admin)`，即全局角色为 `admin` 的会话或静态管理 token。

> 注意两套角色的区别：**会话**类端点看的是用户的全局角色，**`perm:`** 类端点看的是用户在活动组织内的成员角色。

### 1.2 活动组织：`X-Org-Id`

所有涉及租户数据的端点先解析"活动组织"，优先级为：

1. 请求头 `X-Org-Id`（须能解析为 > 0 的整数）；
2. 服务账号 API Key 所属组织；
3. 默认组织（首次启动自动创建，slug = `default`）。

`perm:` 类端点会校验调用者在解析出的组织内确有成员关系，因此跨租户传 `X-Org-Id` 会得到 403。静态管理 token 与超级管理员跳过这一校验。

> 已知边界：`GET /api/devices` **不受活动组织约束**，返回的是全局设备在线名册——设备/广播平面目前仍是单租户。

### 1.3 RBAC 角色 → 权限

权限目录（`resource:action`）：`alert:publish`、`alert:cancel`、`alert:read`、`device:read`、`device:provision`、`sa:manage`、`member:manage`、`org:manage`、`settings:manage`。

| 角色 | 授予的权限 |
|---|---|
| `admin` / `owner` / `org_admin` | 全部 9 项 |
| `dispatcher` | `alert:publish`、`alert:cancel`、`alert:read`、`device:read` |
| `operator` | `alert:publish`、`alert:read`、`device:read`、`device:provision` |
| `viewer` / `user` | `alert:read`、`device:read` |

未列出的角色名不授予任何权限（fail-closed）。

### 1.4 速率限制

5 个凭证校验端点（`/api/auth/login`、`/api/auth/2fa/verify`、`/api/auth/passkey/login/finish`、`/api/auth/oidc/exchange`、`/api/auth/saml/acs`）共享一个**每 IP 10 次/分钟**的固定窗口限流器，超限返回 `429` + `Retry-After: 60`。

限流键是客户端地址。`X-Forwarded-For` **只在请求来自受信代理时才被采信**，由 `ALERTHUB_TRUSTED_PROXIES` 指定：

| 取值 | 含义 |
|---|---|
| `loopback`（默认） | 信任同机反向代理（`127.0.0.0/8`、`::1`） |
| `none` | 一律用 TCP 对端地址，完全忽略 `X-Forwarded-For` |
| `10.0.0.0/8,192.168.1.7` | 显式列出代理地址或网段 |

采信时从右往左遍历 `X-Forwarded-For`，取**第一个不属于受信代理**的地址——客户端自己写进去的值位于更左侧，遍历到不了那里。没有"信任全部"这个选项：那会让 `X-Forwarded-For` 完全由攻击者控制，等于给限流器发无限张门票。

这一点直接决定限流是否有效。设成 `none` 而又跑在反向代理后面时，所有客户端共用同一个桶，**这 5 个端点的限流会从"每 IP 10 次/分钟"塌成"全站 10 次/分钟"**，届时任何人每分钟打满 10 次就能把其他人挡在登录之外。审计记录里的 IP 同样取自这个值。

限流器是进程内的，集群部署需要自行前置共享状态。持 token 的端点（refresh/publish/…）不限流——它们的凭证不可猜。

### 1.5 缓存与压缩

| 资源 | `Cache-Control` |
|---|---|
| 所有 JSON 响应（含 `/pubkey`） | `no-store` |
| `/admin/assets/*`（Vite 内容哈希产物） | `public, max-age=31536000, immutable` |
| `/admin/` 的 index.html | `no-cache` |
| `/` 下的告警客户端静态文件 | `no-cache` |

告警客户端的文件名**没有**内容哈希，若不显式声明，浏览器的启发式新鲜度可能长时间复用旧副本——对生命安全通道不可接受，故钉死为 `no-cache`（仍可走 304）。

响应体 ≥ 1024 字节且 Content-Type 可压缩时启用 gzip；Range 请求与已压缩类型（字体、图片）自动跳过。

### 1.6 错误格式

错误响应是 **`text/plain`** 的一行短消息，不是 JSON。常见状态码：

`400` 请求体或参数不合法 · `401` 凭证无效/过期/已吊销 · `403` 权限或 scope 不足 · `404` 对象不存在，或该 SSO 方式未启用 · `405` 方法不允许 · `429` 触发限流 · `500` 服务端错误 · `502` 发布到 broker 失败 · `503` 依赖不可用（仅 `/readyz`）。

---

## 2. 告警平面

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `POST /api/publish` | `perm:alert:publish` | 校验输入 → 生成 id/nonce/issued_at → 签名 → 发 `alerts/events` + 按替换策略 retained 发 `alerts/active` → 落库 + 入投递外发队列。 |
| `POST /api/cancel` | `perm:alert:cancel` | 对指定 id 发出已签名的撤回，并清空 retained active（若它正持有该告警）。 |
| `GET /api/history` | `perm:alert:read` | 活动组织最近 50 条已签名信封，按 `issued_at` 倒序。 |
| `POST /api/cap` | `scope:alerts:ingest` | CAP 1.2 XML 摄入；`msgType=Cancel` 时走撤回路径。 |
| `GET /api/devices` | `perm:device:read` | 设备在线名册（来自 `status/#` 的 LWT + birth）。**全局，非按组织隔离**。 |
| `GET /api/delivery/stats` | `perm:alert:read` | 活动组织的持久化投递健康度：状态计数 + 最近死信。 |

### 2.1 `POST /api/publish`

请求：

```json
{
  "severity": "emergency",
  "category": "earthquake",
  "title": "正在发生地震",
  "body": "震中距你约 42 公里，预计 15 秒后到达。",
  "action": "趴下，掩护，抓牢",
  "ttl": 120
}
```

- `severity` 必填，枚举：`notice` | `warning` | `critical` | `emergency`。
- `category` 必填，枚举：`earthquake` | `fire` | `weather` | `system` | `security` | `custom`。
- `title` / `body` / `action` 不得含 `\n` 或 `\r`（SPEC §3.2 规则 7）。
- `action` 省略时按 category 填入默认处置语；`ttl` 省略或 ≤ 0 时按 severity 取默认值（`emergency`/`critical` = 120 秒，其余 = 600 秒）。
- `source` 由服务端固定写入 `panel`，客户端不能指定。

响应 `200`，返回**完整的已签名信封**（即客户端在 MQTT 上收到的同一份 JSON）：

```json
{
  "schema_version": 1,
  "id": "0192f3a1-…",
  "type": "alert",
  "category": "earthquake",
  "severity": "emergency",
  "title": "正在发生地震",
  "body": "震中距你约 42 公里，预计 15 秒后到达。",
  "action": "趴下，掩护，抓牢",
  "source": "panel",
  "issued_at": 1765238400,
  "ttl": 120,
  "nonce": "9f86d081884c7d659a2feaa0c55ad015",
  "cancels": "",
  "sig": "<base64url-raw-64>"
}
```

失败：`400` 校验不通过（severity/category 非法、含换行、JSON 解析失败）；`405` 非 POST；`502` 发布到 broker 失败。

### 2.2 `POST /api/cancel`

请求 `{"id": "<被撤回告警的 id>"}`（`id` 必填）。

响应 `200`，返回一条 `type: "cancel"` 的已签名信封：`severity` = `notice`、`category` = `custom`、`title` = `警报已解除`、`ttl` = 120、`cancels` = 原 id。同时若 retained active 正持有该 id 则被清空。

失败：`400` JSON 非法或缺 `id`；`405` 非 POST；`502` 发布失败。

### 2.3 `GET /api/history`

响应 `200`，一个**已签名信封的数组**（结构同 2.1 的响应对象），最新在前。条数固定 50，暂无分页参数。

### 2.4 `POST /api/cap`

请求体是 CAP 1.2 XML（原样读取，上限 1 MiB）。这是给外部系统/其他程序的互操作入口。

映射要点：CAP 的 `category` → AlertHub category；`urgency`/`severity`/`certainty` 三元组坍缩为单一 severity；`status` 非 `Actual`（Test/Exercise 等）时 severity 被压到最高 `warning`，不会触发真实全屏警报。

告警 id 是**确定性**的：`"cap-" + hex(sha256(sender + "\x00" + identifier))[:24]`。因此后续 CAP Cancel 无需映射表即可精确召回。

`msgType != Cancel` 时响应 `200`：

```json
{ "id": "cap-2b7f…", "severity": "critical", "category": "weather", "test": false }
```

`msgType == Cancel` 时，服务端解析 `<references>`（空格分隔的 `sender,identifier,sent` 三元组），对每一项重建同一 id 并逐条撤回，响应 `200`：

```json
{ "cancelled": ["cap-2b7f…", "cap-91ac…"] }
```

失败：`400` XML 非法、映射结果不合法、或 Cancel 未带 `<references>`；`403` scope 不足；`405` 非 POST；`502` 发布失败。

### 2.5 `GET /api/devices`

响应 `200`，设备状态数组：

```json
[{ "device_id": "kitchen-tablet", "state": "online", "at": 1765238400, "client": "web", "last_seen": 1765238412 }]
```

`state` 为 `online` | `offline`。该名册来自 broker 的 `status/#` 订阅，是**全局**的：设备表还没有 `org_id`，设备开通功能尚未构建。

### 2.6 `GET /api/delivery/stats`

响应 `200`：

```json
{
  "counts": { "pending": 3, "sent": 812, "dead": 1 },
  "dead": [{
    "alert_id": "0192f3a1-…", "channel": "webhook",
    "target": "https://…", "attempts": 5,
    "last_error": "…", "updated_at": 1765238400
  }]
}
```

`counts` 是 `delivery_jobs` 按状态的计数；`dead` 是最近 20 条死信（fail-loud 可见性）。

---

## 3. 认证

### 3.1 口令与会话

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `GET /api/auth/methods` | 公开 | 告诉登录界面该显示哪些登录方式。 |
| `POST /api/auth/login` | 公开 · **限流** | 口令登录；若已启用 2FA，只返回 pending token。 |
| `POST /api/auth/refresh` | 公开（凭 refresh token） | 换发新的 access/refresh 对。 |
| `POST /api/auth/logout` | 公开 | 无状态；清除 `ah_access` Cookie，返回 `204`。 |
| `GET /api/auth/me` | 会话 | 当前身份。 |

**`GET /api/auth/methods`** 响应：

```json
{
  "local": true, "passkey_enabled": true, "passkey_passwordless": true,
  "sso": false, "oidc": false, "saml": false,
  "site_title": "AlertHub 控制台"
}
```

**`POST /api/auth/login`** 请求 `{"upn": "admin", "password": "…"}`。

未启用 2FA 时响应 `200`：

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "user": { "id": 1, "upn": "admin", "role": "admin", "email": "a@b.c" }
}
```

（`email` 为空时省略。下文所有"会话响应"均指这一结构。）

已启用 2FA 时响应 `200`，但只给出待验证凭据：

```json
{ "status": "2fa_required", "pending_token": "<jwt, 5 分钟>", "methods": ["totp", "recovery"] }
```

失败：`400` JSON 非法；`401` 用户不存在 / 已禁用 / 未设口令 / 口令错误（统一 `invalid credentials`，不区分）；`429` 限流。

**`POST /api/auth/refresh`** 请求 `{"refresh_token": "<jwt>"}` → 会话响应。若用户已禁用或 `TokenVersion` 已递增则 `401`。

**`GET /api/auth/me`** 返回 `{"id","upn","role","email"}`。用静态管理 token 调用时返回 `{"id": 0, "upn": "admin-token", "role": "admin"}`。

### 3.2 二步验证（TOTP）

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `POST /api/auth/2fa/verify` | 公开 · **限流** | 用 pending token + 验证码换取正式会话。 |
| `GET /api/auth/2fa/status` | 会话 | 当前用户是否已启用 2FA。 |
| `POST /api/auth/2fa/begin` | 会话 | 开始注册，返回 otpauth URL + 密钥。 |
| `POST /api/auth/2fa/enable` | 会话 | 提交验证码确认启用，返回一次性恢复码。 |
| `POST /api/auth/2fa/disable` | 会话 | 提交验证码关闭，返回 `204`。 |

**`POST /api/auth/2fa/verify`** 请求：

```json
{ "pending_token": "<login 返回的 pending_token>", "code": "123456" }
```

`code` 可以是 TOTP 验证码，也可以是一次性恢复码。成功返回会话响应；`401` 表示 pending token 无效/过期、用户已禁用或已吊销、或验证码错误。

`begin` 响应 `{"otpauth_url": "otpauth://totp/…", "secret": "…"}`；`enable` 响应 `{"recovery_codes": ["…", …]}`（恢复码以 AES-256-GCM 加密存储，**仅此一次**明文返回）。

### 3.3 Passkey / WebAuthn

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `POST /api/auth/passkey/register/begin` | 会话 | 取注册 challenge，返回 `{options, session}`。 |
| `POST /api/auth/passkey/register/finish` | 会话 | 查询参数 `?session=&name=`，请求体是 attestation。成功 `204`。 |
| `POST /api/auth/passkey/login/begin` | 公开 | 无用户名（discoverable）登录 challenge，返回 `{options, session}`。 |
| `POST /api/auth/passkey/login/finish` | 公开 · **限流** | 查询参数 `?session=`，请求体是 assertion。成功返回会话响应。 |
| `GET /api/auth/passkey/list` | 会话 | 已注册凭据：`[{"id","name","created_at","last_used_at"}]`。 |
| `POST /api/auth/passkey/delete` | 会话 | 请求体 `{"id": 1}`，成功 `204`。 |

`options` 即 WebAuthn 标准的 `PublicKeyCredentialCreationOptions` / `RequestOptions`，直接喂给浏览器 API。RP ID 与 origin 来自 `ALERTHUB_RP_ID` / `ALERTHUB_RP_ORIGIN` 配置，**绝不取自 Host 头**。

注册类端点要求真实会话登录：用静态管理 token 调用会返回 `400`（无 JWT claims，无法确定绑定到哪个用户）。

### 3.4 OIDC 单点登录

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `GET /api/auth/oidc/login` | 公开 | 302 跳转到 IdP（带 state / nonce / PKCE，均写入 HttpOnly Cookie）。 |
| `GET /api/auth/oidc/callback` | 公开 | IdP 回调：校验 state（常数时间比对）→ 换 token → JIT 建号 → 302 到 `/admin/sso?code=<一次性码>`。 |
| `POST /api/auth/oidc/exchange` | 公开 · **限流** | SPA 用 `{"code": "…"}` 换取会话响应。一次性码有效期 60 秒，用后即焚。 |

未启用 OIDC 时 `login` / `callback` 返回 `404`。IdP 返回的错误只记服务端日志，不回显给客户端。JIT 创建的用户角色取 `ALERTHUB_OIDC_DEFAULT_ROLE`，并自动加入默认组织——注意该变量**同时管辖 SAML**（两条 SSO 路径共用 `ensureSSOUser`），且同时用作 `users.role` 与默认组织的成员角色。

之所以走"一次性码 → POST 换取"而不是直接把 token 放进 URL 片段，是为了避免 token 出现在浏览器历史/Referer 中。

### 3.5 SAML 2.0 单点登录

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `GET /api/auth/saml/login` | 公开 | 302 跳转到 IdP（HTTP-Redirect 绑定）。 |
| `POST /api/auth/saml/acs` | 公开 · **限流** | Assertion Consumer Service：IdP POST `SAMLResponse`，校验通过后 302 到 `/admin/sso?code=`。 |
| `GET /api/auth/saml/metadata` | 公开 | SP 元数据 XML（`application/samlmetadata+xml`），用于在 IdP 侧注册。 |

未启用 SAML 时三者均返回 `404`。IdP 发起（IdP-initiated）的 SSO **默认关闭**（`ALERTHUB_SAML_ALLOW_IDP_INITIATED`）——它是 CSRF/重放面。拿到会话的方式与 OIDC 相同：一次性码 + `/api/auth/oidc/exchange`。

---

## 4. 组织与服务账号

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `GET /api/orgs` | 会话 | 超级管理员看到全部组织，其他用户只看到自己有成员关系的组织。 |
| `POST /api/orgs` | 会话（**仅超级管理员**） | 创建组织。**仅当调用方是会话用户时**创建者才自动获得 `owner` 成员身份；用静态 admin token 调用不会写入成员行（无 JWT claims 可归属）。 |

### 场景模板（一键发送）

| 方法 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/scenarios` | perm `alert:read` | 服务端持有的五个场景：`evacuate` / `shelter` / `lockdown` / `dropcover` / `allclear`，各含 severity/category/措辞/CAP `response_type`/TTL。**由服务端下发**，保证各客户端措辞一致。 |
| `POST /api/publish/scenario` | perm `alert:publish` | body `{id, note?}`。按模板发送；`note` 会**追加**到正文,但**不能覆盖** `action`（指令由服务端固定）。`source` 记为 `scenario:<id>`，审计可追溯是哪个模板。未知 id → 404。 |

### 出向 CAP（把我们的告警发布为 CAP 1.2）

| 方法 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/cap/alert?id=<alertID>` | perm `alert:read` | 单条告警渲染为 **CAP 1.2 XML**（`application/cap+xml`）。severity 反推为一组会**折叠回同一 severity** 的 urgency/severity/certainty 三元组（有往返测试守护）。`type=cancel` 会带上 `<references>` 指明撤回对象。 |
| `GET /api/cap/feed` | perm `alert:read` | 最近 50 条的 **Atom feed**，每个 entry 内嵌该告警的 CAP 文档（CAP 本身没有多告警容器，消费方期望一个可轮询的 feed）。**需鉴权**，不是公开广播源。 |

`<sender>` 取自 `ALERTHUB_CAP_SENDER`（默认 `alerthub`）。消费方按 `(sender, identifier)` 去重，**必须跨重启稳定**，因此它是配置项而非从请求 Host 推导。
**演练**以 `status=Exercise` 发出，绝不标 `Actual` —— 这是 ingest 侧演练门的镜像：不能让一次测试在下游被升级成真实响应。

### 审计日志

| 方法 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/alerts/acks?id=<alertID>` | perm `alert:read` | 「谁已确认」名册（SPEC §5.3）：`acked`（含 device_id/ack_at）、`online`、**`pending`（在线但尚未确认——事发时真正有用的那个数）**、`ack_count`。设备身份取自 **topic** 而非 payload：broker ACL 只允许设备写自己的 `alerts/+/ack/<自己的id>`，payload 可伪造。 |
| `GET /api/sources` | perm `alert:read` | 只读列出已配置的入向/出向通道（panel、CAP、EEW、ntfy、投递、看门狗、SIEM），只报「是否启用」与控制它的环境变量名，**绝不返回任何密钥或 URL**。来源配置只走环境变量——让 feed 在控制台可编辑等于再开一条注入警报的路径。 |
| `GET /api/audit?limit=N` | perm `settings:manage` | 当前组织的审计条目，最新在前（默认 100，上限 500）。每条含 `actor_type`（`user`/`service_account`/`admin_token`/`system`）、`actor_name`、`action`、`target_id`、`ip`、`prev_hash`、`hash`。 |
| `GET /api/audit/verify` | perm `settings:manage` + **仅超级管理员** | 重算整条哈希链。返回 `{ok, entries, bad_id?, reason?}`。链是**全局**的（跨租户，保护平台完整性），故校验是平台级操作；组织管理员只能读自己那份过滤视图。 |

记录的动作：`alert.publish`、`alert.cancel`、`auth.login`、`auth.login_failed`、`auth.sso_login`、`2fa.enable`、`2fa.disable`、`passkey.add`、`passkey.delete`、`service_account.create`、`service_account.delete`、`org.create`。配置 `ALERTHUB_SIEM_URL` 后，条目还会按持久化游标至少一次外送到 SIEM（携带链哈希，供采集端独立验链）。审计写入是 **best-effort**：写失败会大声记日志，但**不会**让原动作失败——因为审计表不可用而拒绝广播紧急警报，是更糟的结果。
| `GET /api/admin/service-accounts` | `perm:sa:manage` | 列出活动组织的服务账号。 |
| `POST /api/admin/service-accounts` | `perm:sa:manage` | 创建服务账号，**明文 key 只返回一次**。 |
| `POST /api/admin/service-accounts/delete` | `perm:sa:manage` | 请求体 `{"id": 1}`，成功 `204`。 |

`/api/orgs` 的 GET 响应是 `[{"id","slug","name"}]`；POST 请求 `{"slug": "acme", "name": "Acme Inc"}`（`slug` 必填，`name` 省略时取 `slug`），返回同样的对象。非超级管理员 POST 得到 `403`；slug 冲突得到 `400`。

服务账号 GET 响应：

```json
[{ "id": 1, "name": "cap-bridge", "scopes": ["alerts:ingest"],
   "disabled": false, "created_at": 1765238400, "last_used_at": 1765240000 }]
```

POST 请求 `{"name": "cap-bridge", "scopes": ["alerts:ingest"]}`（`scopes` 省略时默认 `["alerts:ingest"]`），响应：

```json
{ "id": 1, "name": "cap-bridge", "scopes": ["alerts:ingest"], "token": "ahk_…" }
```

`token` 字段**只在创建时出现这一次**，数据库里只存 SHA-256 摘要，遗失只能重建。

---

## 5. 公开与运维

| 方法 路径 | 鉴权 | 作用 |
|---|---|---|
| `GET /pubkey` | 公开 | 信任锚 + 浏览器客户端引导信息。 |
| `GET /healthz` | 公开 | 存活探针：进程在跑就返回 `200` + `ok`（纯文本）。 |
| `GET /readyz` | 公开 | 就绪探针：`Store.Ping()` 成功返回 `{"ready": true}`，否则 `503`。 |
| `GET /metrics` | 公开 | Prometheus 指标。 |
| `GET /` | 公开 | 精简告警客户端（静态文件，来自 `ALERTHUB_WEB_DIR`）。 |
| `GET /admin/` | 公开 | 内嵌的 React 管理控制台（history 模式，未命中文件回落到 index.html）。 |
| `GET /admin` | 公开 | `301` 重定向到 `/admin/`。 |

**`GET /pubkey`** 响应：

```json
{
  "pubkey": "<base64url-raw-32>",
  "schema_version": 1,
  "max_skew": 120,
  "ws_port": "1884",
  "mqtt_user": "client",
  "mqtt_pw": "dev-client-pw"
}
```

浏览器客户端启动时拉取它以取得验签公钥与 MQTT/WebSocket 连接参数。这里的 MQTT 口令在浏览器里本就不是真正的秘密——真正的信任锚是签名，加上 broker ACL 禁止客户端写告警通道（SPEC §6/§8）。生产环境应改为**构建期内嵌**公钥。

`/metrics` 暴露的计数器：`alerthub_alerts_published_total`、`alerthub_cap_ingest_total`、`alerthub_auth_logins_total`、`alerthub_heartbeats_total`、`alerthub_delivery_enqueued_total`、`alerthub_delivery_attempts_total`。

`/admin/assets/*` 下未命中的路径直接返回 `404`，不会回落到 SPA index——缺失的哈希资源必须硬失败，而不是拿到一份 HTML。

---

## 6. curl 示例

发布一条告警（用静态管理 token，最省事的脚本路径）：

```sh
curl -fsS -X POST http://localhost:8080/api/publish \
  -H "Authorization: Bearer $ALERTHUB_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"severity":"emergency","category":"earthquake",
       "title":"正在发生地震","body":"震中距你约 42 公里，预计 15 秒后到达。",
       "action":"趴下，掩护，抓牢","ttl":120}'
```

CAP 1.2 摄入（用服务账号 key，并指定活动组织）：

```sh
curl -fsS -X POST http://localhost:8080/api/cap \
  -H "Authorization: Bearer ahk_xxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "X-Org-Id: 1" \
  -H "Content-Type: application/xml" \
  --data-binary @- <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>ACME-2026-0001</identifier>
  <sender>ops@example.com</sender>
  <sent>2026-08-14T09:00:00+08:00</sent>
  <status>Actual</status>
  <msgType>Alert</msgType>
  <scope>Private</scope>
  <info>
    <category>Fire</category>
    <event>Building fire</event>
    <urgency>Immediate</urgency>
    <severity>Severe</severity>
    <certainty>Observed</certainty>
    <headline>B 座三层起火</headline>
    <description>请立即从最近的安全出口撤离。</description>
    <instruction>不要乘电梯。</instruction>
  </info>
</alert>
XML
```

撤回同一条 CAP 告警时，`msgType` 改为 `Cancel`，并带上
`<references>ops@example.com,ACME-2026-0001,2026-08-14T09:00:00+08:00</references>`
——服务端据此重建同一个确定性 id 并精确召回。
