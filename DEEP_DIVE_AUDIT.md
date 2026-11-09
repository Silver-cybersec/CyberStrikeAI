# CyberStrikeAI 只读细查补充

- 对照文档：`SECURITY_AUDIT.md`（PR #1，提交 `60c75a6aba979b7fae998610e515bc475ff06d7b`，分支 `cursor/security-audit-0ab2`）。该文件不在本分支。
- 本仓提交：`b43bdb991c3bee4f433cd1a0a370a90c4e24241e`（与原审计同一 `main`）。
- 查询日：2026-11-09。
- 方法：只读。读了本仓源码、`go.mod` / `go.sum`，以及两个 fork 的 git 历史、官方模块 zip 和校验库响应。用目录哈希算法重算了 `h1`。没有运行本仓程序、测试、`go test`、`go build`，没有执行 `go mod download` / `go mod verify`，没有向钉钉、飞书、Slack、Discord、Telegram、QQ 或模型接口发请求。
- 证据标记：**已核实**（源码、提交或哈希对得上）、**有冲突**（与原审计表述不一致）、**无法确认**（这次没拿到足以判定的材料）。

## 1. 结论摘要

| 项 | 一句结论 | 对原审计定级的影响 |
|---|---|---|
| (1) `meguminnnnnnnnn/go-openai` v0.1.6 | 相对上游 tag `v1.41.2` 的差异是协议字段、调用方可选的请求头/请求体钩子，以及放宽推理模型参数校验；没有新增外连地址、遥测或密钥外传。 | **下调**。原审计写「与上游的完整差异是否含恶意逻辑：未确认」。这一未知项可以收掉。模块仍不是上游，总体「高」不因此改变。 |
| (2) `uouuou/dingtalk-stream-sdk-go` `079132acc406` | 这是官方 tag `v0.9.1` 之上、只改 `client/client.go` 的个人补丁，内容是连接关闭和 panic 恢复；它不在上游任何分支上。官方 `v0.9.2-beta.1` 后来用另一套改动重写了该文件。 | **上调**。原审计写「同一 SHA 在官方仓库也能查到，因此不是未知篡改」。提交对象按 SHA 能从官方远程取到，但没有上游分支包含它。补丁本身未见外传，原「隐藏后门未发现」仍成立。 |
| (3) Slack、Discord、QQ、Telegram，以及同路径上的微信、企业微信、钉钉、飞书 | 这四家没有公网 HTTP 回调；启用后用机器人凭证做出站长连接。默认 `user_binding`，未绑定的发送者到不了 Agent。钉钉和飞书的 HTTP 占位不处理消息。 | **下调**。原审计写「一旦打开，钉钉与飞书回调的鉴权强度未确认」。HTTP 占位不执行指令。四家原审计未单列，本次不把总体「高」降下来。 |

## 2. 逐项细查

### 2.1 go-openai fork v0.1.6

**已核实。** 本仓没有 `replace` 这一模块。它由 `github.com/cloudwego/eino-ext/libs/acl/openai v0.1.18-0.20260924031408-10df7cac3f6d` 间接引入。该版本的 `go.mod` 写着：`github.com/meguminnnnnnnnn/go-openai v0.1.6`，注释说明这是 `sashabaranov/go-openai` 的临时 fork。本仓 `internal/openai/eino_sse_sanitizer.go` 第 3–9 行描述的是同一条调用链。

| 对象 | 值 |
|---|---|
| 选定版本 | `go.mod` 第 108 行，`v0.1.6`，间接 |
| `go.sum` | 第 283–284 行。zip `h1:c74nk9F3+/agOd09eHeQt/Ayty4pw54X2Dj5JHdxcys=`；`go.mod` `h1:qs96ysDmxhE4BZoU45I43zcyfnaYxU3X+aRzLko/htY=` |
| fork tag | `v0.1.6` → `a92c8d868a5db59bb6e0e40a2230c417edb1bd04`（2026-09-24 10:41:57 +0800，合并说明为暴露 cache write token） |
| tag 树 | `38b6f8015018527e1471c5995b30bfdfb67fb92b` |
| 对应上游 | 分叉点就是上游 tag `v1.41.2`，提交 `8e5611cc5efdc2533b80e5667b69741c3fad875c`（2025-08-29），树 `8e344d76d0c5308444310af22e7bd47317938954` |
| 上游现状 | `master` 最新 tag `v1.43.0`，`dd54fd29688ae9934688a2928be0abbd8647a812`（2026-09-29）。上游没有 `v0.1.6` 这个 tag |
| 代理来源 | `v0.1.6.info` 的 `Origin.Hash` 等于 `a92c8d868a5db59bb6e0e40a2230c417edb1bd04`，`Origin.URL` 为 `https://github.com/meguminnnnnnnnn/go-openai` |

原审计对 tag、提交和时间的描述 **已核实**，没有冲突。

分叉点之后、tag 之前有 36 个提交。非合并提交的作者邮箱多次出现 `bytedance.com`，另有 `yhfszb@gmail.com`。提交说明集中在额外 JSON 字段、可选请求头、请求体修改钩子、用量字段、音频/文件片段，以及去掉推理模型参数校验。最终树与 `v1.41.2` 的 diff 已逐文件看过。36 个中间提交没有逐个检查「先加入再删除」的内容，见第 4 节。

`git diff --name-only v1.41.2 v0.1.6` 共 66 个路径。把 `github.com/meguminnnnnnnnn/go-openai` 替换回 `github.com/sashabaranov/go-openai` 之后：

- 47 个文件只剩模块路径变化，**已核实**无其他差异。包括 `audio.go`、`stream_reader.go`、各 `examples/*.go`，以及绝大多数 `*_test.go`。
- 3 个文件是新增：`option.go`、`common_test.go`、`go.sum`。
- 16 个已有文件在路径规范化之后仍有内容差异；再加上 3 个新增文件。下表覆盖这 19 个路径。

| 文件 | 相对 `v1.41.2` | 判定 |
|---|---|---|
| `.gitignore` | 增加 `.DS_Store` | 已核实，无关 |
| `README.md` | 补充 ExtraFields 示例；示例 import 仍写上游路径 | 已核实，文档 |
| `chat.go` | 音频、视频、文件片段；`Temperature` 改为指针；`SetExtraFields`（第 420–424 行）；响应用 sonic 反序列化并保留 `RawBody`（第 566 行）；`CreateChatCompletion`（第 577 行起）增加可选参数 | 已核实，见下方网络结论 |
| `chat_stream.go` | 流式增量的额外字段与 sonic 反序列化；流式创建函数接受同一组可选参数 | 已核实，请求仍走原来的 `fullURL` |
| `chat_stream_test.go`、`chat_test.go`、`common_test.go`、`internal/unmarshaler_test.go`、`internal/request_builder_test.go` | 覆盖新字段和钩子的测试 | 已核实，测试双写 `http://localhost`，没有新的生产主机 |
| `internal/form_builder_test.go` | import 顺序和路径 | 已核实，无逻辑 |
| `client.go` | 仅新增 `withExtraHeader`（第 101–108 行） | 已核实。`newRequest`（第 121 行）和把配置令牌放进 `Authorization`（第 218 行）不在这次差异里 |
| `common.go` | `Usage` 保留未知 JSON；`PromptTokensDetails` 增加 `CacheWriteTokens`（第 59 行） | 已核实，只解析响应 |
| `go.mod` | 模块路径改为 fork；新增 `sonic v1.14.0`、`json-patch v0.5.2`、`testify v1.10.0`。没有 `replace` | 已核实 |
| `go.sum` | 为上述依赖写 `h1`。另有未出现在 `require` 里的历史行，含 `nullprogram.com/x/optparse`、`knz/go-libedit` | 已核实文件内容。这些历史行不会被依赖方的构建使用，见第 3 节 |
| `option.go` | 第 12–21 行：`WithRequestBodyModifier`、`WithExtraHeader`。只有调用方传入时才生效 | 已核实 |
| `internal/marshaller.go` | 第 17–42 行：若值实现 `GetExtraFields()`，用 `json-patch` 的 MergePatch 把这些字段并进原本要发送的 JSON | 已核实。目标仍是这一次请求的 body，没有第二个 URL |
| `internal/request_builder.go` | 一处空行 | 已核实 |
| `internal/unmarshaler.go` | 第 24 行用 sonic 把未知 JSON 收进 map，再删掉结构体已声明的字段 | 已核实，解析响应，不发请求 |
| `reasoning_validator.go` | `Validate` 在识别 o1/o3/o4/gpt-5 之后直接 `return nil`（第 40–50 行）。上游在这里拒绝 `MaxTokens`、非 1 的 temperature 等 | 已核实。这是放宽客户端校验，不是外传 |

网络、遥测、密钥：

- 生产代码里的 API 根仍是 `config.go` 第 9 行的 `https://api.openai.com/v1`。该文件不在内容差异里。Anthropic 根地址同样未改。
- `CreateChatCompletion` 仍调用 `c.fullURL(...)` 后 `newRequest`（`chat.go` 第 616–618 行）。`withExtraHeader` 只在调用方给出 map 时追加头。
- 对 v0.1.6 全部 `*.go` 检索 `http.NewRequest`、`Dial`、`os.Getenv`、`exec.`、`telemetry`、`webhook` 后，新增命中都在测试或上述请求体钩子里。没有新的主机名，没有 `init()` 联网。
- 本仓自己的检索：没有调用 fork 的 `SetExtraFields` 或 `WithRequestBodyModifier`。摘要请求使用 eino-ext 的头 `X-CyberStrike-Summarization: 1`（`internal/openai/summarization_diag.go` 第 16 行，`internal/multiagent/eino_summarize.go` 第 323–324 行）。这是本仓常量，不是 fork 里写死的上报地址。

**有冲突：无。** 与原审计「只看了提交说明和文件名」相比，本次把未知项补上了，没有推翻「OSV 无记录、h1 已锁定」。

### 2.2 钉钉 SDK fork

**补丁内容已核实。原审计「该 SHA 等于已合并的官方树」有冲突。**

本仓 `go.mod` 第 153–155 行：

```text
replace github.com/open-dingtalk/dingtalk-stream-sdk-go => github.com/uouuou/dingtalk-stream-sdk-go v0.0.0-20250626025113-079132acc406
```

| 对象 | 值 |
|---|---|
| 伪版本 | `v0.0.0-20250626025113-079132acc406` |
| 提交 | `079132acc406dc3977bf0543b103b53a2c548006` |
| 提交时间 | 2025-06-26 10:51:13 +0800，即 2025-06-26 02:51:13Z。伪版本里的 `20250626025113` 与提交者时间一致 |
| 作者 | Rinvay.H。GitHub 用户 `uouuou` 的公开名称同为 Rinvay.H。该用户在官方 issue #28 下留言，时间早于这个提交 |
| 父提交 | `d1cc841e6013c3f6513a5bb01dfe3219b9c37d17` |
| 树 | `106100dc3539e7f161c21c070b6981e3323a1c6f`。从 `uouuou` 克隆和从 `open-dingtalk` 按 SHA 取到的树相同 |
| `go.sum` | 第 394–395 行。zip `h1:b72HNsEnmTRn7vhWGOfbWHAkA5RbRCk0Pbc56V2WAuY=`；`go.mod` `h1:ln3IqPYYocZbYvl9TAOrG/cxGR9xcn4pnZRLdCTEGEU=` |
| 代理来源 | `.info` 的 `Origin.Hash` 为上述完整 SHA，`Origin.URL` 为 `https://github.com/uouuou/dingtalk-stream-sdk-go` |
| fork 的 `go.mod` | 模块路径仍是 `github.com/open-dingtalk/dingtalk-stream-sdk-go`。没有 `replace`。依赖是 `uuid`、`gorilla/websocket`、`testify` |

官方仓库：

- tag `v0.9.1` 就是父提交 `d1cc841e6013c3f6513a5bb01dfe3219b9c37d17`（2025-04-18）。本仓 `require` 写的 `v0.9.1` 被 replace 掉，`go.sum` 没有 `v0.9.1` 的 zip `h1`。这一点与原审计一致，**已核实**。
- `git merge-base --is-ancestor 079132acc406 open-dingtalk/main` 结果是不在 main 上。`branch --contains` 为空。官方对该 SHA 的 pulls 接口返回空。**有冲突**：原审计把「按 SHA 能查到提交」写成了「树与官方相同、不是未知篡改」。按 SHA 能从官方远程取到对象，是因为这个提交留在仓库网络里；它没有进入任何上游分支。
- 官方 `main` / tag `v0.9.2-beta.1` 是 `d8d6e1f19d68b231c1514fdac973d866a2882b93`（2026-07-30）。自 `v0.9.1` 起有 12 个提交，其中包括 `64dec92`（用 context 处理 closed channel panic）以及后续的 websocket 生命周期改动。`git diff --stat 079132acc406 v0.9.2-beta.1` 涉及 9 个文件，`client/client.go` 是大段重写。fork 不包含这些后续提交。

fork 相对父提交（也就是官方 `v0.9.1`）只有 `client/client.go`，+60 / -24。其余 45 个文件与 `v0.9.1` 相同，**已核实**（`git diff --name-only` 只有这一文件；模块 zip 与该提交树逐字节相同）。

该 diff 已通读。变化是：用 `sync.Once` 关闭 `closeChan`（第 150–156 行），读循环退出时发关闭信号（第 176 行），ping 失败或超时走同一信号（第 214、226 行），`processLoop` 收到信号后返回（第 240 行之前的 select）。没有新的 URL、请求头、文件读取或凭据处理。连接仍先向 `https://api.dingtalk.com` 加上 `/v1.0/gateway/connections/open` 申请端点（`utils/utils.go` 第 9–10 行，`client/client.go` 第 401–408 行），再拨号响应里的 websocket（第 109 行）。这两处不在补丁 diff 里。

pin 上全部 Go 文件的 URL 检索只看到 `https://api.dingtalk.com` 和示例里的文档链接。debug 日志会打印建连请求体（`client/client.go` 第 435–437 行），体里包含调用方传入的应用密钥。这是 `v0.9.1` 已有行为，补丁没有改它。本机局域网地址写入建连请求也是上游协议字段，发往上述钉钉主机，不是第三个目的地。

fork 历史从 `16f426cfa209e17b487dd57cb74b696fcd8f5bef` 到父提交，与官方 main 上能看到的同一串提交一致；唯一多出来的是 `079132acc406`。fork 只有 `main`，最后推送停在该提交（2025-06-26）。仓库标记为 `open-dingtalk/dingtalk-stream-sdk-go` 的 fork，0 star。

本仓使用点：`internal/robot/ding.go` 第 38–44 行用应用 Key/Secret 订阅 `/v1.0/im/bot/messages/get`。这是出站长连接，不是本仓 HTTP 端口上的回调。

### 2.3 机器人入站：谁能把文字送进命令处理

四家目标平台，加上原审计已提到、走同一 `HandleMessage` 的微信、企业微信、钉钉、飞书。

共同出口是 `internal/handler/robot.go` 的 `HandleMessage`（第 383 行）。平台用户标识为空则拒绝（第 390–392 行）。普通文本先过 `resolveRobotAccess`（第 159–183、402–407 行）：

- 默认模式 `user_binding`（`EffectiveMode`，第 618–623 行；示例 `config.example.yaml` 第 517–518 行及各平台 `auth.mode`）。必须已经用绑定码把「平台 + 外部用户 ID」绑到一个启用的 RBAC 用户。绑定码接口在登录和 `auth:self` 之后（`internal/app/app.go` 第 974 行）。消费绑定码失败就拒绝，不执行 Agent。
- `service_account` 要求发送者 ID 与 `allowed_external_users` 全字匹配（第 626–636 行）。空值、`*` 和空名单在 `ValidateRobotAuthorization`（第 751–774 行）失败。`config.Load`（第 1653、1738–1742 行）和保存配置的处理函数都会调用它。服务端入口 `cmd/server/main.go` 第 66 行调用 `config.Load`。校验允许把服务账号设成管理员 ID，但名单仍必须是具体发送者。
- 未绑定发送者可以收到帮助、版本号和 `whoami` 里的平台身份与鉴权模式（`handleRobotCommand` 第 1247 行起，`robotCommandPermission` 对这几条不要求权限）。需要 `chat:*`、`agent:execute`、`roles:read`、`config:read`、`project:*`、`vulnerability:read` 的命令会先查权限。Agent 对话还要求同时具备 `agent:execute`、`chat:read`、`chat:write`（第 406–407 行）。
- 示例里八个机器人均为 `enabled: false`（`config.example.yaml` 第 515–576 行）。`strict_user_identity` 未配置时默认 true（第 644–649 行）。钉钉 `allow_conversation_id_fallback` 与飞书 `allow_chat_id_fallback` 示例为 false。

`POST /api/robot/test` 在登录中间件之后（`app.go` 第 1018–1019 行）。

各平台入站：

| 平台 | 入站形态 | 本仓做了什么 | 谁的文字会进入 `HandleMessage` | 标记 |
|---|---|---|---|---|
| Slack | Socket Mode，无 HTTP 路由 | `internal/robot/slack.go` 第 46–50 行：`bot_token` 加 `OptionAppLevelToken(app_token)`。`slack-go` v0.27.0 的 `socketmode.New`（`socketmode.go` 第 131 行）经 `apps.connections.open` 取 websocket（同文件第 76 行注释）。本仓没有 Signing Secret 字段 | 私信：`ChannelType == im` 且不是 bot（第 83–97 行）。频道：任何 `AppMention`（第 100–111 行），没有频道白名单，也没有「只响应 @」的开关，因为事件本身是提及 | 已核实 |
| Discord | Gateway，无 HTTP 路由 | `internal/robot/discord.go` 第 44–55 行：令牌补 `Bot ` 前缀，声明消息 intents。`discordgo` v0.29.0 `Session.Open`（`wsapi.go` 第 50 行）取 Gateway 后 `identify`（第 130、841 行） | 作者是 bot 则丢弃（第 58–59 行）。私信都进入。服务器频道仅当 `allow_guild_messages` 为 true 且提及本 bot（第 65–71、89–98 行）。示例该开关为 false（示例第 569 行）。没有服务器或频道白名单 | 已核实 |
| Telegram | `getUpdates` 长轮询，无 webhook 路由 | `internal/robot/telegram.go` 第 20、96–117 行。令牌放在 `https://api.telegram.org/bot<token>/...`（第 180–181 行）。没有本地签名校验；能拉到更新，是因为令牌被 Telegram 接受 | 来自 bot 的更新丢弃（第 126–127 行）。私聊都进入。群仅当 `allow_group_messages` 为 true（示例第 557 行为 false）。用户名非空时还要 @ 到该用户名（第 134–140、159–177 行）。用户名为空且 `getMe` 失败时，群里的普通文本也会进入。开关默认关着，所以默认配置不会走到这里 | 已核实 |
| QQ | 官方 SDK websocket，无 HTTP 路由 | `internal/robot/qq.go` 第 59–102 行：AppID 与 ClientSecret 换 token，`botgo.NewOpenAPI` 或沙箱客户端，再 `Identify`。`botgo` v0.2.1 的 API 域是 `https://api.sgroup.qq.com`，沙箱是 `https://sandbox.api.sgroup.qq.com`，令牌域是 `https://bots.qq.com`（`constant/constant.go` 第 8–14 行）。websocket 拨号地址来自 `api.WS` 的返回值（SDK `websocket/client/client.go` 第 53–59、157–169 行）。示例 `sandbox: true`（示例第 576 行） | C2C 文本都进入（第 116–138 行）。群只注册了群 @ 事件（第 89–91、142–166 行）。没有额外用户白名单。沙箱与正式环境的差别是 SDK 域名，不是本仓再验一层签名 | 已核实 |
| 钉钉 | Stream，外加一个不处理消息的 HTTP 占位 | 长连接见 2.2。`HandleDingtalkPOST`（`robot.go` 第 1952–1958 行）在启用时返回 200 和 `{"message":"ok"}`，不读业务字段，不调用 `HandleMessage`。回复发到消息里的 `SessionWebhook`（`ding.go` 第 134–140 行），本仓不再限制主机名；该 URL 来自已建连的 Stream 帧 | 长连接回调里，有 `SenderId` 时用 `t:<client_id>\|u:<sender>`。两者都空则丢弃（`ding.go` 第 101–112 行）。会话 ID 回退只在配置打开且严格身份关闭时发生 | HTTP 占位 **已核实** 不执行指令。Stream 对端是否始终是钉钉网关，取决于申请端点的响应，见第 4 节 |
| 飞书 | websocket，外加一个不处理消息的 HTTP 占位 | `lark.go` 第 42–49 行：`NewEventDispatcher("", "")`，`larkws.NewClient(AppID, AppSecret)`，没有 `WithDomain`。SDK 默认域 `https://open.feishu.cn`（`client.go` 第 490 行），建连 `POST /callback/ws/endpoint`，体为 AppID 与 AppSecret（`ws/client.go` 第 94、236–239 行）。事件帧调用 `EventDispatcher.Do`（第 423 行）。`Do`（`dispatcher.go` 第 243 行）不比较 verification token。`VerifySign` 在加密密钥为空时直接返回成功（第 152–153 行），且 websocket 路径不调用它。配置项 `verify_token` 只出现在配置结构、保存和脱敏（`config.go` 第 688 行），没有被入站代码读取 | 文本消息用 tenant + user/open/union id（`lark.go` 第 74–99、117–140 行）。HTTP `HandleLarkPOST`（`robot.go` 第 1964–1976 行）在带 `challenge` 时原样回显，不调用 `HandleMessage`，也不比较 `verify_token` | **已核实**。原审计「HTTP 回调鉴权未确认」可以收口：这个 HTTP 函数不执行命令。长连接信任的是用应用凭证换到的 websocket |
| 企业微信 | 唯一会执行命令的 HTTP 回调 | `app.go` 第 979–989 行挂在登录中间件之外，每 IP 每分钟 60 次。启用且 token 为空则 403（`robot.go` 第 1401–1408 行）；`ValidateWecomConfig`（第 663–671 行）在 `Load` 时要求 token。GET/POST 用 token、timestamp、nonce、echostr 或 Encrypt 做排序后的 SHA1（第 1428–1432、1459、1570–1594 行），并拒绝 5 分钟窗外和重放（第 117–141、1593–1596 行）。配了 EncodingAESKey 却收到空 Encrypt 时拒绝（第 1610–1614 行） | 验签通过后，用企业 ID 加 `FromUserName` 进入命令处理（第 1635–1671 行）。示例 `encoding_aes_key` 为空。明文模式下签名材料是 token、时间戳、nonce 和空的 Encrypt，不包含 `Content` 与 `FromUserName`。验签证明对方知道 token，并且这一组 timestamp/nonce/签名没被重放；它不证明正文未被改过 | 验签存在：**已核实**，与原审计一致。明文模式不覆盖正文：原审计没写，本次补充，不把「有验签」改成「没有验签」 |
| 微信 iLink | 长轮询 | `internal/robot/wechat.go` 第 54–87 行。默认基址 `https://ilinkai.weixin.qq.com`（示例第 524 行）。本仓不再对消息做平台签名校验；`FromUserID` 为空则丢弃 | 能从配置的基址拉到、且带发送者 ID 的文本 | 已核实。基址可改。改成别的主机后，该主机返回的消息会被当成入站 |

四家和钉钉、飞书、微信的消息正文以 Info 记入日志（例如 `slack.go` 第 95 行、`discord.go` 第 74 行、`telegram.go` 第 143 行、`qq.go` 第 137 行）。这是日志里的对话内容，不是缺少鉴权。

## 3. 供应链补充

只复核外围这两条链，没有重跑原审计附录里的 140 个模块。

### 3.1 版本锁定

- `go-openai` v0.1.6 写在 `go.mod`，没有 replace。同文件还有未选中的 `v0.1.2` 的 `go.sum` 行（第 281–282 行）。两版的 `go.mod` 字节相同，所以 `go.mod` 的 `h1` 相同；zip 的 `h1` 不同。构建会不会再下载 `v0.1.2`：没有运行 `go list -m all`，**无法确认**。选中版本以 `go.mod` 的 `v0.1.6` 为准。
- 钉钉以 replace 伪版本锁定。官方 `v0.9.1` 不会被拉取。伪版本时间戳与提交者 UTC 时间一致。
- fork 自己的 `go.sum` 不被依赖方使用。其中 `nullprogram.com/x/optparse`、`knz/go-libedit` 等历史行不在该 fork 的 `go.mod` `require` 里。本仓 `go.sum` 没有这两条的 zip `h1`。本仓另有一条只有 `/go.mod`、没有 zip `h1` 的 `github.com/jessevdk/go-flags v1.4.0`，不表示选中了该模块。
- 本仓直接依赖 `github.com/bytedance/sonic v1.15.0`。fork 的 `go.mod` 写 `v1.14.0`。最小版本选择会选本仓的 `v1.15.0`。`json-patch v0.5.2` 已在本仓 `go.mod` 第 80 行。

### 3.2 go.sum 与 zip

哈希是 Go 的 `dirhash.Hash1`：每个文件内容的 SHA-256，按 zip 内文件名排序后写成 `哈希  文件名` 行，再对这段文本做 SHA-256 和 base64。对代理 zip 和 `.mod` 重算的结果与本仓 `go.sum`、以及 `sum.golang.org` lookup 响应里的两行 `h1` 一致。

| 模块 | zip 与 git tag/提交 | 文件数 | `h1` |
|---|---|---|---|
| `meguminnnnnnnnn/go-openai@v0.1.6` | 与 `a92c8d868a5db59bb6e0e40a2230c417edb1bd04` 逐字节相同，无只在一侧出现的文件 | 108 | 与 `go.sum` 第 283–284 行一致 |
| `uouuou/dingtalk-stream-sdk-go@v0.0.0-20250626025113-079132acc406` | 与 `079132acc406` 逐字节相同 | 46 | 与 `go.sum` 第 394–395 行一致 |
| `v0.1.2` 的 `.mod` | 与 `v0.1.6` 的 `.mod` 字节相同 | — | 与 `go.sum` 第 282 行一致 |

lookup 响应还带 `sum.golang.org` 的签名行和树头。本次只比对了其中的 `h1` 文本。没有在本地验证签名和默克尔包含证明，也没有执行 `go mod verify`。**无法确认**这张票据的包含证明；**已核实**的是 HTTPS 取回的 `h1` 与本地重算、与 `go.sum` 三者相同。

### 3.3 来源

- `go-openai`：GitHub 上的 fork，tag 与代理 `Origin` 一致。eino-ext 显式依赖这个版本，并写明临时替代上游。它不是本仓私自 replace 的副本。模块路径挂在个人账号 `meguminnnnnnnnn` 下；账号或 tag 被改之后，已有 `h1` 会对不上，构建会失败，除非同时改 `go.sum`。
- 钉钉：伪版本指向个人仓库 `uouuou`。内容等于官方 `v0.9.1` 加一文件补丁，不等于官方 `v0.9.2-beta.1`。继续用这个 replace，就拿不到官方 main 上那 12 个后续提交。原审计建议「改用已经包含 `079132acc406` 的官方正式版」：上游没有包含该 SHA 的 tag 或分支。官方后续修复是另一串提交。

### 3.4 OSV、GHSA、恶意包库

2026-11-09 对 `https://api.osv.dev/v1/querybatch` 的查询，下列版本返回的漏洞列表长度为 0：

- `github.com/meguminnnnnnnnn/go-openai` `0.1.6`、`0.1.2`
- `github.com/sashabaranov/go-openai` `1.41.2`、`1.43.0`
- `github.com/uouuou/dingtalk-stream-sdk-go` 上述伪版本
- `github.com/open-dingtalk/dingtalk-stream-sdk-go` `0.9.1`、`0.9.2-beta.1`
- `github.com/bytedance/sonic` `1.14.0`、`1.15.0`
- `github.com/evanphx/json-patch` `0.5.2`
- `github.com/bwmarrin/discordgo` `0.29.0`
- `github.com/slack-go/slack` `0.27.0`
- `github.com/tencent-connect/botgo` `0.2.1`
- `github.com/larksuite/oapi-sdk-go/v3` 与 `github.com/larksuite/oapi-sdk-go` 的 `3.4.22`

GitHub Global Advisories（`ecosystem=go`，`affects` 分别为 megumi fork、sashabaranov、uouuou fork、open-dingtalk）返回条数为 0。

deps.dev：`meguminnnnnnnnn/go-openai` v0.1.6 有记录，Apache-2.0，发布时间 2026-09-24T02:41:57Z，响应里没有 advisories。钉钉伪版本的 deps.dev URL 返回 404；proxy 与 sumdb 有这条记录，404 只说明 deps.dev 这次没给出该伪版本页面。

OpenSSF `ossf/malicious-packages` 的 `osv/malicious/go` 递归树有 52 个路径。其中没有 `megumi`、`uouuou`、`dingtalk`、`sashabaranov`、`openai`、`slack-go`、`discordgo`、`botgo`、`larksuite`。`.../go/github.com/meguminnnnnnnnn` 与 `.../go/github.com/uouuou` 的 contents 接口返回 404。

这些结果表示上述库在查询当日没有给出记录。它们不证明以后不会出现公告，也不覆盖「个人仓库以后改 tag」——tag 被改会破坏已记录的 `h1`。

## 4. 未确认项与原因

1. `go-openai` 那 36 个中间提交是否曾加入又删掉逻辑。发布物是 tag 树，已与 `v1.41.2` 和模块 zip 对齐；没有逐个 `git show` 中间补丁。
2. 本仓构建是否还会下载 `go.sum` 里的 `meguminnnnnnnnn/go-openai v0.1.2`。没有运行 `go list -m all`。`go.mod` 选定的是 `v0.1.6`。
3. sumdb 签名和默克尔包含证明。只比对了 lookup 正文里的 `h1`。
4. 钉钉或飞书「申请 websocket 地址」的响应若不是官方网关，SDK 会拨号响应里的 URL。本仓没有再限制主机名。这次没有连真实网关，不能观察运行时返回的地址。静态默认主机是 `https://api.dingtalk.com` 与 `https://open.feishu.cn`。
5. Slack / Discord / QQ SDK 在异常关闭码或重连时的全部边界。本次读了建连和 identify/token 路径，没有通读这三个 SDK 的全部源文件。
6. deps.dev 对钉钉伪版本返回 404 的原因。

## 5. 方法与读取过的 URL

本地只读：本仓 `b43bdb991c3bee4f433cd1a0a370a90c4e24241e` 的 `go.mod`、`go.sum`、`config.example.yaml`、`cmd/server/main.go`、`internal/config/config.go`、`internal/app/app.go`、`internal/handler/robot.go`、`internal/robot/{slack,discord,telegram,qq,ding,lark,wechat}.go`、`internal/openai/eino_sse_sanitizer.go`、`internal/openai/summarization_diag.go`、`internal/multiagent/eino_summarize.go`。原审计正文来自 `git show 60c75a6aba979b7fae998610e515bc475ff06d7b:SECURITY_AUDIT.md`。

克隆后只做 `git log` / `git diff` / `git show`，没有执行仓库里的 Go 程序：

- `https://github.com/meguminnnnnnnnn/go-openai`
- `https://github.com/sashabaranov/go-openai`
- `https://github.com/uouuou/dingtalk-stream-sdk-go`
- `https://github.com/open-dingtalk/dingtalk-stream-sdk-go`

哈希算法对照：`https://raw.githubusercontent.com/golang/mod/v0.21.0/sumdb/dirhash/hash.go`

模块与校验库：

- `https://proxy.golang.org/github.com/meguminnnnnnnnn/go-openai/@v/v0.1.6.info`
- `https://proxy.golang.org/github.com/meguminnnnnnnnn/go-openai/@v/v0.1.6.mod`
- `https://proxy.golang.org/github.com/meguminnnnnnnnn/go-openai/@v/v0.1.6.zip`
- `https://proxy.golang.org/github.com/meguminnnnnnnnn/go-openai/@v/v0.1.2.mod`
- `https://proxy.golang.org/github.com/uouuou/dingtalk-stream-sdk-go/@v/v0.0.0-20250626025113-079132acc406.info`
- `https://proxy.golang.org/github.com/uouuou/dingtalk-stream-sdk-go/@v/v0.0.0-20250626025113-079132acc406.mod`
- `https://proxy.golang.org/github.com/uouuou/dingtalk-stream-sdk-go/@v/v0.0.0-20250626025113-079132acc406.zip`
- `https://proxy.golang.org/github.com/cloudwego/eino-ext/libs/acl/openai/@v/v0.1.18-0.20260924031408-10df7cac3f6d.mod`
- `https://sum.golang.org/lookup/github.com/meguminnnnnnnnn/go-openai@v0.1.6`
- `https://sum.golang.org/lookup/github.com/meguminnnnnnnnn/go-openai@v0.1.2`
- `https://sum.golang.org/lookup/github.com/uouuou/dingtalk-stream-sdk-go@v0.0.0-20250626025113-079132acc406`

漏洞与恶意包：

- `https://api.osv.dev/v1/querybatch`
- `https://api.github.com/advisories?ecosystem=go&affects=github.com/meguminnnnnnnnn/go-openai`
- `https://api.github.com/advisories?ecosystem=go&affects=github.com/sashabaranov/go-openai`
- `https://api.github.com/advisories?ecosystem=go&affects=github.com/uouuou/dingtalk-stream-sdk-go`
- `https://api.github.com/advisories?ecosystem=go&affects=github.com/open-dingtalk/dingtalk-stream-sdk-go`
- `https://api.deps.dev/v3alpha/systems/go/packages/github.com%2Fmeguminnnnnnnnn%2Fgo-openai/versions/v0.1.6`
- `https://api.deps.dev/v3alpha/systems/go/packages/github.com%2Fuouuou%2Fdingtalk-stream-sdk-go/versions/v0.0.0-20250626025113-079132acc406`（404）
- `https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1`（只筛选 `osv/malicious/go/`）
- `https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious/go/github.com/meguminnnnnnnnn?ref=main`（404）
- `https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious/go/github.com/uouuou?ref=main`（404）

钉钉提交与 issue：

- `https://github.com/open-dingtalk/dingtalk-stream-sdk-go/commit/079132acc406dc3977bf0543b103b53a2c548006`
- `https://github.com/uouuou/dingtalk-stream-sdk-go/commit/079132acc406dc3977bf0543b103b53a2c548006`
- `https://github.com/open-dingtalk/dingtalk-stream-sdk-go/issues/28`
- `https://api.github.com/repos/open-dingtalk/dingtalk-stream-sdk-go/commits/079132acc406dc3977bf0543b103b53a2c548006/pulls`（空）
- `https://api.github.com/users/uouuou`

SDK 源文件（只读，版本与本仓 `go.mod` 一致）：

- `https://raw.githubusercontent.com/larksuite/oapi-sdk-go/v3.4.22/event/dispatcher/dispatcher.go`
- `https://raw.githubusercontent.com/larksuite/oapi-sdk-go/v3.4.22/ws/client.go`
- `https://raw.githubusercontent.com/larksuite/oapi-sdk-go/v3.4.22/ws/const.go`
- `https://raw.githubusercontent.com/larksuite/oapi-sdk-go/v3.4.22/client.go`（`FeishuBaseUrl`）
- `https://raw.githubusercontent.com/slack-go/slack/v0.27.0/socketmode/socketmode.go`
- `https://raw.githubusercontent.com/bwmarrin/discordgo/v0.29.0/wsapi.go`
- `https://raw.githubusercontent.com/tencent-connect/botgo/v0.2.1/constant/constant.go`
- `https://raw.githubusercontent.com/tencent-connect/botgo/v0.2.1/websocket/client/client.go`
