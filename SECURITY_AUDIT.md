# CyberStrikeAI 静态安全审计

- 审计对象：`Silver-cybersec/CyberStrikeAI`（GitHub 标记为 `AIPentest/CyberStrikeAI` 的 fork）
- 审计提交：`b43bdb991c3bee4f433cd1a0a370a90c4e24241e`（`main`）
- 许可证：Apache-2.0（`LICENSE`）
- 方法：只读静态审计。未运行仓库内的程序、安装脚本、二进制或镜像，未执行 `pip` / `npm` / `go mod download` / `docker build`。漏洞结论来自 2026-11-09 对 OSV（含 GHSA / GO / PYSEC 编号）及 PyPI、GitHub 公开元数据的只读查询。
- 与上游的关系：该提交与 `AIPentest/CyberStrikeAI` 的 `main`、以及 README 中出现的 `Ed1s0nZ/CyberStrikeAI` 的 `main` 为同一 SHA。GitHub 对 `Silver-cybersec/CyberStrikeAI` 与 `AIPentest/CyberStrikeAI` 的 compare 结果为 `identical`（ahead 0 / behind 0）。本次未发现该 fork 相对上游 `main` 的额外提交。未审计这三个远程上的其他分支。

## 总体结论

**总体风险：高。** 高风险来自产品本身：它是授权渗透测试与攻防自动化平台，默认就会监听所有网卡、关闭人机审批，并让模型直接驱动本机命令、WebShell 和 C2。

**隐藏后门：在本次静态范围内未发现。** 未看到独立于产品功能的混淆载荷、隐藏上报域名、读取 SSH 密钥或浏览器数据后自动外发、安装钩子或随仓库分发的二进制。编码、`exec`、反弹 shell 和自更新都出现在文档化的 C2、工具执行或一键更新路径中。无法用静态阅读证明运行时不会再去拉第三方工具，这类行为标为「未确认」。

**隔离实验室：可以使用，但不能按默认配置直接开机。** 把它当作高权限攻防控制端。先做文末加固，再放到不能访问生产、也不能被实验室外访问的网络里。

## 1. 恶意代码与后门

### 1.1 未发现针对部署者的隐藏后门

抽查了 `cmd/`、`internal/`、`run.sh`、`upgrade.sh`、`scripts/`、`mcp-servers/`、`plugins/`、`tools/` 和 `web/static/js/`（不含只看文件头的压缩库）。结论：

- 没有独立的遥测或“打电话回家”地址。OpenTelemetry 只有在配置打开时才导出，OTLP 缺省是本机 `localhost:4318`（`internal/einoobserve/otel.go` 第 54–62 行）。`config.example.yaml` 第 402 行同样是 `localhost:4318`。
- 没有搜索到读取 `~/.ssh`、浏览器 Cookie / Login Data 后外发的代码。
- 没有 `package.json`，因此没有 npm `postinstall`。仓库内没有可执行二进制、jar、压缩包后门（图片除外）。
- `internal/processguard/watchdog.go` 第 39–40 行写明进程守护在应用初始化之前通过本进程重入和私有管道工作，不打开网络控制口。`group_unix.go` 第 148–156 行的 base64 是把子进程规格交给本机 `syscall.Exec`，不是远程载荷。
- C2 里的 base64（`internal/c2/payload_oneliner.go` 第 141–150 行，PowerShell 第 161–173 行）是生成反弹 shell 单行命令，避免目标 shell 引号问题。这是产品功能，不是藏在启动路径里的载荷。

### 1.2 看起来危险、但属于产品功能的代码

这些能力默认或近乎默认可用，实验室里应视为“操作员和模型都能用的进攻工具”，而不是秘密后门。

| 能力 | 位置 | 说明 |
|---|---|---|
| 任意 shell | `tools/exec.yaml` 第 1–4 行；`internal/security/executor.go` 第 187 行 | 工具 `enabled: true`，命令为 `sh -c`。模型参数直接成为 shell 命令。 |
| 任意 Python | `tools/execute-python-script.yaml` 第 53–56 行 | `python3 -c "$SCRIPT_CONTENT"`。`ADDITIONAL_ARGS` 未加引号，拼进 shell。 |
| 任意 pip | `tools/install-python-package.yaml` 第 53–56 行 | `pip install "$PACKAGE" $ADDITIONAL_ARGS`。包名有引号，额外参数没有。模型可以在安装时再执行 shell。 |
| 内置 C2 与反弹单行命令 | `internal/c2/payload_oneliner.go` 第 112–200 行 | bash `/dev/tcp`、nc、python `exec(base64)`、perl、PowerShell `iex`、curl beacon。 |
| 反向 shell MCP | `mcp-servers/reverse_shell/mcp_reverse_shell.py` 第 73–76、145–150 行 | 监听 `0.0.0.0:<端口>`。默认 `external_mcp.servers` 为空（`config.example.yaml` 第 449–450 行），不会随主进程自动启动。 |
| WebShell 管理 | `internal/database/webshell.go` 第 16、136 行；`internal/handler/webshell.go` | 连接口令写入 SQLite。API 列表会打码（`internal/handler/config_secrets.go` 第 12 行的 `********` 同样用于 webshell 掩码逻辑）。 |
| 一键自更新 | `internal/update/update.go` 第 38–41、57–86 行 | 默认拉取 `https://github.com/AIPentest/CyberStrikeAI.git`，然后构建并替换本机二进制。拒绝 `ext::`（该协议会让 git 执行命令）。允许 `http`、`https`、`ssh`、`git`、`file` 和本机绝对路径。 |
| 公共 DNSLog | `tools/dnslog.yaml` 第 5 行（嵌入的 Python 字符串） | `base_url = "http://dnslog.cn"`。工具 `enabled: true`。只有被调用时才访问该站，启动时不会自动访问。查询内容会离开本机，交给 dnslog.cn 的运营方。 |

`tools/` 下 90 个 YAML 里，78 个 `enabled: true`，12 个 `enabled: false`（含 fscan、FOFA、Shodan、Quake、ZoomEye、VirusTotal、ZAP、Clair、feroxbuster、gobuster、lightx、pacu）。Metasploit、msfvenom、nmap、sqlmap、hydra、impacket、linpeas 等配方是启用的。它们调用本机已安装的命令，仓库本身不附带这些工具的二进制。

`skills/` 与 `knowledge_base/` 是给模型读的攻防说明，启动时不会执行。其中 `skills/proxy-tool-bootstrap/SKILL.md`、`skills/attack-surface-recon/SKILL.md`、`skills/component-vuln-intel/SKILL.md` 指导模型用 curl 访问 ip-api、ProxyScrape、crt.sh、GitHub 等。那是运行时、经 `exec` 才会发生的出站，不是安装器后门。

`mcp-servers/pent_claude_agent/.claude/skills/find-skills/SKILL.md` 第 27–29 行建议 `npx skills add`。该目录不在默认 `skills_dir: skills`（`config.example.yaml` 第 583 行）里。主程序是否会加载它：未确认。`mcp_pent_claude_agent.py` 第 50–54 行把 Claude 侧遥测环境变量设为关闭，这是在减少出站，不是增加上报。

### 1.3 压缩前端库

`web/static/vendor/` 中的 `marked.min.js`、`purify.min.js`、`xterm.js`、`xlsx.full.min.js`、`cytoscape.min.js`、`elk.bundled.js`、`i18next.min.js` 文件头分别对应 marked、DOMPurify、xterm、SheetJS、cytoscape、elk、i18next。未与上游发行包做逐字节比对，是否被篡改：未确认。页面 Markdown 走 `web/static/js/sanitize-markdown.js`，在 DOMPurify 存在时消毒；库缺失时降级为转义纯文本（同文件第 163–164 行）。

### 1.4 认证与密钥处理里没有硬编码后门口令

- 首次启动若还没有管理员口令，会生成 24 位随机口令并 bcrypt 存储（`internal/security/auth_manager.go` 第 57–88 行；`internal/security/rbac.go` 第 90–99 行）。没有写死的默认口令。
- 该口令打印到标准输出一次（`internal/termout/startup.go` 第 98–113 行）。若 stdout 进了 journal 或部署日志，口令会留下。
- `VerifyPasswordHash` 仍接受 `sha256$<salt>$<hash>`（`internal/security/rbac.go` 第 102–119 行）。仓库里没有这种预置哈希。它是旧格式校验，不是后门账号。
- 登录接口有每 IP 每分钟 10 次的限制（`internal/app/app.go` 第 968–970 行）。业务 API 在 `AuthMiddleware` 之后（同文件第 991–992 行）。Gin 为 Release 模式（同文件第 90 行）。
- 配置接口对 `api_key`、`password`、`token`、`secret` 等字段返回掩码（`internal/handler/config_secrets.go` 第 14–19、56–59 行）。`config.example.yaml` 里的 `sk-xxxxxxx` 是占位符，不是可用密钥。
- 会话令牌只放进程内存（`internal/security/auth_manager.go` 第 39 行），浏览器另把令牌写入 `localStorage` 键 `cyberstrike-auth`（`web/static/js/auth.js` 第 20–32 行）。进程重启后服务端会话失效，但浏览器里的副本还在。若页面出现 XSS，令牌可被同站脚本读走。本次未确认存在可利用的 XSS。
- 机器人回调 `/api/robot/wecom|dingtalk|lark` 不走登录中间件（`internal/app/app.go` 第 979–989 行）。示例配置里这些机器人均为 `enabled: false`。企业微信启用后会验签（`internal/handler/robot.go` 第 1413–1433、1570–1591 行）。钉钉与飞书回调在启用后基本是占位：钉钉直接返回 200（第 1952–1958 行），飞书在带 `challenge` 时回显（第 1964–1976 行）。默认关闭，因此不是开机后门；一旦打开，这两个回调的鉴权强度未确认。

## 2. 危险能力与默认配置

示例配置是实验室按 README / `run.sh` 部署时会落到磁盘的那一份（`run.sh` 第 429–431 行说明由服务在首次启动时从 `config.example.yaml` 生成 `config.yaml`）。代码里的 `Default()` 更严一点，但正常部署走示例文件。

### 2.1 网络与传输

- 监听 `0.0.0.0:8080`（`config.example.yaml` 第 17–18 行；代码默认相同，`internal/config/config.go` 第 2375–2377 行）。同一端口上的控制台可以执行命令、管 WebShell 和 C2。
- 示例默认打开 TLS，并使用内存自签证书（`config.example.yaml` 第 25–32 行）。浏览器会告警。在共享网络上，用户若习惯性接受证书，无法区分中间人。`run.sh` 默认还向进程传 `--https`（第 485–489 行）；`--http` 会改走明文。
- 内置 MCP HTTP 默认关闭，且绑定 `127.0.0.1:8081`（`config.example.yaml` 第 441–447 行）。`allow_global_access` 默认 false。
- 静态页面 `/`、`/static`、`/api-docs` 不需登录（`internal/app/app.go` 第 1488–1502 行）。API 规范 `/api/openapi/spec` 需要登录（第 1484–1485 行）。

### 2.2 模型输出的执行边界

没有“模型只能建议、人来执行”的默认边界。

- `hitl.default_mode: off`（`config.example.yaml` 第 203–205 行）。新建会话不审批工具调用。
- 调用拦截默认只拦政府域名（`internal/toolguard/toolguard.go` 第 60–72 行；`internal/config/tool_guard.go` 第 11–17 行；示例第 188–197 行）。不拦内网、云元数据地址或任意命令。
- 进程隔离示例为 `mode: auto` 且 `cgroup_root` 为空（`config.example.yaml` 第 424–426 行）。Linux 上 cgroup 根为空时退回进程组和 watchdog，不施加内存 / PID / CPU 上限，也不切断网络或文件系统（`internal/processguard/platform_linux.go` 第 155–160 行）。这不是沙箱。
- 工具子进程继承服务进程的全部环境变量（`internal/security/executor.go` 第 1258–1265 行）。模型只要让 `exec` 运行 `env` 或读 `config.yaml`，就能拿到 API Key、机器人令牌和云凭证，并随对话发到已配置的模型服务商。
- 工具失败时，完整输出以 Error 记入日志（`internal/security/executor.go` 第 250–254 行）；成功时在 Debug 级别记录完整输出（第 267–269 行）。输出里的口令、令牌、目标数据会进日志。企业微信回调在 Debug 级别记录原始 body（`internal/handler/robot.go` 第 1568 行）。
- 示例把单任务超时设为 600 分钟、最大迭代 12000、单次工具 60 分钟（`config.example.yaml` 第 173–175 行）。模型可以长时间占用进程。代码内置默认是 30 次迭代和 10 分钟工具超时（`internal/config/config.go` 第 2402–2404 行），部署若采用示例文件则不是这组更小的值。

### 2.3 C2

`c2.enabled: true`（`config.example.yaml` 第 451–453 行）。配置段省略时，代码也默认启用（`internal/config/config.go` 第 2475–2486 行）。启用后注册 C2 工具，并在启动时恢复数据库里状态为 `running` 的监听器（`internal/app/c2_lifecycle.go` 第 21–53 行；`internal/c2/manager.go` 第 327–343 行）。

全新空库不会凭空打开监听端口。已有数据目录、且上次监听器标记为 running 时，重启会重新绑定。监听地址由操作员或模型指定；绑定 `0.0.0.0` 时，回连地址取第一块非回环网卡地址，不向公网 IP 查询服务发请求（`internal/c2/payload_builder.go` 第 294–316 行）。

反向 shell MCP 里用 UDP 连接 `8.8.8.8:80` 只为读取本机出口地址，不发送应用数据（`mcp_reverse_shell.py` 第 44–51 行）。该进程默认不启动。

### 2.4 浏览器插件

`plugins/browser-extension/cyberstrikeai-browser-extension/manifest.json` 第 4–8 行：权限是 `storage`，主机权限是可选的 `http://*/*` 与 `https://*/*`。用途是把当前浏览器的 HTTP 流量发给操作员自己的 CyberStrikeAI。它不会随服务端启动安装。装进日常使用的浏览器，等于把浏览流量交给这个控制台。

## 3. 依赖与供应链

本节列出部署或可选构建时会拉取的对象。查询日期 2026-11-09。OSV 按“该版本是否落在公告范围内”返回结果，不表示本仓库一定调用了受影响函数。调用点未逐个确认的，标为未确认。

### 3.1 会拉取什么

| 类别 | 是否存在 | 锁定与校验 |
|---|---|---|
| Go 模块 | `go.mod` / `go.sum`。`go 1.25.0`。直接依赖 38 个，加上间接共 140 个选定版本 | 版本写在 `go.mod`。除被 replace 掉的钉钉 SDK 外，选定版本都有 `go.sum` 的 `h1:`。Go 模块没有 npm 式 postinstall |
| Python | 根目录 `requirements.txt`。无 `poetry.lock` / `uv.lock` / `Pipfile.lock` | 只有下界（`chardet` 另有 `<6`）。无 hash。安装时解析到的具体版本会变 |
| 容器 | 无 Dockerfile、无 docker-compose、无预构建应用镜像 | 不适用。CI 另有一处 Debian 镜像，见 3.7 |
| git submodule | 无 `.gitmodules` | 不适用 |
| 仓库内二进制 | 无 exe、jar、so、zip 形式的预编译程序 | 不适用 |
| 可选 Java | Burp 插件 `pom.xml`、`build.gradle` | 版本号有，无 lockfile，无 jar digest |
| 前端压缩库 | `web/static/vendor/` 已随仓库提交 | 无 SRI，无与上游的校验记录 |
| 安装脚本下载 | `run.sh`、`upgrade.sh`、Burp 的 `build-mvn.sh`、`scripts/test-plugin-auth.sh` | 见 3.6。除 Go 的 sumdb 机制外，这些下载没有脚本内校验和 |

`go mod download` 实际解析结果未在本机执行，上表以 `go.mod` 的 require 为准。`go.sum` 里还有未选中的旧版本行（例如 `github.com/meguminnnnnnnnn/go-openai v0.1.2` 与选定的 `v0.1.6` 并存）。那些旧行不应当被当成“再下一份副本”，但是否被模块图额外下载：未运行 `go list -m all`，标为未确认。

### 3.2 安装器改写的下载源

`run.sh` 第 25–26 行把本次进程的默认源设为：

- `PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple`
- `GOPROXY=https://goproxy.cn,direct`

第 190、199、273–274 行把这两个值传给 `pip install` 和 `go mod download` / `go build`。脚本不修改 `GOSUMDB`。官方 sumdb 仍是默认的 `sum.golang.org`，除非运行环境已经关掉它。环境是否关掉：未确认。

含义：

- Go：在 sumdb 未关闭时，镜像或 `direct` 回源返回的内容必须对上 `go.sum` 的 `h1`，否则构建失败。镜像不能悄悄换包。风险是代理不可用、以及有人在环境里设置 `GOSUMDB=off`。
- Python：没有 hash。镜像或公共 PyPI 返回什么，pip 就装什么。这是本仓库供应链里最弱的一环。

`go.mod` 第 3 行注释也建议 `GOPROXY=https://goproxy.cn,direct`。那只是注释，不会单独生效。

### 3.3 replace 与个人仓库模块

`go.mod` 第 155 行：

```text
replace github.com/open-dingtalk/dingtalk-stream-sdk-go => github.com/uouuou/dingtalk-stream-sdk-go v0.0.0-20250626025113-079132acc406
```

`go.sum` 第 394–395 行有该伪版本的 `h1`。官方模块路径 `v0.9.1` 没有对应 `h1`，构建不会按 `v0.9.1` 拉取。

公开元数据：`uouuou/dingtalk-stream-sdk-go` 是 `open-dingtalk/dingtalk-stream-sdk-go` 的 fork，0 star，最后推送 2025-06-26。提交 `079132acc406` 的说明是连接断开时的 panic 恢复，只改 `client/client.go`。同一 SHA 在官方仓库 `open-dingtalk/dingtalk-stream-sdk-go` 也能查到。SHA 相同表示该提交的树相同。因此这一替换在该提交上不是未知篡改。剩余风险是模块路径挂在个人账号上：账号或仓库被删后，只能依赖代理缓存；以后若有人改 `go.sum`，校验基线会跟着变。

`github.com/meguminnnnnnnnn/go-openai v0.1.6`（`go.mod` 第 108 行，间接）是 `sashabaranov/go-openai` 的 fork。上游没有 `v0.1.6` 这个 tag。该 tag 指向 `a92c8d868a5db59bb6e0e40a2230c417edb1bd04`（2026-09-24，合并说明为暴露 cache write token，文件为 `chat_test.go`、`common.go`、`reasoning_validator.go`）。本仓库 `internal/openai/eino_sse_sanitizer.go` 第 3–9 行说明 Eino 经 `eino-ext` 使用这个 SDK。OSV 对该版本无记录。与上游的完整差异是否含恶意逻辑：未逐文件确认。`go.sum` 有 `h1`，内容被锁定，但不能说明锁定的内容本身无害。

其余模块路径与常见上游一致，未发现 `reqeusts` 这类明显仿冒名。Python 包名与 PyPI 上的正式项目对应，见 3.5。

### 3.4 Go 模块与 OSV

140 个选定版本均已向 `https://api.osv.dev/v1/querybatch` 查询。127 个返回空结果。有记录的 13 个如下。编号同时包含 GHSA 与 Go 漏洞库别名时，GHSA 是主编号。

**与本服务直接相关、建议优先处理**

- `github.com/modelcontextprotocol/go-sdk v1.3.1`（直接依赖，MCP 服务端）
  - `GHSA-89xv-2j6f-qhc8`：未做授权的 HTTP 服务端存在跨站工具调用（需用户交互）。
  - `GHSA-q382-vc8q-7jhj`：JSON 解析对空字符处理不当。
  - `GHSA-xw59-hvm2-8pj6`：本机 HTTP 服务的 DNS rebinding 防护默认关闭。
  - 别名：`GO-2026-4770`、`GO-2026-4773`、`GO-2026-5771`。
  - 本仓库把 MCP HTTP 默认绑在 127.0.0.1 且默认关闭，能降低 rebinding 的暴露面。HTTP 模式若改成对外监听，这些公告就直接落在默认传输上。工具是否走到公告里的具体函数：未确认。
- `golang.org/x/crypto v0.50.0`（直接依赖；本仓库用它做 bcrypt）
  - GHSA：`GHSA-45gg-vh54-h5m9`、`GHSA-5cgq-3rg8-m6cv`、`GHSA-78mq-xcr3-xm33`、`GHSA-89gr-r52h-f8rx`、`GHSA-9m57-25v3-79x9`、`GHSA-f5wc-c3c7-36mc`、`GHSA-jppx-rxg9-jmrx`、`GHSA-q4h4-gmj2-qvw2`、`GHSA-qpw4-5x99-6vjp`、`GHSA-rm3j-f69w-wqmq`、`GHSA-vgwf-h737-ff37`、`GHSA-w879-237q-wc7r`、`GHSA-x527-x647-q7gg`。
  - 摘要集中在 SSH / FIDO / invoking 的认证绕过、拒绝服务和权限检查。bcrypt 子包是否受影响：未确认。
  - Go 漏洞库别名：`GO-2026-5005`、`GO-2026-5006`、`GO-2026-5013`、`GO-2026-5014`、`GO-2026-5015`、`GO-2026-5016`、`GO-2026-5017`、`GO-2026-5018`、`GO-2026-5019`、`GO-2026-5020`、`GO-2026-5021`、`GO-2026-5023`、`GO-2026-5033`、`GO-2026-5932`、`GO-2026-6303`、`GO-2026-6354`、`GO-2026-6355`。
- `golang.org/x/net v0.53.0`
  - `GHSA-5cv4-jp36-h3mw`：HTML 解析器拒绝服务。
  - 别名及同模块其他编号：`GO-2026-5025`、`GO-2026-5026`、`GO-2026-5027`、`GO-2026-5028`、`GO-2026-5029`、`GO-2026-5030`、`GO-2026-5942`、`GO-2026-6603`、`GO-2026-6610`、`GO-2026-6611`、`GO-2026-6612`、`GO-2026-6617`、`GO-2026-6860`、`GO-2026-6866`。
  - 是否解析不可信 HTML：未确认。
- `golang.org/x/text v0.37.0`：`GO-2026-5970`（非法输入死循环）、`GO-2026-6629`（`secure/precis` 解析 panic）。调用点未确认。

**OpenTelemetry（默认不导出；示例里的 endpoint 是本机）**

- `go.opentelemetry.io/otel v1.39.0`：`GHSA-mh2q-q3fh-2475` / `GO-2026-5506`，baggage 头导致过量分配，远程可放大的拒绝服务。
- `go.opentelemetry.io/otel/sdk v1.39.0`：`GHSA-8wmf-6v46-5gfg`（导出配置日志可能写下 endpoint URL）、`GHSA-9h8m-3fm2-qjrq` 与 `GHSA-hfvc-g4fc-pqhx`（本地 PATH 劫持导致代码执行，前提是攻击者能影响本机 PATH）、别名 `GO-2026-4394`、`GO-2026-5426`、`GO-2026-6505`。
- `otlptracehttp v1.34.0` 与间接的 `otlptrace v1.34.0`：`GHSA-8wmf-6v46-5gfg`、`GHSA-w8rr-5gcm-pp58`（OTLP HTTP 响应体无上限，可拒绝服务），别名 `GO-2026-4985`、`GO-2026-6505`。

**其余有记录的模块**

- `github.com/disintegration/imaging v1.6.2`：`GHSA-q7pp-wcgr-pffx`，畸形 TIFF 可导致崩溃。严重性在 OSV 中为 LOW。是否用该库解码用户上传的 TIFF：未确认。
- `golang.org/x/image v0.0.0-20191009234506-e7c1f5e7dbb8`（间接，版本停在 2019）：TIFF / 图像资源耗尽。GHSA：`GHSA-44p7-9xx4-hf2g`、`GHSA-9phm-fm57-rhg8`、`GHSA-j3p8-6mrq-6g7h`、`GHSA-q675-qj96-32m9`、`GHSA-qgc7-mgm3-q253`、`GHSA-x92r-3vfx-4cv3`。另有 `GO-2023-1572`、`GO-2023-1989`、`GO-2023-1990`、`GO-2024-2937`、`GO-2026-4815`、`GO-2026-4961`、`GO-2026-4962`、`GO-2026-5031`、`GO-2026-5032`、`GO-2026-5061`、`GO-2026-5062`、`GO-2026-5066`、`GO-2026-6222`。
- `github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.3`（间接）：`GHSA-xmrv-pmrh-hhx2` / `GO-2026-5764`，解码 panic 导致拒绝服务。本服务是否处理不可信 AWS event stream：未确认。
- `golang.org/x/sys v0.43.0`（间接）：`GO-2026-5024`，Windows 上 `NewNTUnicodeString` 整数溢出。Linux 实验室不受该函数影响；Windows 部署是否调用它：未确认。
- `google.golang.org/grpc v1.79.3`（间接）：`GHSA-2v4p-qf9q-27wj`、`GHSA-hrxh-6v49-42gf`、`GHSA-qc2q-p7wx-3px3`、`GHSA-vp52-pcj8-j9qc`，均为 xDS / HTTP/2 拒绝服务或 RBAC 绕过。别名 `GO-2026-6061`、`GO-2026-6348`、`GO-2026-6441`、`GO-2026-6443`。主服务对外协议是 Gin HTTP，不是 gRPC 监听。是否另有 gRPC 服务端：未确认。

`github.com/gin-gonic/gin v1.9.1`、`github.com/mattn/go-sqlite3 v1.14.18` 在这次查询中无 OSV 记录。

完整 140 行清单见附录 A。

### 3.5 Python

`requirements.txt` 全文只有下界，没有 lock，没有 `--hash`。下表的“最新版”是 2026-11-09 PyPI JSON 的 `info.version`。`run.sh` 会安装当时索引上满足约束的版本，不一定是下界，也不保证是表中的最新版。安装脚本（setup.py / 任意代码）未下载，是否含恶意安装钩子：未确认。包名与 PyPI 项目主页一致，未见仿冒名。

| 包 | 约束 | 查询时最新版 | 主页 / 作者 | OSV |
|---|---|---|---|---|
| requests | `>=2.32.3` | 2.34.2 | psf/requests | 下界 2.32.3：`GHSA-9hjg-9r4m-mvj7`（恶意 URL 导致 `.netrc` 泄露）、`GHSA-gc5v-m9x4-r6x2`（`extract_zipped_paths` 临时文件重用）。别名 `PYSEC-2026-1872`、`PYSEC-2026-2275`。最新 2.34.2：无记录 |
| httpx | `>=0.27.0`，extra `http2` | 0.28.1 | encode/httpx | 下界与最新均无记录。extra 会再拉 `h2`（`>=3,<5`），该传递依赖未单独锁定，OSV 未查 |
| charset-normalizer | `>=3.3.2` | 3.5.2 | PyPI 项目 | 下界与最新均无记录 |
| chardet | `>=5.2.0,<6` | 7.7.0（被 `<6` 排除） | chardet/chardet | 5.2.0 无记录。约束内最高发布版也是 5.2.0 |
| arjun | `>=2.2.0` | 2.2.7 | s0md3v/Arjun，作者 Somdev Sangwan | 下界与最新均无记录 |
| uro | `>=1.0.2` | 1.0.2 | s0md3v/uro | 无记录 |
| bloodhound | `>=1.6.1` | 1.9.0 | dirkjanm/bloodhound.py | 下界与最新均无记录 |
| impacket | `>=0.11.0` | 0.13.1 | SecureAuth / Fortra 的协议库 | 下界与最新均无记录 |
| mcp | `>=1.0.0` | 2.3.0 | modelcontextprotocol.io，LF 项目 | 下界 1.0.0 有记录；最新 2.3.0 无记录 |

`mcp` 1.0.0 的公告：

- `GHSA-3qhf-m339-9g5v`：FastMCP 校验错误导致拒绝服务。
- `GHSA-9h52-p55h-vw2f`：DNS rebinding 防护默认关闭。
- `GHSA-j975-95f5-7wqh`：Streamable HTTP 未处理异常导致拒绝服务。
- `GHSA-jpw9-pfvf-9f58`：HTTP 传输未核对已认证主体。
- `GHSA-vj7q-gjh5-988w`：WebSocket 传输无 Host/Origin 校验。
- 别名：`PYSEC-2026-1616`、`PYSEC-2026-1617`、`PYSEC-2026-1618`、`PYSEC-2026-3482`、`PYSEC-2026-3483`。

因为约束是 `>=1.0.0`，一次“幸运”的安装可能拿到已修复的 2.3.0，一次被固定或镜像滞后的安装也可能仍是有公告的旧版。两种结果本次都没有安装验证。

`mcp-servers/pent_claude_agent` 文档另要求 `claude-agent-sdk` 和 `pyyaml`，它们不在 `requirements.txt`，不会被 `run.sh` 自动安装。

运行中的 `install-python-package` 工具可以从模型给出的包名直接 `pip install`，且不使用 hash。这是第二条供应链入口，比根目录 requirements 更宽。

### 3.6 脚本与可选插件会下载的文件

| 来源 | 下载对象 | 版本锁定 | 校验和 | 触发条件 |
|---|---|---|---|---|
| `run.sh` 第 190–199、273–274 行 | PyPI 镜像上的 requirements；Go 模块 | Python 不锁定；Go 由 go.mod/go.sum 锁定 | Python 无；Go 依赖 sumdb + `h1` | 执行 `./run.sh` |
| `upgrade.sh` 第 47、110–126、685 行 | `https://github.com/${GITHUB_REPO}/archive/refs/tags/${TAG}.tar.gz`，默认仓库 `AIPentest/CyberStrikeAI`，tag 默认最新 Release | 仓库名有格式校验；tag 可变 | 脚本内无 sha256 / 签名校验 | 目录不是 git 工作树时走 Release 包。git 克隆走另一条更新逻辑 |
| `plugins/burp-suite/cyberstrikeai-burp-extension/build-mvn.sh` 第 13–32、40–41 行 | `https://archive.apache.org/dist/maven/maven-3/3.9.6/binaries/apache-maven-3.9.6-bin.tar.gz`，然后 Maven Central | Maven 3.9.6 锁定 | 无校验和、无签名检查 | 本机没有 `mvn` 且选择该脚本 |
| `plugins/burp-suite/.../build.gradle` 第 15–24 行 | Maven Central：`burp-extender-api:2.3`、`jackson-databind:2.17.2`、Gradle Shadow 插件 `com.github.johnrengelman.shadow:8.1.1` | 版本号固定，无 Gradle lock | 无仓库内 digest | 选择 Gradle 构建 |
| `pom.xml` 第 17–24、28–31 行 | `burp-extender-api:2.3`（provided）、`maven-jar-plugin:3.4.2` | 版本固定 | 无仓库内 digest | 选择 Maven 构建 |
| `scripts/test-plugin-auth.sh` 第 11 行 | `https://repo.maven.apache.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar` | 2.3 锁定 | 无校验和 | 手动或 CI 跑该脚本 |
| `build.sh` | 不下载，要求本地已有 `lib/burp-extender-api.jar` | — | — | 手动 |
| `package.sh` | 只在本地打 zip | — | — | 手动 |

OSV / Maven 生态查询：

- `com.fasterxml.jackson.core:jackson-databind:2.17.2` 有记录：`GHSA-3pjw-73gf-8qr5`、`GHSA-5gvw-p9qm-jgwh`、`GHSA-5jmj-h7xm-6q6v`、`GHSA-cxp5-3px4-pw24`、`GHSA-gx83-3vf8-gh7j`、`GHSA-hgj6-7826-r7m5`（反序列化 `InetSocketAddress` 会做 DNS，SSRF）、`GHSA-j3rv-43j4-c7qm`（多态类型校验可被绕过并实例化任意类）、`GHSA-q4xh-88c3-wmh7`、`GHSA-rmj7-2vxq-3g9f`、`GHSA-vvgp-rfg2-7rr6`、`GHSA-wjgm-6hv5-3cvf`、`GHSA-wv8q-qhhj-9h54`。主 Go 服务不依赖 Jackson。插件是否启用 default typing 或相关反序列化：未确认。
- `burp-extender-api:2.3`、`apache-maven:3.9.6`、`maven-jar-plugin:3.4.2`：本次查询无记录。Shadow 插件未用 Maven 坐标查询，OSV 状态未确认。

这些 Java 依赖只在有人构建 Burp 插件时出现，不是 `run.sh` 的一部分。

### 3.7 仅 CI 会拉的对象

实验室按 README 部署不会走这些步骤。它们仍是仓库会触发的拉取。

- `.github/workflows/self-update.yml` 第 19–24 行、`plugin-auth.yml` 第 20–24 行、`process-isolation.yml` 第 16–17 行：`actions/checkout@v4`、`actions/setup-go@v5`、`actions/setup-node@v4`、`actions/setup-java@v4`。标签会移动，不是 commit SHA，也没有动作 digest。
- `process-isolation.yml` 第 34–36 行：`debian:bookworm-slim`，无镜像 digest。作业以 `--privileged` 运行该容器；同时 `--network none`。仅在该 workflow 的 Linux job 中出现。

### 3.8 拉取建议

1. Go 保持 `GOSUMDB=sum.golang.org`。需要镜像时使用 `GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct` 这类仍会校验 `h1` 的配置，不要 `GOSUMDB=off`。更好的做法是在可联网的构建机生成 `vendor/` 或模块缓存，实验室离线构建。
2. 不要用 `run.sh` 的默认 pip 镜像直接装。把 `requirements.txt` 收成带 `--hash` 的 lock，或自建只读 wheelhouse。在修到无 OSV 记录之前，至少把 `requests` 指到 2.34.2（或更新的无公告版本），把 `mcp` 指到 2.3.0（或更新的无公告版本），并锁死 `httpx`、`h2`、`impacket`、`bloodhound`、`arjun`。
3. 升级或替换有 OSV 记录的 Go 模块后再长期运行，优先 `modelcontextprotocol/go-sdk`、`golang.org/x/crypto`、`golang.org/x/net`、`golang.org/x/image`、OpenTelemetry 导出器、`google.golang.org/grpc`。升级本身不在本次变更里。
4. 钉钉 SDK 的 replace 若只为了那个 panic 修复，跟踪官方仓库里已经包含 `079132acc406` 的正式版本，然后去掉个人模块路径。在此之前保留现有 `h1`，不要手改伪版本。
5. `meguminnnnnnnnn/go-openai` 在去掉或换成上游模块之前，把该版本的源码 diff 纳入人工审查。本次只看了提交说明和文件名。
6. `upgrade.sh` 的 Release 包在校验 sha256 之前不要用于生产或共享实验室。git 部署保留上游远程，一键更新默认指向 `AIPentest/CyberStrikeAI`，会覆盖本地未提交改动以外、且不在保护名单里的代码。
7. Maven / Burp API 的 jar 与 Maven 发行包核对 Apache 或 Maven Central 的校验和后再用。不需要插件就不要跑 `build-mvn.sh`。
8. 关闭模型可用的 `install-python-package`，避免对话期间再引入未审查的包。

## 4. 实验室使用前必须做的加固

下列各项都做完，才适合在隔离实验室开机。少做一项，默认配置仍然能让已登录用户或被提示词影响的模型在本机执行命令。

1. 网络隔离。入站只允许实验室管理网；出站只允许选定的模型 API。不要给该主机到生产网、元数据服务和任意互联网的路由。
2. `server.host` 改为 `127.0.0.1` 或管理网卡地址，不要 `0.0.0.0`。用正式证书，或只在本机接受自签证书。不要在共享网段上培训用户点击“仍要继续”。
3. 第一次登录后立刻改掉管理员口令，并清掉含初始口令的 stdout / journal。`config.yaml` 与 `data/` 设为仅运行用户可读。
4. `c2.enabled: false`。不要配置 `mcp-servers/reverse_shell`。不需要 WebShell 时不要使用该功能；口令在 SQLite 里是明文。
5. `hitl.default_mode` 改为 `approval`。`exec`、`execute-python-script`、`install-python-package`、`metasploit`、`msfvenom` 以及任何 shell 类工具不要放进免审批白名单。
6. Linux 上把 `security.process_isolation.mode` 设为 `required`，并配置委托的 `cgroup_root`。`auto` 加空 cgroup 不是沙箱。
7. 服务进程环境里不要放云密钥、GitHub token 或模型密钥。模型可以通过工具读到环境变量。密钥只放 `config.yaml`，并假定模型在开启 `exec` 时仍能读这个文件。
8. 日志级别保持 info 以上，不要为了排障长期开 debug。已知失败的工具输出仍会进 Error 日志，日志系统按机密数据处理。
9. 按 3.8 处理依赖之后再安装。在那之前，这台机器的 Python 与 Go 缓存应视为不可信输入。
10. 关掉控制台一键更新，或把 `update.repo` 固定到已经审查过的只读镜像。不要把 `file://` 指到其他用户可写的目录。
11. 浏览器插件只装在专门的测试浏览器里。
12. 机器人集成保持关闭，直到单独审查钉钉和飞书回调的鉴权。

## 附录 A. go.mod 选定模块

查询日 2026-11-09。`h1` 指 `go.sum` 中是否有该选定版本的哈希行。超过八个公告编号的单元格已截断，完整编号在 3.4。

| 模块 | 版本 | 直接/间接 | go.sum h1 | OSV（2026-11-09） |
|---|---|---|---|---|
| `github.com/bwmarrin/discordgo` | `v0.29.0` | 直接 | 有 | 无记录 |
| `github.com/bytedance/sonic` | `v1.15.0` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino` | `v0.9.21` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/adk/backend/local` | `v0.2.6` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/document/loader/file` | `v0.0.0-20260427010451-749e3706378b` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/document/transformer/splitter/markdown` | `v0.0.0-20260427010451-749e3706378b` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/document/transformer/splitter/recursive` | `v0.0.0-20260427010451-749e3706378b` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/embedding/openai` | `v0.0.0-20260427010451-749e3706378b` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/model/agenticclaude` | `v0.1.7` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/model/agenticopenai` | `v0.2.4` | 直接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/components/model/openai` | `v0.1.13` | 直接 | 有 | 无记录 |
| `github.com/creack/pty` | `v1.1.24` | 直接 | 有 | 无记录 |
| `github.com/disintegration/imaging` | `v1.6.2` | 直接 | 有 | 有记录：GHSA-q7pp-wcgr-pffx |
| `github.com/eino-contrib/jsonschema` | `v1.0.3` | 直接 | 有 | 无记录 |
| `github.com/gin-gonic/gin` | `v1.9.1` | 直接 | 有 | 无记录 |
| `github.com/google/uuid` | `v1.6.0` | 直接 | 有 | 无记录 |
| `github.com/gorilla/websocket` | `v1.5.3` | 直接 | 有 | 无记录 |
| `github.com/larksuite/oapi-sdk-go/v3` | `v3.4.22` | 直接 | 有 | 无记录 |
| `github.com/mattn/go-sqlite3` | `v1.14.18` | 直接 | 有 | 无记录 |
| `github.com/modelcontextprotocol/go-sdk` | `v1.3.1` | 直接 | 有 | 有记录：GHSA-89xv-2j6f-qhc8, GHSA-q382-vc8q-7jhj, GHSA-xw59-hvm2-8pj6, GO-2026-4770, GO-2026-4773, GO-2026-5771 |
| `github.com/open-dingtalk/dingtalk-stream-sdk-go` | `v0.9.1` | 直接 | 否（被 replace，不按此版本拉取） | 无记录 |
| `github.com/pkoukk/tiktoken-go` | `v0.1.8` | 直接 | 有 | 无记录 |
| `github.com/robfig/cron/v3` | `v3.0.1` | 直接 | 有 | 无记录 |
| `github.com/skip2/go-qrcode` | `v0.0.0-20200617195104-da1b6568686e` | 直接 | 有 | 无记录 |
| `github.com/slack-go/slack` | `v0.27.0` | 直接 | 有 | 无记录 |
| `github.com/tencent-connect/botgo` | `v0.2.1` | 直接 | 有 | 无记录 |
| `go.opentelemetry.io/otel` | `v1.39.0` | 直接 | 有 | 有记录：GHSA-mh2q-q3fh-2475, GO-2026-5506 |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` | `v1.34.0` | 直接 | 有 | 有记录：GHSA-8wmf-6v46-5gfg, GHSA-w8rr-5gcm-pp58, GO-2026-4985, GO-2026-6505 |
| `go.opentelemetry.io/otel/exporters/stdout/stdouttrace` | `v1.34.0` | 直接 | 有 | 无记录 |
| `go.opentelemetry.io/otel/sdk` | `v1.39.0` | 直接 | 有 | 有记录：GHSA-8wmf-6v46-5gfg, GHSA-9h8m-3fm2-qjrq, GHSA-hfvc-g4fc-pqhx, GO-2026-4394, GO-2026-5426, GO-2026-6505 |
| `go.opentelemetry.io/otel/trace` | `v1.39.0` | 直接 | 有 | 无记录 |
| `go.uber.org/zap` | `v1.26.0` | 直接 | 有 | 无记录 |
| `golang.org/x/crypto` | `v0.50.0` | 直接 | 有 | 有记录：GHSA-45gg-vh54-h5m9, GHSA-5cgq-3rg8-m6cv, GHSA-78mq-xcr3-xm33, GHSA-89gr-r52h-f8rx, GHSA-9m57-25v3-79x9, GHSA-f5wc-c3c7-36mc, GHSA-jppx-rxg9-jmrx, GHSA-q4h4-gmj2-qvw2 … |
| `golang.org/x/net` | `v0.53.0` | 直接 | 有 | 有记录：GHSA-5cv4-jp36-h3mw, GO-2026-5025, GO-2026-5026, GO-2026-5027, GO-2026-5028, GO-2026-5029, GO-2026-5030, GO-2026-5942 … |
| `golang.org/x/term` | `v0.42.0` | 直接 | 有 | 无记录 |
| `golang.org/x/text` | `v0.37.0` | 直接 | 有 | 有记录：GO-2026-5970, GO-2026-6629 |
| `golang.org/x/time` | `v0.14.0` | 直接 | 有 | 无记录 |
| `gopkg.in/yaml.v3` | `v3.0.1` | 直接 | 有 | 无记录 |
| `cloud.google.com/go/auth` | `v0.7.2` | 间接 | 有 | 无记录 |
| `cloud.google.com/go/auth/oauth2adapt` | `v0.2.3` | 间接 | 有 | 无记录 |
| `cloud.google.com/go/compute/metadata` | `v0.9.0` | 间接 | 有 | 无记录 |
| `github.com/Azure/azure-sdk-for-go/sdk/azcore` | `v1.17.0` | 间接 | 有 | 无记录 |
| `github.com/Azure/azure-sdk-for-go/sdk/internal` | `v1.10.0` | 间接 | 有 | 无记录 |
| `github.com/anthropics/anthropic-sdk-go` | `v1.56.0` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2` | `v1.30.3` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream` | `v1.6.3` | 间接 | 有 | 有记录：GHSA-xmrv-pmrh-hhx2, GO-2026-5764 |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.27.27` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.17.27` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | `v1.16.11` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | `v1.3.15` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | `v2.6.15` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/internal/ini` | `v1.8.0` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | `v1.11.3` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | `v1.11.17` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/service/sso` | `v1.22.4` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | `v1.26.4` | 间接 | 有 | 无记录 |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.30.3` | 间接 | 有 | 无记录 |
| `github.com/aws/smithy-go` | `v1.20.3` | 间接 | 有 | 无记录 |
| `github.com/bahlo/generic-list-go` | `v0.2.0` | 间接 | 有 | 无记录 |
| `github.com/bmatcuk/doublestar/v4` | `v4.10.0` | 间接 | 有 | 无记录 |
| `github.com/buger/jsonparser` | `v1.1.2` | 间接 | 有 | 无记录 |
| `github.com/bytedance/gopkg` | `v0.1.3` | 间接 | 有 | 无记录 |
| `github.com/bytedance/sonic/loader` | `v0.5.0` | 间接 | 有 | 无记录 |
| `github.com/cenkalti/backoff/v4` | `v4.3.0` | 间接 | 有 | 无记录 |
| `github.com/cespare/xxhash/v2` | `v2.3.0` | 间接 | 有 | 无记录 |
| `github.com/cloudwego/base64x` | `v0.1.6` | 间接 | 有 | 无记录 |
| `github.com/cloudwego/eino-ext/libs/acl/openai` | `v0.1.18-0.20260924031408-10df7cac3f6d` | 间接 | 有 | 无记录 |
| `github.com/dlclark/regexp2` | `v1.10.0` | 间接 | 有 | 无记录 |
| `github.com/dustin/go-humanize` | `v1.0.1` | 间接 | 有 | 无记录 |
| `github.com/evanphx/json-patch` | `v0.5.2` | 间接 | 有 | 无记录 |
| `github.com/felixge/httpsnoop` | `v1.0.4` | 间接 | 有 | 无记录 |
| `github.com/gabriel-vasile/mimetype` | `v1.4.2` | 间接 | 有 | 无记录 |
| `github.com/gin-contrib/sse` | `v0.1.0` | 间接 | 有 | 无记录 |
| `github.com/go-logr/logr` | `v1.4.3` | 间接 | 有 | 无记录 |
| `github.com/go-logr/stdr` | `v1.2.2` | 间接 | 有 | 无记录 |
| `github.com/go-playground/locales` | `v0.14.1` | 间接 | 有 | 无记录 |
| `github.com/go-playground/universal-translator` | `v0.18.1` | 间接 | 有 | 无记录 |
| `github.com/go-playground/validator/v10` | `v10.14.0` | 间接 | 有 | 无记录 |
| `github.com/go-resty/resty/v2` | `v2.6.0` | 间接 | 有 | 无记录 |
| `github.com/go-viper/mapstructure/v2` | `v2.5.0` | 间接 | 有 | 无记录 |
| `github.com/goccy/go-json` | `v0.10.2` | 间接 | 有 | 无记录 |
| `github.com/gogo/protobuf` | `v1.3.2` | 间接 | 有 | 无记录 |
| `github.com/golang/groupcache` | `v0.0.0-20210331224755-41bb18bfe9da` | 间接 | 有 | 无记录 |
| `github.com/golang/protobuf` | `v1.5.4` | 间接 | 有 | 无记录 |
| `github.com/google/jsonschema-go` | `v0.4.2` | 间接 | 有 | 无记录 |
| `github.com/google/s2a-go` | `v0.1.7` | 间接 | 有 | 无记录 |
| `github.com/googleapis/enterprise-certificate-proxy` | `v0.3.2` | 间接 | 有 | 无记录 |
| `github.com/goph/emperror` | `v0.17.2` | 间接 | 有 | 无记录 |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | `v2.25.1` | 间接 | 有 | 无记录 |
| `github.com/invopop/jsonschema` | `v0.14.0` | 间接 | 有 | 无记录 |
| `github.com/jolestar/go-commons-pool/v2` | `v2.1.2` | 间接 | 有 | 无记录 |
| `github.com/json-iterator/go` | `v1.1.12` | 间接 | 有 | 无记录 |
| `github.com/klauspost/cpuid/v2` | `v2.2.10` | 间接 | 有 | 无记录 |
| `github.com/klippa-app/go-pdfium` | `v1.19.3` | 间接 | 有 | 无记录 |
| `github.com/leodido/go-urn` | `v1.2.4` | 间接 | 有 | 无记录 |
| `github.com/mailru/easyjson` | `v0.9.0` | 间接 | 有 | 无记录 |
| `github.com/mattn/go-isatty` | `v0.0.19` | 间接 | 有 | 无记录 |
| `github.com/meguminnnnnnnnn/go-openai` | `v0.1.6` | 间接 | 有 | 无记录 |
| `github.com/modern-go/concurrent` | `v0.0.0-20180306012644-bacd9c7ef1dd` | 间接 | 有 | 无记录 |
| `github.com/modern-go/reflect2` | `v1.0.2` | 间接 | 有 | 无记录 |
| `github.com/nikolalohinski/gonja` | `v1.5.3` | 间接 | 有 | 无记录 |
| `github.com/openai/openai-go/v3` | `v3.44.0` | 间接 | 有 | 无记录 |
| `github.com/pb33f/ordered-map/v2` | `v2.3.1` | 间接 | 有 | 无记录 |
| `github.com/pelletier/go-toml/v2` | `v2.2.3` | 间接 | 有 | 无记录 |
| `github.com/pkg/errors` | `v0.9.1` | 间接 | 有 | 无记录 |
| `github.com/segmentio/asm` | `v1.1.3` | 间接 | 有 | 无记录 |
| `github.com/segmentio/encoding` | `v0.5.4` | 间接 | 有 | 无记录 |
| `github.com/sirupsen/logrus` | `v1.9.3` | 间接 | 有 | 无记录 |
| `github.com/slongfield/pyfmt` | `v0.0.0-20220222012616-ea85ff4c361f` | 间接 | 有 | 无记录 |
| `github.com/standard-webhooks/standard-webhooks/libraries` | `v0.0.1` | 间接 | 有 | 无记录 |
| `github.com/tetratelabs/wazero` | `v1.11.0` | 间接 | 有 | 无记录 |
| `github.com/tidwall/gjson` | `v1.18.0` | 间接 | 有 | 无记录 |
| `github.com/tidwall/match` | `v1.1.1` | 间接 | 有 | 无记录 |
| `github.com/tidwall/pretty` | `v1.2.1` | 间接 | 有 | 无记录 |
| `github.com/tidwall/sjson` | `v1.2.5` | 间接 | 有 | 无记录 |
| `github.com/twitchyliquid64/golang-asm` | `v0.15.1` | 间接 | 有 | 无记录 |
| `github.com/ugorji/go/codec` | `v1.2.11` | 间接 | 有 | 无记录 |
| `github.com/wk8/go-ordered-map/v2` | `v2.1.8` | 间接 | 有 | 无记录 |
| `github.com/yargevad/filepathx` | `v1.0.0` | 间接 | 有 | 无记录 |
| `github.com/yosida95/uritemplate/v3` | `v3.0.2` | 间接 | 有 | 无记录 |
| `go.opencensus.io` | `v0.24.0` | 间接 | 有 | 无记录 |
| `go.opentelemetry.io/auto/sdk` | `v1.2.1` | 间接 | 有 | 无记录 |
| `go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc` | `v0.49.0` | 间接 | 有 | 无记录 |
| `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` | `v0.49.0` | 间接 | 有 | 无记录 |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace` | `v1.34.0` | 间接 | 有 | 有记录：GHSA-8wmf-6v46-5gfg, GO-2026-6505 |
| `go.opentelemetry.io/otel/metric` | `v1.39.0` | 间接 | 有 | 无记录 |
| `go.opentelemetry.io/proto/otlp` | `v1.5.0` | 间接 | 有 | 无记录 |
| `go.uber.org/multierr` | `v1.11.0` | 间接 | 有 | 无记录 |
| `go.yaml.in/yaml/v4` | `v4.0.0-rc.2` | 间接 | 有 | 无记录 |
| `golang.org/x/arch` | `v0.15.0` | 间接 | 有 | 无记录 |
| `golang.org/x/exp` | `v0.0.0-20250305212735-054e65f0b394` | 间接 | 有 | 无记录 |
| `golang.org/x/image` | `v0.0.0-20191009234506-e7c1f5e7dbb8` | 间接 | 有 | 有记录：GHSA-44p7-9xx4-hf2g, GHSA-9phm-fm57-rhg8, GHSA-j3p8-6mrq-6g7h, GHSA-q675-qj96-32m9, GHSA-qgc7-mgm3-q253, GHSA-x92r-3vfx-4cv3, GO-2023-1572, GO-2023-1989 … |
| `golang.org/x/oauth2` | `v0.34.0` | 间接 | 有 | 无记录 |
| `golang.org/x/sync` | `v0.20.0` | 间接 | 有 | 无记录 |
| `golang.org/x/sys` | `v0.43.0` | 间接 | 有 | 有记录：GO-2026-5024 |
| `google.golang.org/api` | `v0.189.0` | 间接 | 有 | 无记录 |
| `google.golang.org/genproto/googleapis/api` | `v0.0.0-20251202230838-ff82c1b0f217` | 间接 | 有 | 无记录 |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20251202230838-ff82c1b0f217` | 间接 | 有 | 无记录 |
| `google.golang.org/grpc` | `v1.79.3` | 间接 | 有 | 有记录：GHSA-2v4p-qf9q-27wj, GHSA-hrxh-6v49-42gf, GHSA-qc2q-p7wx-3px3, GHSA-vp52-pcj8-j9qc, GO-2026-6061, GO-2026-6348, GO-2026-6441, GO-2026-6443 |
| `google.golang.org/protobuf` | `v1.36.10` | 间接 | 有 | 无记录 |
