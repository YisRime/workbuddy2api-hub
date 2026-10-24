# 风控差异清单 · hub 出站请求 vs 官方客户端(2026-10-24 实测版)

> 目标:回答「hub 与原始客户端的请求哪里不同,哪些不同会导致账号风控」。
> hub 侧证据来自当前主线代码逐行核对(chat 链路的 wire 头 = `Account.headers()`
> 全量 + `Connection: keep-alive`,见 `wb_upstream_pool._request_headers` 的
> 保真路径);客户端侧证据来自 **2026-10-24 16:28 整轮真实对话的 mitmproxy
> 实测**(`capture/lifecycle.jsonl` 640 行之后,下文引用格式 `cap:行号`),
> 以及 5.8.4 抓包与 asar/npm 解包的历史结论。
> 结论按「最可能导致风控」排序,每条给出两侧证据与处置建议。

---

## 〇、一句话结论(2026-10-24 实测后)

本轮实测把「头族形态」从代码推断变成了逐头证据:**桌面主对话的真实发送方是
OpenAI Node SDK(undici),一个浏览器头都不带,但带全套 x-stainless-\* 指纹、
acp-connection-id、gzip 压缩的请求体和 Accept-Encoding**;hub 的桌面身份头族
恰好是另一条链路(内嵌 web 聊天,copilot.tencent.com)的形态——多发 3 个浏览器
头、少发约 11 个 SDK 头、Accept 值不同、body 不压缩,逐请求可指纹的偏差比
之前认为的更大。跨请求维度的三大差异(同 IP 多号、重试扇出、极薄活性面)
不变,仍是最高优先级。

同时修正三处旧结论(细节见 §五):

1. **桌面主对话确实带 `X-Agent-Type: main`**(旧 §7 撤销,hub 现状是对的);
2. **www.workbuddy.ai 域的桌面 chat 实测带 `X-Device-Token: v3:…`**(TuringShield,
   旧「国际版不发」按解包推断的结论与 wire 相悖);
3. **桌面端 chat body 确认 gzip**(160490 字节 JSON → 55912 字节 wire,
   `Content-Encoding: gzip`),旧 §6 的「待确认」落地。

---

## 一、差异总表(按风控相关度排序)

| # | 差异 | hub 现状 | 客户端实测(cap:行号) | 风控相关度 |
|---|---|---|---|---|
| 1 | 同 IP 多账号 | 默认全部账号共用一个出口 IP(per-account proxy 可选) | 一人一设备一号一 IP | **高** |
| 2 | CN 版 X-Device-Token;国际版实测也带 | 配置了 `device_token(_file)` 则所有 CN 账号共用同一个;没配置则整头缺失;国际版一律不发(`wb_accounts.resolve_device_token` + realm 判断) | .ai 域主对话与标题请求都带各自的 `X-Device-Token: v3:AAAA…`(cap:723/727);共用单 token = 号池串成一台设备,缺失 = 形态不符,两头都不对 | **高** |
| 3 | 失败重试换号扇出 | 5xx/401/402/429 把同一请求体秒级重发到下一个账号(`open_upstream` 重试循环;11140 已默认停手) | 不存在:一轮对话固定一个账号 | **高** |
| 4 | chat wire 头族:3 个多余浏览器头 + 9~11 个缺失 SDK 头 | ~~桌面/VSCode 分支发 `Origin`/`Referer`/`Accept-Language`…~~ **已对齐(2026-10-24 第二轮)**:桌面分支删 3 浏览器头、Accept 改 `application/json`、`x-codebuddy-request` 小写、补 x-stainless-\*×7(无 timeout)/`acp-connection-id`/b3 四段父 span,gzip body 见 #6;VSCode 分支无实测未动 | 主对话(cap:727)无 Origin/Referer/Accept-Language,`Accept: application/json`,带 x-stainless-\*×7(无 timeout)、`acp-connection-id`(UUIDv7)、`x-codebuddy-request: 1`(小写)、`Content-Encoding: gzip`、`Accept-Encoding: gzip, compress, deflate, br`、b3 四段 + `X-B3-ParentSpanId`;X-Requested-With 客户端确实发 | **中高**(头族已对齐;剩余见 §六) |
| 5 | 空闲活性面极薄 | 空闲时只有积分刷新/token 保活/签到/daily-chat,无轮询上报 | 10 分钟窗口 300+ 条轮询;**且每轮对话有整套伴随流量**:conversations CRUD、conversation-sync push、cf-publish、/v2/report、/v1/traces、标题生成请求(cap:686-736),hub 一条都没有 | **中** |
| 6 | Accept-Encoding / 桌面端 body 不 gzip | ~~Python http.client 不加 `Accept-Encoding`;gzip 只在 CLI/VSCode 身份开~~ **已对齐**:`_daily_chat_upstream` / `open_upstream` / probe 三处对全部身份 gzip + `Content-Encoding: gzip`;`Accept-Encoding` 请求头暂不发(见 §六) | 桌面 chat body gzip(160490→55912,cap:727);请求带 `Accept-Encoding: gzip, compress, deflate, br` | **中** |
| 7 | 会话 id 不落上游会话库 | ~~hub 本地派生~~ **已对齐(2026-10-24 第三轮)**:桌面身份每会话先 `POST /console/as/conversations/v2` 落库、用返回的云端 UUID 当 X-Conversation-ID,成功后后台发 title/activity PATCH(updatedAtMs 冻结在创建时刻);失败按 TTL 冷却回落派生 id;`wb_settings.cloud_conversations_enabled` 可整体关闭(默认开)。cf-publish(加密)/sync-push/辅助模型标题**不伪造** | 客户端每轮对话先落库拿云端 UUID(cap:686→727),期间 PATCH isPlayground/title/lastActivityAtMs(cap:692/701/724/731),另发 sync-push 与加密 cf-publish | **中→已对齐** |
| 8 | refresh / billing 头族不符 | ~~refresh 发 4 个浏览器头 + 单段 UA;billing 发 Machine/Session-ID + Origin/Referer~~ **国际版已对齐(2026-10-24 第二轮)**:refresh 按 cap:711 的 15 头桌面主组件形态(`_refresh_headers`,UA 三段式);billing 按 cap:715 的 axios 形态(UA `axios/1.16.1`,无 Machine/Session/Origin/Referer);**国内版无实测,维持原样** | refresh 两种形态(cap:66/340/432、cap:711)都无浏览器头,UA 三段式;billing 是 `axios/1.16.1` UA + `Accept-Language: zh`(跟界面语言) | **中** |
| 9 | 版本钉死会漂移 | intl=5.8.4、cn=5.8.3,从不访问 /v2/update | 客户端自动更新(另见 cap:650/740 的内嵌 web 组件还停在 5.8.3) | 低→中 |
| 10 | TLS / 网络栈 | Python + OpenSSL,HTTP/1.1 | Node(undici),同为 HTTP/1.1 | 低(号池长期实证:不是硬门禁) |

已对齐、**不要动**的项(本轮实测逐一验证):identity 常量族(X-IDE-\* /
X-Agent-Intent / X-Agent-Purpose / `X-Agent-Type: main` / X-Private-Data /
X-Product / **UA 三段式逐字符一致**)、id 形态(会话=带连字符 UUID、
X-Request-ID=X-Conversation-Message-ID=32hex UUIDv7、
X-Conversation-Request-ID=X-Root-Request-ID 同值)、trace 头族的键集合、
`X-Requested-With: XMLHttpRequest` 客户端确实发(保留)、CLI 身份的
x-stainless-\*(除 timeout,见 §五)、本地 ACP 头不进上游。

---

## 二、逐条展开

### 1. 同 IP 多账号(最高优先级,不变)

17 个账号全天从同一 IP 发 chat,若还是机房 IP 则更糟。官方模型是
「一个账号 = 一台设备 = 一个出口」。per-account proxy 机制已在
(`Account.proxy` + opener 池 + 住宅/机房标注),但它是可选配置。

**处置**:号池超过个位数就按账号分出口;`wb_ipintel` 把「多号共用机房出口」
标成面板显式告警。用户自己的实证(官方客户端同 IP 一天切多号发言没事)
说明 IP 不是唯一信号,但「同 IP + 头族异常」叠加时风控更快。

### 2. 设备 token:共用或缺失两头都不对(国际版也要发)

`resolve_device_token()` 全局单值,CN 账号共用;国际版按 #448 不发。本轮实测
cap:723/727(.ai 域、intl 头族)主对话与标题请求**都带**
`X-Device-Token: v3:AAAA…`——与解包「二进制里没有构造器」的推断相悖,
按 wire 事实修正:5.8.4 国际版也发 TuringShield token。

**处置**:短期——文档与面板明示「配置单 token = 把号池串成一台设备」;
hub 生成不了真实 v3 token,缺失就是缺失,不要伪造 `v3:` 假值(格式校验
过不了反而更显眼);中期——按账号配置真机抓取的 token,或确认 5.9.x 是否
提供失败态头(本轮没有观测到 `X-Device-Token-Error`)。

### 3. 重试换号的请求体扇出(不变)

`open_upstream` 重试循环把同一 body 秒级扇出给多个账号,prompt 内容本身
成为关联信号。11140 已默认停手,内容扇出是同类风险。

**处置**:「同一请求体跨账号重发」加默认上限(如 2 个账号),超出把错误
交还客户端。

### 4. chat wire 头族:hub 发的是「内嵌 web 聊天」的形态,不是主对话的

实测把旧 §4 的「5 个浏览器头」修正为精确清单。客户端桌面主对话
(cap:727,`X-Agent-Purpose: conversation`)由 OpenAI Node SDK 发出,
43 个头(含传输层);与 hub 桌面分支(34 个)逐头 diff:

- **hub 多发 3 个**:`Origin`、`Referer`、`Accept-Language`——客户端主对话
  一个都不带。它们其实是另一条链路的形态:内嵌 web 聊天
  (`copilot.tencent.com/v2/chat/completions`,cap:650/740)才带
  `Origin: https://www.codebuddy.cn` / `Referer` / `Accept-Language: zh-CN` /
  Title-Case `X-CodeBuddy-Request`。hub 当年的头族抄的是 web 控制台形态。
- **hub 少发约 11 个**:`x-stainless-arch/lang/os/package-version/retry-count/
  runtime/runtime-version`×7(注意**没有** x-stainless-timeout)、
  `acp-connection-id`(UUIDv7,每连接一个)、`Content-Encoding: gzip`、
  `Accept-Encoding: gzip, compress, deflate, br`、`X-B3-ParentSpanId`
  (主对话 b3 是四段 `tid-sid-1-parent`;auxiliary 才是三段,cap:723)。
- **值不同**:`Accept` 客户端就是 `application/json`(SDK 默认),hub 桌面
  分支是 axios 的 `application/json, text/plain, */*`;
  `X-CodeBuddy-Request` 客户端全小写 `x-codebuddy-request`。
- **对齐了**:`X-Requested-With: XMLHttpRequest` 客户端确实发(不要删);
  UA `WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0` 与 hub `desktop_ua()`
  逐字符一致;X-Agent-Type: main 主对话确实带(hub 正确)。

**处置**:桌面身份 chat 头集合按 cap:727 重排——删 Origin/Referer/
Accept-Language,Accept 改 `application/json`,`x-codebuddy-request` 改小写,
补 x-stainless-\*×7(复用 `cli_stainless_headers()` 去掉 timeout)、
acp-connection-id(按连接稳定)、Content-Encoding + gzip、Accept-Encoding、
trace_headers(with_parent=True)。VSCode 分支同法复核。配 fixture 测试钉住
「chat 头集合 ⊆ 官方清单」。实现注意:Python 侧 advertise `br` 就得自己
解 brotli 响应,没有 brotli 依赖时只 advertise `gzip` 是折中(或加依赖)。

### 5. 空闲活性面 + 对话伴随流量

抓包里的桌面端没人说话也在持续轮询(msg-center 25s、feature-flag、/v2/report、
market、conversations 同步)。本轮还看到**每轮对话的整套伴随流量**(cap:686-736):
会话 CRUD、`/console/as/conversation-sync/notify/push`(带 deviceName/locale/
taskTitle)、cf-publish×N、/v2/report×N、/v1/traces×N、标题生成模型请求、
memory/profile 拉取。hub 账号只有光秃秃的一条 chat POST,「会话创建/同步/
上报全没有」本身就是桌面身份不该有的形态。

**处置**:不建议伪造整套轮询;真正值得做的是**节律**(工作时段、每小时上限)。
对话伴随流量里成本最低、信号最强的是 conversations 落库(见 §7),
其余不建议主动伪造。

### 6. Accept-Encoding / gzip(已确认)

桌面 chat body 实测 gzip:160490 字节 JSON → 55912 字节 wire,头带
`Content-Encoding: gzip` + `Accept-Encoding: gzip, compress, deflate, br`
(cap:727)。hub 的 gzip 基建已在(`wb_identity.gzip_body`,CLI/VSCode 用),
桌面身份没接上。response 侧:官方客户端 undici 自动解压,hub 收 SSE 时
需确认上游不会因 Accept-Encoding 改变响应编码(先测再全量开)。

**处置**:桌面身份接 `gzip_body` + 补两个头,与 §4 一起改。

### 7. 会话 id 不落上游会话库(新增)

客户端每轮对话先 `POST /console/as/conversations/v2` 创建云端会话
(返回带连字符 UUID),主对话的 `X-Conversation-ID` 就是这个云端 UUID,
期间还有多次 PATCH(title/lastActivityAtMs)与 conversation-sync push。
hub 的 conv id 本地派生,上游侧不存在对应会话记录——若渠道校验拿它查库,
就是现成的「非官方客户端」标记(与 11-128 同族的校验完全可能这么做)。

**处置**:短期在文档记录该关联;若后续实测发现「会话未落库」导致 403/11-128,
再考虑对话前静默建会话(POST conversations/v2 + 用返回 UUID),那是
「多做动作」,先不动。

### 8. refresh / billing 头族(实测修正)

refresh 实测两种形态,都不带浏览器头:

- CLI 插件版(cap:66/340/432,空闲触发):13 头,UA
  `workbuddy-ai/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`,无 X-Requested-With、
  无 Accept-Encoding;
- 桌面主组件版(cap:711,对话期间触发):15 头,多 X-Requested-With +
  Accept-Encoding,UA 首段 `WorkBuddy/5.8.4`。

两者都带 `X-Auth-Refresh-Source: plugin`、`X-Request-ID` 32hex、X-Product: SaaS。
hub refresh 现状:多发 Origin/Referer/X-CodeBuddy-Request/Accept-Language,
UA 单段 `WorkBuddy/5.8.4`(billing_ua),缺 X-Request-ID/X-Product/X-Requested-With。

billing(cap:714/715/718):`User-Agent: axios/1.16.1`、`Accept: application/json`、
`Accept-Language: zh`、`Accept-Encoding: gzip, compress, deflate, br`,
不带 X-Machine-ID/X-Session-ID/Origin/Referer/X-CodeBuddy-Request。
hub billing 发 `WorkBuddy/5.8.4` UA + Machine/Session-ID + Origin/Referer。

**处置**:refresh 对齐桌面主组件版 15 头(删 4 浏览器头、UA 三段式、补
X-Request-ID/X-Product/X-Requested-With/Accept-Encoding);billing 改 axios
形态(删 Machine/Session-ID/Origin/Referer/X-CodeBuddy-Request,UA axios/1.16.1,
Accept-Language 按区域 zh/en)。`/v2/plugin/accounts`、`/v3/config` 同为
桌面主组件形态(cap:712/716,注意 config 带 `Connection: close`)可一并参考。

---

## 三、验证方式

本轮已回答(证据见 §五):

1. ✅ 桌面端内置 CLI 2.161.0 的 chat:body gzip、带 Accept-Encoding、
   无浏览器头(X-Requested-With 除外)、带 x-stainless-\*/acp-connection-id;
2. ✅ 桌面主对话确实带 `X-Agent-Type: main`、X-Device-Token(v3)也带;
3. ✅ 一轮真实对话的完整接口面与头族逐头落盘。

剩余问题:

1. hub 自身出站与客户端抓包的自动逐头 diff(`analyze_capture.py --diff`,
   把 mitmproxy 指到 hub 的 per-account proxy 链),替代代码核对;
2. CN 版桌面拿不到 TuringShield SDK 时发什么(本轮这台机器 SDK 正常);
3. 「会话 id 未落库」是否真的参与渠道校验(拿 hub 直发 + 观察是否 11-128)。

## 四、与既有文档的关系

- `docs/风控校验-5.8.4.md` §7 第 4 行「refresh 头一致」与本轮 cap:66/711
  实测不符(refresh 不带浏览器头族);其第三节「仓库不发 x-requested-with
  家族」指的是 identity 构造器本身,wire 上桌面分支带 X-Requested-With /
  X-CodeBuddy-Request 的描述按本清单 §4 修正。
- `docs/任务交接-实测抓包-2026-10-24.md` §3 的接口头族表与本文一致,
  本文为其最终结论版。

## 五、2026-10-24 16:28 实测对话链路(证据基线)

操作:WorkBuddy 5.8.4 桌面端(intl 头族)真实发送一条消息,mitmproxy
local 模式全量落盘 `capture/lifecycle.jsonl`,边界 640 行,对话流量 686-740。
**桌面对话不再走 websocket**:本次没有新建任何 websocket(此前 392-492 行的
`www.codebuddy.ai /v2/agentos/localagent/workspaces/websocket` 是 localagent
工作区通道),对话本体全部走 HTTPS SSE。

| 接口 | 形态要点 | cap:行号 |
|---|---|---|
| `POST /console/as/conversations/v2` | 10 头;UA `workbuddy-ai/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`;X-Request-ID 32hex;无浏览器头 | 686 |
| `POST /console/as/conversations/{uuid}` PATCH 语义 | 同上;body 只带 title/lastActivityAtMs 等增量 | 692/701/724/731 |
| `POST /space/api/agent/v1/mcp` | **undici 全小写头**;UA 单段 `WorkBuddy/5.8.4`;jsonrpc(握手/工具),**不是对话本体**;GET 尝试回 405 | 707-719 |
| `POST /v2/chat/completions`(主对话) | OpenAI SDK 形态,43 头,见 §4 逐头清单;body gzip 160490→55912;stream:true | 727 |
| `POST /v2/chat/completions`(标题生成) | auxiliary/conversation_topic;无 X-Root-Request-ID;b3 三段;conv id 是独立 UUIDv7 | 723 |
| `POST /v2/plugin/auth/token/refresh` | 两种形态(13/15 头),见 §8 | 66/711 |
| `POST /billing/meter/*` | axios/1.16.1 形态,见 §8 | 714/715/718 |
| `POST /v2/report` | axios;两种 UA(首段 WorkBuddy / workbuddy-ai) | 720/734/735 |
| `POST /v1/traces` | OTel exporter,UA `OTel-OTLP-Exporter-JavaScript/0.52.1`,仅 5 头 | 721/726/729 |
| `POST /cf-publish/api/publish` | undici 小写;`user-agent: node` | 691/694/725 |
| `POST /console/as/conversation-sync/notify/push` | 同 conversations CRUD 形态;body 带 deviceName/locale/taskTitle | 736 |
| `POST copilot.tencent.com/v2/chat/completions` | **内嵌 web 聊天**(另一会话):Origin/Referer https://www.codebuddy.cn、Accept-Language: zh-CN、X-IDE-Version 5.8.3、Accept-Encoding: identity、24 万字节明文 body | 650/740 |

杂项:tencent.sso.codebuddy.cn / www.workbuddy.cn 的 401 是同机其它组件噪声;
`GET /v2/feature-flag/…` 404、`/v2/chat/busy` 404 为客户端自身行为。

---

## 六、2026-10-24 第二轮处理状态与解包补充

### 6.1 代码已对齐(本轮提交的内容)

| 项 | 改动 | 证据 |
|---|---|---|
| 桌面 chat 头族 | 删 Origin/Referer/Accept-Language;Accept → `application/json`;`X-CodeBuddy-Request` → 小写 `x-codebuddy-request`;补 x-stainless-\*×7(**无** timeout);补 `acp-connection-id`(按 (uid, session_key) 稳定派生,UUIDv7 形态);b3 四段 + `X-B3-ParentSpanId` | cap:727;`wb_accounts.Account.headers`、`wb_identity.build_identity_headers` |
| 桌面 chat body | 全身份 gzip + `Content-Encoding: gzip`(open_upstream / probe / daily-chat 三处);cache_retention 仍 CLI 专属 | cap:727;解包 productFeatures.RequestBodyGzip |
| refresh(国际版) | 15 头桌面主组件形态(删 4 浏览器头、UA 三段式、补 X-Request-ID/X-Product/X-Requested-With);抽成 `Account._refresh_headers()` 可测 | cap:711 |
| billing(国际版) | axios 形态(删 Machine/Session/Origin/Referer/X-Requested-With/X-CodeBuddy-Request/X-No-Enterprise-Id,UA `axios/1.16.1`) | cap:714/715/718 |
| fixture | 新增 `tests/_test_desktop_wire_shape.py`:桌面 chat 头名集合(大小写敏感)⊆ cap:727 的 43 头;refresh/billing 头集合与实测逐一相等 | — |

国内版(cn)refresh/billing/桌面 chat 的值与形态**均无实测样本**,全部维持原样;
VSCode 分支同样无 wire 实测,未动(头族仍是解包推断形态)。

### 6.2 解包新证据(`app.asar.unpacked/cli/`,5.8.4 内置 CLI 2.161.0)

- **product.json**:`authentication.attributes.platform: "workbuddy-ai"`(UA 中段
  来源);`internalDomain`(copilot.tencent.com / www.codebuddy.cn)与
  `externalDomain`(www.workbuddy.ai / www.codebuddy.ai)——同一个桌面 App
  双域族并存,本机 endpoint 是 external 侧;`turingSdk.channelId: 400111`
  ——国际版桌面也配了 TuringShield(与 cap:727 的 X-Device-Token 互证)。
- **acp-connection-id**:`this.connectionId`,ACP 连接级(连接存续期复用,
  本地网关侧校验/补发),随 chat 带到上游;`x-codebuddy-request: 1` 来自
  `withSecurityHeader()`。hub 按 (uid, session_key) 派生是「每会话一连接」的
  近似,比官方「每次启动一连接」粒度细,方向安全。
- **RequestBodyGzip 是服务端下发的 productFeatures 开关**,且设了自定义
  CODEBUDDY_BASE_URL 时跳过;当前对实测账号开启。
- **cache_retention 在 2.161.0 的 dist 里 0 处命中**——hub 桌面身份不注入
  是对的(那是 2.168.x 独立 CLI 的逻辑)。
- **body 字段**:`extra_vars` 是增长埋点注入(`growthEvent`,hub 不伪造);
  `verbosity`/`reasoning_summary` 由模型设置驱动(extended thinking 时
  `summary="auto"`/`verbosity="high"`),且 `SdkFieldCleanupRule` 在部分路径
  会删掉这两个字段——hub 透传客户端 payload 的做法正确,不注入。
- **企业头族**:axios 拦截器的头名清单含 X-Enterprise-Id / X-Tenant-Id /
  X-Department-Info,官方头名确认。

### 6.3 第三轮新增(会话生命周期 + 云控)

- **会话生命周期**(上表 #7):`Account.cloud_conversation / touch_cloud_conversation`
  + `wb_proxy._desktop_conv_lifecycle`。create body 逐字段对齐 cap:686
  (type/conversationOrigin/isPlayground/workDir/clientContext);**hostId 按账号
  派生**(官方是机器级 UUID,全局共用就成了跨账号关联键);workDir 按账号昵称
  拼 `C:/Users/<昵称>/WorkBuddy AI/<时间戳>` 形态;title 用首条用户消息前 20
  字(官方 create 的 name 同源),**不发**辅助模型标题请求;伴随 PATCH 后台线程
  best-effort,不挡响应。设置键 `cloud_conversations`(默认开)可关。
- **云控开关**:`/v3/config` 成功响应里的 `productFeatures` 进
  `wb_identity.set_product_features`(现只有 RequestBodyGzip),gzip body/
  Content-Encoding 三处站点跟它走;响应无此节时维持默认(开——product.json
  静态默认即 true)。`remote_config_headers` 也对齐 cap:716(去 Origin/Referer,
  补 X-Requested-With/X-Request-ID/X-Product/X-Domain/Connection: close)。
- **参数拼装验证**:chat 头族与生命周期 body 全部有 fixture 钉住
  (`_test_desktop_wire_shape.py` / `_test_cloud_conversation.py`,共 15 条);
  body 走「透传 + 净化」网关设计,官方专属字段(extra_vars/verbosity/tools
  清单)按 §6.2 结论不伪造。

### 6.4 第四轮:独立 CLI 2.174.0 实测(capture/cli.jsonl)

官方 npm 包 `@tencent-ai/codebuddy-code` 2.174.0(npm latest)下载到临时路径,
`CODEBUDDY_AUTH_TOKEN` 注入假 JWT 强制真实发请求(边缘 401,但请求形态在鉴权
前已完整组装,gzip body 106902→35189)。与 hub CLI 分支(原对齐 2.168.2 解包)
逐头对比后的**修正已入库**:

| 实测(2.174.0) | hub 修正 |
|---|---|
| `x-requested-with: XMLHttpRequest`(小写,2.168.2 解包无此项) | CLI 分支补发 |
| `x-codebuddy-request: 1`(小写,CLI 也发) | CLI 分支补发 |
| **无 `x-stainless-timeout`**(解包推断的 1200 与 live 不符) | 已删,全分支不发 |
| `baggage: codebuddy.session_id=<会话id>,codebuddy.conversation_request_id=<轮id>` | CLI 分支补发(W3C baggage) |
| `X-Domain: www.codebuddy.ai` **鉴权后带**(cap:cli.jsonl:73/75;假 token 401 抓包里没有是 custom-token 未鉴权伪影) | hub 原本就发(值=endpoint 域),维持 |
| 版本 2.174.0(UA/X-IDE-Version) | 默认值 2.168.2→2.174.0 |
| body:`cache_retention` ✓、`extra_vars` ✓、gzip ✓、b3 四段父 span ✓、id 关系 ✓ | 无需改 |

已对齐确认的项(无改动):Accept=application/json、无 Origin/Referer/
Accept-Language/X-Device-Token/acp-connection-id、UA `CLI/<v> CodeBuddy/<v>`、
X-Agent-Runtime: other、X-Private-Data 按企业号、X-Product: SaaS、
x-stainless-runtime-version 跟宿主 node(实测 v24.20.0,hub 默认 v22.21.1 仍在
合理分布内,可 env 覆盖)。

CLI 的 `/v3/config` 头族:9 头(X-Requested-With Title-Case、Connection: close、
X-Request-ID 32hex、无 X-Domain)——hub 的 remote_config_headers 用桌面形态
(带 X-Domain),同为官方形态之一,不改。

方法学注记:CLI 尊重 HTTP(S)_PROXY,普通 mitmproxy 代理模式即可抓(无需
local 模式/UAC);local 模式抓不到走回环代理(Clash 7890)的流量,这是本轮
唯一踩的坑。

**成功路径补录(同日第二轮,真实登录)**:用户经 TUI `/login` 完成浏览器授权,
全链路落盘(cli.jsonl:17-52):`POST /v2/plugin/auth/state?platform=CLI` 发起 →
`GET /v2/plugin/auth/token?state=<uuid>` 每秒轮询(约 30 次)→
`GET /v2/plugin/login/account?state=…` 拉账号 → `/v2/plugin/accounts` →
`/v3/config`——与 hub 的 OAuth 设备流同族同端点。会话内三连请求
(topic 400 → main 200 → prompt_suggestion 200):

- **X-Domain 鉴权后带**(修正上表的假 token 结论);
- auxiliary 的两种 purpose:`conversation_topic`(其 X-Conversation-Request-ID
  为空串、无 X-Root-Request-ID)与 `prompt_suggestion`;
- 同一会话所有请求共享同一 traceId 与 ParentSpanId(b3 尾段一致);
- Bearer 为 1365 字符 JWT,X-User-Id 36 字符 UUID。

### 6.5 剩余未对齐项(按风险排序)

1. ~~**`Accept-Encoding` 请求头**~~ **已对齐(2026-10-24 第五轮)**:hub
   国际版声明 `gzip, deflate`(只声明会解的),`wb_accounts.urlopen` 中心
   解压层(gzip/deflate 流式,read/read1/readline/迭代全覆盖);官方四档中
   compress/br 无标准库实现,不声明。
2. **X-Device-Token(国际版)**:实测客户端带 `v3:` TuringShield token,
   hub 生成不了、不伪造(见 §2 处置)。
3. **header 顺序**:官方头的排列顺序(SDK 的插入序)hub 未复刻;HTTP/1.1
   wire 上可见,但属低信号,暂不动。
4. ~~**VSCode 分支**~~ **已对齐(2026-10-24 第六轮,Open VSX vsix
   解包 + 启动期 wire)**:UA 第二段实为 `coding-copilot`(旧解包笔记的
   `CodeBuddy` 有误);主 chat 的 Accept 是 `text/event-stream`;头集合 =
   buildModelRequestHeaders 显式头 + buildAuthHeaders 鉴权头,不含
   X-Product / X-Product-Version / X-Env-ID / X-Request-Trace-Id(旧解包
   把非 chat 拦截器的头混进了 chat 形态)。详见 wb_identity VSCode 分支注。
5. **国内版**:整版无实测样本,需在国内版客户端上复刻本轮流程抓一轮。

### 6.7 第七轮(2026-10-25):VSCode 鉴权后 live wire、CLI CN 探针

- **VSCode 鉴权后 live wire**(capture/vscode-chat.jsonl:120,http.proxy +
  隔离 profile 路线,登录流 auth/token→login/account 全部落盘)修正上一轮
  解包结论:**X-Product / X-Product-Version / X-Env-ID / X-Request-Trace-Id
  都在主 chat 上**(来自请求实例层,buildModelRequestHeaders 只是显式层——
  上一轮只看显式层删错了,旧解包笔记的"全局拦截器"模型才是对的);UA 在
  chat 上是 `VSCode/<宿主> CodeBuddy/<ext>`(coding-copilot 第二段只在
  /v3/config);`Content-Type: application/json;charset=UTF-8`;无显式
  Accept(undici 默认 `*/*`);**X-Device-Token-Error 实测在发**(值
  sdk_not_initialized,19 字符,与 webpack 占位分析互证);无
  x-codebuddy-request/baggage/acp-connection-id;id 关系与 B3 四段父 span
  与 hub 现状一致。hub VSC 分支已按 live wire 重排(1.118.1 实测宿主)。
- **CLI CN 探针**(CODEBUDDY_BASE_URL=copilot.tencent.com + 假 token,
  capture/vscode-chat.jsonl:131):CN 端点对无效 token 回 **302 重定向到
  www.codebuddy.cn**(intl APISIX 是 401);请求头族与 intl CLI 完全同构
  (baggage/x-requested-with/x-codebuddy-request/stainless/b3 四段),
  X-IDE-Version 2.175.0(npm latest 又漂了一版,头族稳定);gzip 跳过是
  BASE_URL 模式已知伪影。CN 鉴权后 wire 待真实 CN 账号登录补录。

### 6.6 第六轮(2026-10-24 深夜):Accept-Encoding 落地、节律限速、VSCode 对齐

- **Accept-Encoding + 解压层**:`wb_accounts.urlopen` 中心包装
  `DecodingResponse`(gzip 流式/deflate 流式,兼容 zlib 容器误发;
  read/read1/readline/迭代全覆盖),国际版各请求声明 `gzip, deflate`
  (只声明会解的;官方四档中 compress/br 无标准库实现)。压缩流 length=0,
  未压缩透传保留 #522 截断启发。CN 域真机冒烟通过(透传分支不破坏现有
  链路)。
- **每小时 token 节律**:`limits.hourly_token_limit`(默认 0=关),固定
  钟点桶,`ready()` 把达限账号摘出调度,把「7×24 均匀打满」变成小时级
  起伏。与 daily limit 互补。
- **VSCode 分支对齐**(解包 4.12.39997873 + 启动期 wire):UA 第二段
  `coding-copilot`、Accept `text/event-stream`、主 chat 不发 X-Product/
  X-Product-Version/X-Env-ID/X-Request-Trace-Id。至此**三身份全部有
  权威形态依据**(wb/cli=鉴权后 live wire,vsc=同版本 vsix 解包+启动期
  wire)。方法学事故记录:扩展宿主不继承窗口代理 env;local 模式按进程
  名 `Code` 拦截会波及日常 VS Code(已回滚,未留系统残留)。
- **结构性项最终口径**:X-Device-Token(intl 实测带 v3 token,hub 不伪造
  ——生成不了真值,伪值更显眼;cn 待实测);国内版整版仍无实测样本。
  三身份的头族/body/id 语义/会话生命周期/伴随遥测均已对齐,剩余项只有
  这两条结构性缺口与国内版实测。
