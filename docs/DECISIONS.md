# 个人决定与打底调整

以下是生成器的输入约束，不由每日上游更新覆盖。打底是 LOWERTOP 的 `lazy_group.conf`；具体版本见 `snapshot/manifest.json`。

| 分类 | 保留 / 修改 / 替换 / 删减 |
|---|---|
| R01 苹果 | 保留完整 Apple 列表并固定 DIRECT；补充 Apple / iCloud / CloudKit 同步域名，`humb.apple.com` 明确直连。Apple 原始列表仍在原来的相对位置，只有明确核心例外前置。普通 Siri、听写、搜索不再进入混合 AI 分组。 |
| R02 OpenAI | 替换混合 AI 入口：仅提取打底 AI 文件的 ChatGPT 段，合并 ACL4SSR OpenAi.list；统一 OpenAI 住宅分组，覆盖 ChatGPT / OpenAI / Codex 共用端点。 |
| R02 Claude | 新增独立住宅分组。只采用指定页面的类型前缀规则块中的域名规则；采用官方入站 IPv4 `/23` 与 IPv6 `/48`、加 `no-resolve`。 |
| Claude Check 检测 | 恢复旧规则的 `DOMAIN,api64.ipify.org,V3 Static Residential` 精确前置例外；只改变此检测域名，其他 ipify.org 域名仍按通用规则分流。个人输入保存为 `claude_check_probe`，本次不改 Claude Check 配置。 |
| R03 同花顺 | 补充原始 12 条 DIRECT；不因父域覆盖删掉子域条目。 |
| R04 懂球帝 | 补充 `DOMAIN-KEYWORD,apimg.qunliao.info,REJECT` 作为去广告起点。后续按广告和正常内容实测增补，不承诺单条规则去尽全部广告。 |
| R05 国内 | 沿用打底国内专用、通用 China、GEOIP CN；哔哩哔哩固定 DIRECT。重点名单保存在 personal.json，第一版不为每个应用添加独立来源。 |
| 海外服务 | 保留 YouTube、Netflix、Disney、HBO/Max、Spotify、Telegram、PayPal、Twitter、Facebook、Amazon、GitHub、Microsoft、Google、TikTok，策略归并为Overseas。 |
| 游戏 | 保留 Sony、SteamCN、Game；删除被 Game 覆盖的 Nintendo、Epic、Steam 独立引用。SteamCN 仍代理。 |
| 字节跳动例外 | `bytedapm.com` 及子域明确代理，早于国内通用规则；`snssdk.com` 及子域直连，移除代理侧重复。 |
| 策略组 | 删除地区测速组与合并后的服务组，只保留三个精确绑定的固定 select 组。 |
| Google 重写 | 原样保留 g.cn / google.cn → google.com 两条重写，以及 `hostname = *.google.cn`。不添加证书或解密开关。 |

AI 规则先于普通 Apple 与通用国内规则；`humb.apple.com` 例外更早。其余保留来源按打底相对顺序展开。一般精确重复仍只保留最先的一条，不做父域压缩；OpenAI / Claude 之间的共享条目例外，两组分别保留独立副本，各组内仍精确去重。当前匹配顺序为 Claude 在前，共享条目优先命中 Claude；OpenAI 的独立副本完整保留。共享认证、监控、客服等依赖被其他应用使用时也走住宅。

OpenAI 不自动加入 WorkOS、`oaistatsig.com` 等待实测内容；不把官方允许列表当作第三个自动来源，不加入 `humb.apple.com`。Claude 保留 `datadog`、`sift` 关键词，不转换页面说明、NTP 建议、较宽网段或 ASN。官方入站网段发生变化时停止更新，交由核对。

保留已选 DNS、系统备用 DNS、Apple / iCloud 系统 DNS 指定及下列行为：

```ini
dns-direct-fallback-proxy = true
ipv6 = true
prefer-ipv6 = false
udp-policy-not-supported-behaviour = REJECT
block-quic = all-proxy
close-if-proxy-chain-missing = true
```

最后一项是新增的中转缺失保护，不能替代住宅节点本身异常的实际验收。未知的新 AI 端点仍可能没有被静态列表覆盖，必须在真实功能测试中核对。

2026-09-13：用户确认将境外策略组名称统一改为 `Overseas`。所有规则引用与 FINAL 同步改名，仍绑定原普通 V3；分流顺序、目标、节点及住宅策略不变。

2026-09-14（第一阶段，后续顺序决定见下）：补齐 Claude 的 sentry.io、intercom.io、intercomcdn.com 三条独立规则。policy/personal.json 的 claude_required_rules 固定已审阅的 19 条域名及关键词规则；缺失时停止生成，不能以 OpenAI 仍有同类规则判为完整。仍从既定网页来源更新，不新增来源、ASN、NTP 或扩大 IP 段。本次仅完善规则内容，尚未调整匹配顺序：anthropic.auth0.com、events.statsigapi.net 和共享服务仍先命中 OpenAI。两组独立内容不等于共享域名能按调用应用区分出口；优先级调整需另作决定。

2026-09-14（最终决定）：用户采纳 Claude 规则前置，并要求 OpenAI / Claude 两套独立、不互相补齐。policy/personal.json 的 ai_rule_order 固定为 Claude、OpenAI；claude_required_rules 保留 19 条域名/关键词，openai_required_rules 保留 25 条已审阅规则，另保留官方 Claude 入站 IP 校验。两组分别保留所有来源规则，组内去重、组间不去重；任何一组缺失规则均停止生成，即使另一组仍能匹配该域名。验证分别移除另一组来源后剩余组的目标仍归本组，并核对合并配置的 Claude 优先级及 OpenAI 核心端点。共享域名优先归 Claude，也适用于 OpenAI 发出的同域名请求；这是用户接受的域名优先级取舍，不承诺按应用隔离。节点绑定、其他规则、DNS、NTP、ASN 与 IP 范围不变。
