# 个人决定与打底调整

以下是生成器的输入约束，不由每日上游更新覆盖。打底是 LOWERTOP 的 `lazy_group.conf`；具体版本见 `snapshot/manifest.json`。

| 分类 | 保留 / 修改 / 替换 / 删减 |
|---|---|
| R01 苹果 | 保留完整 Apple 列表并固定 DIRECT；补充 Apple / iCloud / CloudKit 同步域名，`humb.apple.com` 明确直连。Apple 原始列表仍在原来的相对位置，只有明确核心例外前置。普通 Siri、听写、搜索不再进入混合 AI 分组。 |
| R02 OpenAI | 替换混合 AI 入口：仅提取打底 AI 文件的 ChatGPT 段，合并 ACL4SSR OpenAi.list；统一 OpenAI 住宅分组，覆盖 ChatGPT / OpenAI / Codex 共用端点。 |
| R02 Claude | 新增独立住宅分组。只采用指定页面的类型前缀规则块中的域名规则；采用官方入站 IPv4 `/23` 与 IPv6 `/48`、加 `no-resolve`。 |
| R03 同花顺 | 补充原始 12 条 DIRECT；不因父域覆盖删掉子域条目。 |
| R04 懂球帝 | 补充 `DOMAIN-KEYWORD,apimg.qunliao.info,REJECT` 作为去广告起点。后续按广告和正常内容实测增补，不承诺单条规则去尽全部广告。 |
| R05 国内 | 沿用打底国内专用、通用 China、GEOIP CN；哔哩哔哩固定 DIRECT。重点名单保存在 personal.json，第一版不为每个应用添加独立来源。 |
| 海外服务 | 保留 YouTube、Netflix、Disney、HBO/Max、Spotify、Telegram、PayPal、Twitter、Facebook、Amazon、GitHub、Microsoft、Google、TikTok，策略归并为常规境外。 |
| 游戏 | 保留 Sony、SteamCN、Game；删除被 Game 覆盖的 Nintendo、Epic、Steam 独立引用。SteamCN 仍代理。 |
| 字节跳动例外 | `bytedapm.com` 及子域明确代理，早于国内通用规则；`snssdk.com` 及子域直连，移除代理侧重复。 |
| 策略组 | 删除地区测速组与合并后的服务组，只保留三个精确绑定的固定 select 组。 |
| Google 重写 | 原样保留 g.cn / google.cn → google.com 两条重写，以及 `hostname = *.google.cn`。不添加证书或解密开关。 |

AI 规则先于普通 Apple 与通用国内规则；`humb.apple.com` 例外更早。其余保留来源按打底相对顺序展开。精确重复只保留最先的一条，不做父域压缩；两份 AI 来源的相同条目归入 OpenAI。共享认证、监控、客服等依赖被其他应用使用时也走住宅。

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
