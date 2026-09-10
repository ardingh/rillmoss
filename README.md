# rillmoss · 溪苔

只供本人使用的 Shadowrocket 分流配置，共用于 iPhone 与 Mac。配置由个人决定和选定的公开规则来源生成，设备只需要一份完整的 `rillmoss.conf`。

**已公开开发候选仓库，每日来源检查已启用；成品自动发布保持关闭。** 当前候选在 Mac 的住宅节点缺失测试中回退到普通 V3，不可作为已验收的日常配置。用户已暂缓后续故障复测；正常连接初测与已知失败分别保留，见[设备验收](docs/ACCEPTANCE.md)和[仓库交付记录](docs/PUBLICATION_REVIEW.md)。

| 策略组 | 唯一节点 |
|---|---|
| 常规境外 | `V3（vless+vision+reality）` |
| OpenAI | `V3 Static Residential` |
| Claude | `V3 Static Residential` |

住宅节点在设备上保持“代理通过”普通 V3。配置不含任何节点连接参数。分组没有其他候选出口；客户端在节点缺失、不可达及 UDP 场景下的实际处理仍须验收。

## 本地检查与生成

需要 Python 3.11+、curl 与 Git。生成程序仅使用 Python 标准库；curl 验证 HTTPS 证书，未使用忽略证书校验。

```sh
python3 -m unittest discover -s tests -v
python3 -m rillmoss verify --bundle .
python3 -m rillmoss prepare --output .work/review-20260910
```

`prepare` 输出完整候选包，要求目标目录不存在。它不会覆盖当前配置，不会推送 Git。首个项目且没有条数基线时才允许 `--bootstrap`；之后不能用它绕过异常检查。

从当前完整成功快照离线重建，结果文件须尚不存在：

```sh
python3 -m rillmoss rebuild --bundle . --output .work/rebuilt.conf
```

`python3 -m rillmoss update` 执行一次真实来源检查。自动发布暂停时只记录结果，当前成品保持原样。完整成功候选保留在 `.work/check-*/bundle/`。这条命令没有 Git push；只有 GitHub 工作流的单独提交步骤才会写回仓库。

## 看哪里

| 文件 | 用途 |
|---|---|
| `rillmoss.conf` | 完整内嵌配置；首行是实际规则版本 |
| `policy/personal.json` | 通用设置、精确分组、个人例外与已核对打底基准 |
| `policy/sources.json` | 固定来源清单、处理方式与打底顺序 |
| `policy/counts.json` | 上次采用的成功条数基线；首次为已审阅候选基线 |
| `policy/release.json` | 发布暂停开关与设备验收依据 |
| `snapshot/` | 当前完整来源原文、提交版本、校验值及生成输入 |
| `reports/build.json` | 规则命中、精确去重与未导入的打底变化 |
| `version.json` | 当前规则版本、生成时间和快照标识 |
| `checks/` | 每轮真实检查记录；失败或无变化不伪造新规则版本 |
| [个人决定](docs/DECISIONS.md) | 对打底的保留、替换与删减 |
| [设备验收](docs/ACCEPTANCE.md) | 日常启用前的 Mac / iPhone 验收及实际结果 |
| [维护与恢复](docs/MAINTENANCE.md) | 每日任务、手动更新、来源失效、回退 |
| [来源说明](docs/SOURCES.md) | 来源与引用范围 |

## 日常使用（验收、发布后）

本人仓库的[完整配置地址](https://raw.githubusercontent.com/ardingh/rillmoss/main/rillmoss.conf)已可访问，目前内容仍是开发候选。

[每日来源检查](https://github.com/ardingh/rillmoss/actions/workflows/update.yml)也可点击 **Run workflow** 手动运行。当前只写回检查记录并保存完整候选，不替换上述配置。

两端均使用配置模式、保持 VPN 开启，核对没有更高优先级模块覆盖。设置配置后台更新间隔为 1 天，也可手动“更新配置”。GitHub 每日台北时间 08:08 触发，设备后台加载不保证同步或准点。

Apple / iCloud 及国内服务通常直连；保留 `dns-direct-fallback-proxy = true`，所以直连解析失败时允许代理兜底。OpenAI 和 Claude 没有其他代理出口。其他 AI 没有独立分类，AI 工具访问 GitHub、软件包仓库等独立目标时按目标地址正常分流。

保留 Google 跳转重写与 MITM 域名声明不等于启用 HTTPS 解密。Apple / iCloud 不解密；懂球帝第一版只使用分流去广告。Apple Intelligence 与 ChatGPT 语音不纳入第一版功能验收。
