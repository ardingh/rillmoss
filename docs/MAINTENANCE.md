# 更新、发布与恢复

## 每日更新

GitHub Actions 的 `Daily source check and update` 在 `Asia/Taipei` 每日 08:08 触发，也支持 Actions 页面手动 **Run workflow**。仓库尚未发布时不会运行。

执行顺序：测试 → 固定各 GitHub 来源仓库的提交 → 同轮抓取全部 35 项 → 严格解析 → 检查条数与出口 → 暂存完整候选 → 记录真实检查 → 一次 Git 提交写回。HTTP 每次最多 30 秒、最多 3 次；HTTPS 下载和重定向均要求证书验证。网页保存原始字节与 SHA-256。

任一来源失败，不能拿旧来源拼出新配置。只新增失败检查记录，成品、个人设置、成功快照及规则版本保持原样，工作流最终必须标红。下载阶段之前的平台故障、仓库无法写回或 GitHub 完全漏跑，可能只能在 Actions 留下失败状态，不能保证仓库出现新记录。

`checks/latest.json` 是最近实际检查；`version.json` 是当前成品。规则内容没变时不改配置首行版本或 `rules_built_at`；来源提交、网页内容或成功快照变化可独立记录。日期均采用带时区的 UTC 时间。

成功候选还保留在本地 `.work/check-*/bundle/`；GitHub 工作流保存完整候选 Artifact 30 天，便于暂停发布时核对。已采用版本的永久历史由 Git 提交保存，包括对应快照。若需要长期保存尚未采用的候选，下载其完整 Artifact，不能只保存其中某份来源。

工作流使用仓库 `GITHUB_TOKEN` 的 `contents: write`，不需要个人 token。只暂存明确的成品、对应输入、快照和检查记录。任务并发组串行化，脚本另有本地排他锁。开始提交前确认远端 main 未变；提交后 push 如遇竞态或分叉立即失败，不 rebase、不 force。

GitHub 的计划任务可能延迟、漏跑，公开仓库长期无活动也可能暂停。08:08 仅是触发时间。设备后台更新还受系统调度、应用退出与网络影响。[GitHub 调度说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

## 来源与个人修改

修改 `policy/personal.json` / `policy/sources.json`，生成新的候选目录。不要手改 `rillmoss.conf`。新增上游规则集、分组、开关、重写只进入 `base_changes_not_imported` 报告，不自动启用。

相对于 `policy/counts.json`，任一来源条数减少超过 20% 或增加超过 50% 即停止。条数来自实际有效规则解析，不相信文件注释。采用完整成功版本时，条数基线一并更新。若变化合理，先审阅该来源的增删、出口影响与原文校验值，把原因和旧新条数记入审阅记录，才可修改基线；出口检查始终独立执行。

`personal.json` 的 `required_ai_targets` 保存首版已核对的 66 个 AI 域名 / 匹配探测目标。即使删掉单条规则未触发数量阈值，也必须保持这些目标走住宅，否则本轮停止。实测确认的重要新端点应同步补入这份保护清单。

本地审阅候选后采用：

```sh
python3 -m rillmoss prepare --output .work/review-next
python3 -m rillmoss verify --bundle .work/review-next
python3 -m rillmoss adopt-candidate --bundle .work/review-next
python3 -m unittest discover -s tests -v
```

`adopt-candidate` 是本地维护动作，会暂停自动发布并清空旧验收声明；之后按改动范围复测，再恢复发布。该命令没有 push。GitHub workflow 不调用它。

永久失效的来源单独替换或删减；此期间设备继续使用最后完整版本。不得自动改来源 URL、取消严格解析，或用未经验证的原始打底当作 AI 恢复配置。

## 首次公开发布

依次完成 Mac、iPhone 验收。`docs/ACCEPTANCE.md` 必须有脱敏结果，私密证据留在 `private/`。首次发布前审阅 Git 待公开清单、全部 diff、完整快照和测试结果；当前候选没有发布授权。

确认后才使用 work 账号 `ardingh` 创建公开仓库 `ardingh/rillmoss`，使用本地 `github-work` 身份；不要切换全局默认账号。只公开代码、规则、个人策略选择、公开来源原文与脱敏检查结果。不要建 GitHub Release。

完成验证后填写 `policy/release.json` 的 `acceptance`：`mac`、`iphone`、`ai_faults`、`ipv4`、`ipv6`、`udp`、`device_update` 为 `passed`，并记录 `rules_version` 与 `evidence`。软件不能判断人为填写是否真实，严禁凭静态测试填写设备结果。首次采用仍保持 `publish_enabled: false`，首次公开后按确认范围改为 true，启用成品自动写回。

设备从本人稳定地址加载，手动更新核对版本。再核对 work 账号的 Actions 通知接收设置及接收者；修改通知设置另按账号权限边界确认。第一版仅用 GitHub 原生失败通知，不添加独立监测服务。[通知机制](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs)

## 回退

先从 Git 历史选定此前明确可用的完整提交，在独立目录检出它；不能只恢复 `.conf`。在其 `policy/release.json` 中应有对应版本的实际验收依据。用当前代码验证旧快照，仍须满足当前 AI 出口约束。

```sh
python3 -m rillmoss verify --bundle /absolute/path/to/known-good-checkout
python3 -m rillmoss rollback --bundle /absolute/path/to/known-good-checkout
python3 -m unittest discover -s tests -v
```

回退命令先把当前 `publish_enabled` 设为 false，再恢复成品、个人设置、来源快照和版本记录，并写入检查记录。每日检查继续，成品自动发布暂停。审阅后以新提交记录回退；不 reset 远端、不改历史、不强推。修复并复测后才能恢复发布。

本地安装操作支持异常回滚；公开端的原子性来自“一次 Git 提交 + 一次普通 push”。运行机器突然断电时可能留下本地暂存状态，但未经完整提交和 push 的内容不会出现在公开端。恢复时先 `verify`，不要把脏暂存目录直接发布。
