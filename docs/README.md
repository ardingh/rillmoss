# 个人入口

[订阅链接 · 基础版](https://raw.githubusercontent.com/ardingh/rillmoss/main/rillmoss.conf) · [订阅链接 · 去广告版](https://raw.githubusercontent.com/ardingh/rillmoss/main/rillmoss-ad.conf)

基础版（保留现有分流及原有懂球帝单条拦截）：

```text
https://raw.githubusercontent.com/ardingh/rillmoss/main/rillmoss.conf
```

去广告版（同一基础版加 anti-AD，优先保护现有住宅分流及直连例外）：

```text
https://raw.githubusercontent.com/ardingh/rillmoss/main/rillmoss-ad.conf
```

任选一个。两个版本各自更新，不会互相切换。先生成、校验基础版，再生成、校验去广告版；去广告来源失败时基础版仍可更新，去广告版保留上一完整版本。具体状态见仓库 `checks/latest.json`。

[项目说明](PROJECT.md) · [维护与恢复](MAINTENANCE.md) · [完整备份](BACKUP.md)
