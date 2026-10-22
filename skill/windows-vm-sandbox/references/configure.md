# 已有实例：资源与账户

这些是 agent 的内置职责，不生成本地临时维护脚本。先 `host.py inspect --profile ...`，并以远端 `root/instance.json` 校对身份；修改后刷新控制端 profile。

## 资源

```sh
python3 scripts/configure.py --profile CURRENT.json --memory-gib 64 --host-limit-gib 72 --vcpus 96 --cpu-set 0-95 --start-free-gib 136
python3 scripts/configure.py --profile CURRENT.json --memory-gib 64 --host-limit-gib 72 --vcpus 96 --cpu-set 0-95 --start-free-gib 136 --apply --stop --restart
```

示例数值不代表默认值。第一个命令通过 SSH 只读检查；第二个允许正常关机并恢复原先运行的 VM。暂停或关机超时会阻断，不强制断电。启动原本关机的 VM 仍用 `host.py start`。

该命令同步 XML、保存定义、profile、登记表、资源控制器、slice、启动 hook 和哈希清单；不改变磁盘、网络或账户。失败保留事务备份，无法恢复的步骤须明确报告。资源配置与实际 Windows 内资源分别验收。

## 保留系统、重命名账户和改密码

```sh
python3 scripts/account.py --profile CURRENT.json --admin-user alice --credentials-mode generate
python3 scripts/account.py --profile CURRENT.json --admin-user alice --credentials-mode generate --apply
# 用户指定密码时只传递远端 root 0600 JSON 文件路径：
python3 scripts/account.py --profile CURRENT.json --admin-user alice --credentials-mode file --secret-file /root/private/alice.json --apply
```

不带 apply 的账户命令仅形成本地计划，不读取秘密或联系宿主。执行时保留账户 SID 和原用户目录，用账户自身 ChangePassword 保护已有 DPAPI 数据，随后重命名；不重装，不做 C reset，不更改其他用户。用户名与用户目录不同是正常的，例如 `alice` 仍使用 `C:\Users\vmadmin`。

先通过新凭据认证再提交 owner/凭据/profile/登记表。失败保留受限 transaction/pending 文件；使用同一请求的 `--resume --apply`，不猜密码、不手删 marker。完成后用 `credentials.ps1 import-linux` 刷新控制端 DPAPI，再以 `guest.ps1 inspect/run` 验证真实客户端通道。不要把 Windows localhost 认证报告成远端桌面已经通过。
