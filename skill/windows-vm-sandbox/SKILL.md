---
name: windows-vm-sandbox
description: 从空 Linux 主机部署和管理隔离的 Windows KVM 虚拟机，支持资源与账户询问、镜像下载交接、新建实例、日常启停、仅重置 C 盘保留 D 盘，以及经 WinRM 上传脚本和操作 Windows。适用于用户明确请求部署或使用该类 VM；不把普通 Windows 本机操作或 Docker 管理改造成虚拟机部署。
---

# Windows VM Sandbox

先识别用户要做什么，再只读相应文档。使用用户选择的资源、端口、用户名和密码提供方式；当前实例的配置只是案例。

| 用户意图 | 先读 | 确定性工具 |
|---|---|---|
| 空 Linux 主机首次部署、新建独立 VM | [初始化部署](references/initialize.md) | `scripts/profile.py`、`scripts/prepare_host.py` |
| 查看、启停、删除后重建定义 | [日常管理](references/operate.md) | `scripts/host.py`，复用目标机器现有脚本 |
| 恢复 Windows、保留 D | [重置与基线](references/reset.md) | 目标的 `reset.sh --discard` |
| 上传文件、执行代码、下载结果 | [Windows 操作](references/windows-agent.md) | `scripts/guest.ps1` |
| 交给另一个 agent／小模型 | [交接契约](references/handoff.md) | 限定 Windows 端点、工作目录和凭据句柄 |
| 失败、RDP 不通、OOM、安装循环 | [排错](references/troubleshooting.md) | 先读证据，最多两次同因重试 |

需要资源与字段说明时读 [profile](references/profile.md)；GPU 需求和专供/共享选择读 [GPU 分支](references/gpu.md)，不可默认无 GPU。适配现有 `192.168.20.5 / winvm01` 时再读 [当前案例](references/current-instance.md)。下载地址及版本核验读 [镜像与依赖](references/downloads.md)。

## 执行约定

1. 对已有 VM 先核对 profile 的名称、UUID、路径和远端事实。日常任务不重新安装宿主依赖，不覆盖运行脚本，不引入新全局命令。
2. 新建 VM／从空机初始化前，询问未提供的资源、端口、账户等关键输入；完成容量盘点和具体计划，在用户已授权部署的范围内执行。额外影响其他服务或清除现有数据才另问。已回答过的内容沿用，不重复询问。
3. 缺镜像、凭据、授权或关键目标信息时，在对应交接点停下。记录下一步及所需文件，不把超时当作许可。
4. 维护 JSON 进度文件：`stage`、`target`、`evidence`、`next_action`、`needs_user_input`；不放密码。每步通过验收才推进，失败停在该步。
5. 当前运行时以 `/home/vm_run/scripts` 为准；包内 runtime 仅是生成新实例的输入，不能对现有 VM 直接“重新部署”。
6. 用户请求“重置／重装”时说明 C 会清除、D 是否保留。先检查授权和恢复条件；“重建定义”只保留并重新注册原状态，不能冒充系统重置。
7. 固定 guest RAM、宿主上限和整机预留是三件事。低内存告警不暂停 VM；不停止其他用户任务或自动降低他们的限额。
8. 密码仅用安全提示、当前用户 DPAPI 或受限文件，永不写聊天、Git、命令参数、脚本日志。Windows 操作使用用户选定的管理员，不擅自新增低权限 agent 账户。
9. RDP 验收需成功认证和实际桌面会话；WinRM 需认证、执行身份和上传哈希；出站隔离需 Windows 内请求与宿主 DROP 证据。端口通、启动日志或网页超时单独都不够。
10. 不导出整盘快照、TPM/NVRAM 回滚来实现“只重置 C、保留 D”。加密、未知分区或证据不完整时停止自动重置。

给用户的结果只需：动作和目标、是否通过、关键证据、剩余阻塞或下一步。小模型按一条阶段命令执行、读取 JSON 返回、验收、继续，不一次猜出整套 SSH/PowerShell 命令。
