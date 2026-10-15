# 换使用者并复用 Windows 基线

这个流程用于同一台已经安装并完成基线验收的 VM 换给另一位同事使用。它复用现有 Windows 安装和 C 盘基线，不下载 ISO、不重新安装系统、不创建镜像层。它不是“新建第二台 VM”；新 VM 仍必须使用新的 profile、UUID、存储根、网络 /30 和发布端口，按 [初始化部署](initialize.md) 从头验收。

## 先收集交接输入

在执行任何停止或清盘动作前，向新使用者确认并写入一个**不含密码**的 owner profile：

```json
{
  "schema_version": 1,
  "name": "winvm01",
  "uuid": "现有 VM 的 UUID",
  "admin_user": "new-owner",
  "labels": {"owner": "新同事", "purpose": "开发"},
  "credentials": {"mode": "generate", "secret_file": null},
  "data_policy": "preserve"
}
```

必须询问：

- Windows 管理员用户名；密码选择 `generate`（受限文件随机生成）或 `file`（root 0600 JSON，只有 `password` 字段）。密码不能放入 profile、命令行、聊天、Git 或日志。
- D 盘是 `preserve` 还是 `clear`。默认应让用户明确选择；保留意味着新管理员可能读取上一位使用者留下的数据。
- 是否沿用原 VM 的资源、GPU、RDP/WinRM 端口和网络白名单。此流程默认沿用，资源、GPU 和端口的变更必须走单独的新 profile / 迁移计划，不能在交接时静默修改。

验证 `name` 和 UUID 必须与目标 VM 一致，owner profile 不能指向另一台实例。`data_policy=clear` 还必须在命令行显式加 `--discard-data`；它表示在已验证的同一系统盘上逻辑格式化 D，**不代表安全擦除**，不允许清整块磁盘、重分区或全盘清 C/D。

## 分阶段执行

1. `inspect` 目标 VM，保存 UUID、当前状态、基线摘要、D 身份、存储余量和当前会话证据。若基线缺失、UUID 不符、加密/EFS 状态未知或 recovery marker 存在，返回 `needs_user_input` / `blocked`，不要继续。
2. 进入维护窗口。将发布的 RDP/WinRM 临时收窄到宿主回环，保留宿主管理和 QGA；出站隔离、磁盘守卫、cgroup 和日志继续启用。已有桌面或 agent 任务必须先结束，否则停止并报告。
3. 先做 C-only reset，验证 C 恢复成功、D 身份仍匹配。`preserve` 保留 D；`clear` 只在同一盘的 D GUID/offset/size/NTFS serial 证据完整时逻辑格式化 D，并记录结果。
4. 使用 QGA 把 owner 配置送入 Windows 的受限临时工作目录，创建或更新用户、设置管理员权限、配置 RDP/WinRM 所需权限，然后删除临时秘密。只保留本次选择的日常管理员，不创建额外 agent 账户。不得把 owner 密码交给 Linux 第三方依赖；`owner_verify.ps1` 在 Windows 内完成本地 WinRM HTTPS `5986` 验证、上传/执行脚本和 SHA-256 回读。
5. Windows 内使用新凭据通过 `127.0.0.1:5986` 做 WinRM Negotiate 认证、上传哈希和管理员脚本执行；宿主另连 `127.0.0.1:<发布端口>`，验证 NAT 可达且 TLS 证书与已认证的 Windows listener 一致。宿主这段只做 TLS pin，不声称已从宿主完成账户认证；对外重新开放后，再用 [agent 通道验收](handoff.md) 做实际客户端的认证和文件传输。若新用户配置失败，保持维护状态，不清 marker 让普通 `start` 绕过交接。
6. 验证 C/D 策略、固定 RAM/vCPU、GPU 定义、网络阻断和拦截日志。RDP 服务自动健康只报告 `ready_for_RDP`；只有操作者确认使用 `COMPUTER\\user` 建立真实桌面后，才能报告 RDP interactive verified。通过后恢复原来的发布白名单，写入不含密码的公共 owner 状态；重置所需秘密仅存于 root 受限目录。

每一步输出 `stage`、`target`、`evidence`、`next_action`、`needs_user_input`。小模型只能根据 JSON 的成功状态继续；遇到失败停在当前阶段，不重复安装、不猜密码、不连续盲重试。

## 入口与边界

最终用户入口仍是现有远端基础脚本，内部实现放在 `scripts/lib`：

```sh
/home/vm_run/scripts/reset.sh --discard --owner-profile /root/private/new-owner.json
/home/vm_run/scripts/reset.sh --discard --owner-profile /root/private/new-owner.json --discard-data
```

裸 `reset.sh --discard` 在尚未注册 owner 状态时沿用基线账户；注册 owner 状态后，每次 C reset 都自动重新应用当前 owner。若当前 owner 失效，流程先进入维护状态并要求重新登记，不自动暴露基线管理员。

复制工程到新 Linux 主机只带来通用的入口生成器和文档，不迁移当前 VM 的磁盘、TPM、NVRAM、凭据或基线。新主机仍需一次完整安装和一次基线建立；之后的换人才能免安装复用基线。

当前实例的换人流程没有在本轮实际执行；在没有新用户名、密码方式和 D 盘选择前，不能对当前 VM 做 reset、停机或交接。

因此当前工程状态只能报告“流程与工具已准备、待现场验收”，不能报告 owner reset、WinRM 新凭据或 RDP 真实桌面已经通过。现场必须先做只读 inspect，再由用户提供新 owner 和 D 策略，最后按本页逐阶段执行。
