# C 盘重置与基线

重置只清 Windows C 盘，保留可验证的 D 盘数据、D 的分区身份和 TPM/NVRAM。它不是 Docker 镜像层，也不是整盘快照。用户未明确允许清 C 时，任何 agent 都必须停下。

## 首次建立基线

安装、驱动、管理通道、隔离和清理完成后，确认 root/vol 余量，估算停机释放 VM RSS 后能覆盖冷启动门槛并留余量；实际重启仍重新检查，无法保证其他任务之后不增长。capture 会停机/重启，因此在目标 Linux root 运行：

```sh
python3 scripts/finalize_baseline.py --profile PROFILE.json --capture
```

`--capture` 会在资源窗口通过后受控停机、采集并重启/验证当前系统；它不清除当前 C，也不自动创建 D 盘。它记录受信任的初始 C WIM/哈希、GPT/EFI、C/D 的 GUID、offset、size、64 位 NTFS serial、D sentinel、TPM/NVRAM 和恢复任务。基线中不能有临时密码、自动登录、安装 ISO、调试文件或未批准用户数据。若冷启动门槛不满足，必须等待或停在这里，不能绕过门槛。

capture 后必须检查输出 JSON 和 recovery 文件，再由用户决定是否做一次破坏性 C-only 演练。没有通过演练，不得声称 reset 已启用。

## 用户批准后启用并演练

只有用户明确表示允许清除 C 上现有程序和文件，才运行：

```sh
python3 scripts/finalize_baseline.py --profile PROFILE.json --accept-reset --discard
```

`--discard` 是明确的 destructive gate；它不是“丢弃镜像层”的普通选项。执行前向用户说明：C 上的 Windows、程序、用户文件和工作目录会恢复到基线；D 不应被格式化或重建。若当前没有 D，流程只记录“无 D 可验证”，不会凭空制造 D。

演练和后续每次 reset 的验收必须包括：

- C 仅被重新格式化并应用基线 WIM；EFI、GPT 磁盘身份、TPM/NVRAM 未被回滚。
- 若 D 存在，D 分区 GUID、offset、size、64 位 NTFS serial、drive letter 和 sentinel 内容 hash 保持；不能只看 Windows 的分区 index 或盘符。
- Windows 启动后恢复 D 盘符（如需要），RDP 实际登录建立桌面，WinRM HTTPS 认证/执行身份/上传 SHA-256 通过。
- 网络守卫、store 容量和 cgroup 仍生效；出站请求被宿主 DROP 并写入日志。

## 日常重置

通过本机 agent：

恢复后的 Windows 账户密码和 WinRM 证书也回到基线时的状态。若期间修改过它们，用可信 QGA 证据和受限初始凭据重新核对控制端 profile/DPAPI；不要把一次认证失败直接当作恢复失败或再次重置密码。

```sh
python3 scripts/host.py reset --profile PROFILE.json --discard
```

远端用户入口是 `/home/vm_run/scripts/reset.sh --discard`。controller 会先读取 QGA 上下文并检查 C/D、加密/EFS、GPT 和基线，再正常停机；只在证据完整时进行离线 C 恢复。它会写 recovery marker、做启动后 SYSTEM 验证，成功才清 marker 并返回 `C_reset=verified`、`D_preserved` 等结果。

若中途失败，VM 应保持停止或安全阻塞状态并保留 marker；不要删除 marker、手工启动未验证系统或重复改分区。先读 `logs` 和 recovery JSON，再按失败阶段修复；同一原因不要盲目重试。

## Fail-closed 条件

QGA 不通、C/D 加密状态无法证明、存在 EFS、GPT/分区 GUID/offset/size/NTFS serial 不匹配、D sentinel/hash 缺失、基线 WIM 校验失败、存储余量不足或 reset marker 不一致时必须拒绝。不要永久关闭 BitLocker/Device Encryption，也不要用整盘 qcow backing chain、TPM/NVRAM 回滚冒充 C-only reset。

当前实例已完成过 C-only、D 保留、RDP/WinRM 和网络验证；新 profile 或空机只读/离线检查通过，不等于新机 reset 已现场验收。
