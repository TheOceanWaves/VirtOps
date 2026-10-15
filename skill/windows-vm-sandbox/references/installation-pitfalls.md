# 安装和恢复踩坑清单

这是给小模型的硬规则。遇到同一错误不要反复改模板；先保留证据、回到对应阶段，最多做两次同因修复，仍失败就停下交接。

## Windows 安装

- **RunSynchronous 路径过长**：unattend 的 command path 上限 259 字符。用短 `bootstrap.cmd` 调起脚本，缩短工作根目录；不要把长 PowerShell 路径直接拼接进 XML。
- **WIM index 猜错**：index 3 不是通用事实。用 `wimlib-imagex info`/安装器清单核对名称、Pro/Enterprise、x64 和语言；不匹配就停下。
- **PnPUtil 259/3010**：259 表示没有更多匹配项，不单独判失败；必须实际检查 NIC、QGA。3010 表示需要重启，重启后再验证。
- **vioserial 漏装**：存储和网卡能用不代表 QGA 能用。vioserial 是 QGA/时钟/恢复链路的必要驱动，必须安装并实际请求成功。
- **WinRM 启动慢**：服务应为 Automatic 且 `DelayedAutoStart=0`；重启后检查 HTTPS listener、证书 thumbprint 和身份，不以端口监听代替认证。
- **RDP 用户名错**：使用 `COMPUTER\user`（例如 `WINVM01\vmadmin`）。0xc0000064 多为账户前缀/名称错误，不要先重置密码。
- **时钟错误**：暂停或 QGA 未同步会造成 TLS/登录假失败；先查 guest/host 时间，再改证书或密码。

## 宿主资源、磁盘和网络

- guest RAM 是 Windows 固定可见内存；host cgroup 上限还需 QEMU 开销。上限不是预留，暂停也不会释放 QEMU RSS。运行中低内存只告警，不因剩余内存低而杀/暂停 VM；冷启动的 204 GiB 之类门槛仍必须遵守。
- 150 GiB 是宿主总存储预算，不只是 Windows C 的逻辑容量。loop 存储关闭 discard/配置外层分配守卫，确认 qcow/raw、loop 和根盘的实际占用；不要靠 `df` 看到 guest 150 GiB 就认定宿主不会增长。
- 只有批准来源网段可进入 RDP/WinRM；guest 出站默认拒绝公网、宿主和其他组网 IP。控制端通过 WinRM 传结果不等于允许 VM 自主联网；若控制端代为下载，属于控制端 agent 的权限边界，需要另行审计。

## C-only reset

- 恢复按 GPT 磁盘 GUID、分区 GUID、offset、size 和 64 位 NTFS serial 定位，不使用 Windows 缓存的分区 index；D 保留必须先读 GUID/size/serial/sentinel。
- 读取 NTFS VBR 必须从偏移 0 对齐读取 512 字节再解释字段；不要使用未对齐的 seek 3/72。
- `qemu-img dd` 的 skip/count 语义容易把偏移重复计算；使用脚本已有的 image-opts raw wrapper/有界临时文件，不让小模型重写裸盘逻辑。
- WIM XML 常是 UTF-16 BOM；先按 bytes 解析再交给 XML parser，不能假设 UTF-8。
- 加密/EFS/未知分区必须 fail-closed；不要永久禁用 BitLocker/Device Encryption，只为让恢复脚本通过。
- `--discard` 是明确 destructive 授权：它清 C 上程序、用户文件和工作目录。没有授权、QGA 不通、基线哈希不匹配或 D 身份改变时停止。

## 清理与失败恢复

失败安装的中间文件不需要归档，但删除前必须确认没有 qemu/libvirt、loop、mount、fuser 或 systemd 引用。只清理本实例失败物；保留共享 VirtIO ISO、其他 VM、用户目录和模型服务。不要以“目录看起来大”推断可删对象。

常见证据命令：

```sh
virsh -c qemu:///system domstate NAME
virsh -c qemu:///system dumpxml NAME
findmnt /home/vm_run/vol
fuser -vm /home/vm_run/vol
journalctl -u libvirtd -u NAME-capguard --since '-30 min'
```

清理完成后重新跑对应阶段的只读检查；不要从 seed 直接跳到 finish。若端口能通但 RDP/WinRM 认证、实际桌面、上传哈希或宿主 DROP 证据缺失，验收仍失败。
