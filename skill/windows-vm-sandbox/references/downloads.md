# 镜像、驱动和宿主依赖

本文件只解决“拿到可信安装介质并核验”的阶段。下载由用户或 agent 按用户选择的网络执行；下载中断时保存交接状态，用户完成下载后从校验步骤继续。后续 `media.py`、`prepare_host.py` 和 `finalize_baseline.py` 均在目标 Linux 以 root 执行，Skill 文件和 profile 先上传到目标 Linux 工作目录。media/check 只做临时只读挂载并自动卸载，不定义或启动 VM。

## 官方来源

Windows 11 官方下载页：<https://www.microsoft.com/software-download/windows11>。选择与授权相符的 x64 ISO，不使用来历不明的精简版、激活版或别人制作的 WIM。

VirtIO Windows 驱动 ISO：<https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/>；驱动脚本和版本说明：<https://github.com/virtio-win/virtio-win-pkg-scripts>。下载稳定版 ISO，并把确切文件名、大小和 SHA-256 写入进度 JSON。

## 从空 Ubuntu/Debian 主机开始

先在目标 Linux 查看发行版、KVM、cgroup v2、空闲资源和已有 VM。尚无完整 profile/index/ISO 时，不要先调用 prepare_host；完成下文介质清单和 profile 后才运行：

```sh
sudo python3 scripts/prepare_host.py --profile /root/vm-profile/PROFILE.json --stage check
```

生成器针对 Ubuntu 24.04、systemd、cgroup v2 和 monolithic libvirtd。不同发行版/固件或 modular virtqemud 必须先适配，不能在共享宿主自动切换服务。没有 KVM 或 sudo 时停下，不以软件模拟代替。

若 profile 选择 GPU，check 还应报告准确 PCI 型号、IOMMU group、当前驱动、vfio-pci 绑定状态和宿主占用。`passthrough` 只允许只读核验已专供且已绑定设备；`vgpu` 返回 `NEEDS_GPU_INTEGRATION`，直到独立集成分支完成官方型号/驱动/许可核验。不要为了 GPU 直通自动解绑宿主驱动、停止模型服务或重启主机；影响评估和授权属于单独方案。

Ubuntu 24.04 的缺包可由 agent 在用户已授权的范围内先模拟、再安装：

```sh
sudo apt-get update
sudo apt-get -s install libvirt-daemon-system libvirt-clients qemu-system-x86 qemu-utils ovmf swtpm swtpm-tools wimtools ntfs-3g xorriso iptables python3 psmisc iproute2 kmod
sudo apt-get install libvirt-daemon-system libvirt-clients qemu-system-x86 qemu-utils ovmf swtpm swtpm-tools wimtools ntfs-3g xorriso iptables python3 psmisc iproute2 kmod
```

先阅读 `apt-get -s` 的变更；若会移除现有服务、改动不在允许范围或发行版不是 Ubuntu 24.04，停下适配。不要禁用 AppArmor/UFW，不整机升级；完成介质和 profile 后重新 check。宿主安装与控制台参考 [Ubuntu 官方文档](https://ubuntu.com/server/docs/how-to/virtualisation/libvirt/)。

## 下载交接和核验

Windows ISO 必须是完整 ISO，不是单独 WIM。若放在 Windows 本机（例如 `D:\迅雷下载`），完成下载后 agent 可在已有访问权限内传到 Linux；缺文件访问权限再交接用户。不能将 Windows 路径填进 Linux profile。目标 Linux 上可用：

```sh
sudo python3 scripts/media.py --windows-iso /srv/vm-media/Win11.iso --virtio-iso /srv/vm-media/virtio-win.iso
```

media.py 只读临时挂载并输出两个文件 SHA-256、全部 WIM images/index/名称/架构/语言以及 VirtIO 文件清单；它不需要 profile 或 image_index。用户据此选择 Pro/Enterprise、x64、语言后再填 profile。文件不存在、未完成或无法挂载时输出 `NEEDS_USER_INPUT: download media` 并停止；不能自动把半个 ISO 当完整文件。

```sh
sudo python3 scripts/prepare_host.py --profile /root/vm-profile/PROFILE.json --stage check
```

check 阶段会复核 profile 中所选 index 与 media.py 的清单；index 不能默认 3，必须选择与用户要求匹配的 Windows Pro/Enterprise、x64、语言项。找不到匹配项就停下让用户选择。

VirtIO ISO 至少要能找到 viostor（存储）、NetKVM（网络）、vioserial（QEMU Guest Agent 通道）驱动。vioserial 必装，否则后续 QGA、时钟同步和恢复验收可能失效。PnPUtil 返回 259 表示没有更多匹配项，不等于驱动安装失败；返回 3010 表示需要重启，必须重启后再验收 NIC/QGA。

## 不可跳过的输入

缺 Windows ISO、VirtIO ISO、实际 Pro index、语言、授权、存储路径或凭据方式时，阶段停在 `needs_user_input`。下载完成后从 media.py/原检查阶段重入，不能重跑覆盖已有实例。失败下载的临时文件只有在确认没有被 qemu/libvirt/loop/fuser 引用后才清理；共享 VirtIO 镜像和其他 VM 资产不删除。
