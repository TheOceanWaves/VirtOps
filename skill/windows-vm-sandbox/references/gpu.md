# GPU 选择与直通边界

初始化不能假设所有宿主都没有 GPU。先询问用户：VM 是否需要 GPU；若需要，哪一张卡可以长期专供；是否允许共享；宿主上的模型/显示服务当前是否使用它；整卡直通是否允许停止相关宿主任务和重启。GPU 不属于“自动分一半 CPU”的规则，必须单独选择。

## profile 字段

GPU 配置放在 profile 的 `gpu` 区域：

```json
{
  "gpu": {
    "mode": "none",
    "pci_devices": [],
    "dedicated": false
  }
}
```

`mode` 必选：

- `none`：VM 使用 CPU/软件图形，不占宿主 GPU。当前 `winvm01` 是此模式。
- `passthrough`：整卡 PCI 直通；必须填写用户明确专供的 `pci_devices` 地址列表和管理员批准记录。整卡直通后宿主不能继续使用这张卡，宿主 Qwen/显示/其他任务不能同时占用。
- `vgpu`：询问并核验准确 GPU 型号、官方兼容矩阵、驱动、许可和 profile 名称；本工程不伪造通用 vGPU 支持，代码 check 应返回 `NEEDS_GPU_INTEGRATION`，直到有已实现且验收过的集成分支。

`passthrough` 的设备地址必须是管理员明确允许专供 VM、已绑定 `vfio-pci` 且属于完整 IOMMU group 的 PCI 设备。生成 XML 时使用 `hostdev managed=no`，不自动解绑宿主驱动、不抢占模型、不停止服务、不重启主机。若设备仍由 NVIDIA/显示驱动使用，或 IOMMU group 含有不允许直通的其他设备，立即停止并交接影响评估。

profile 使用 `dedicated=true` 记录已明确专供的选择；它不代替真实用户授权。生成器增加 PCIe root ports，但大 BAR 的 GPU 仍需按硬件核验 Above 4G、UEFI、MMIO 窗口和驱动；设备 Code 12 等错误先读硬件资料，不盲改宿主 BIOS/内核。非 GPU 同槽功能或不安全的混合 IOMMU group 会拒绝直通。

技术入口：[libvirt PCI hostdev 定义](https://libvirt.org/formatdomain.html#host-device-assignment)、[NVIDIA 官方 vGPU 文档](https://docs.nvidia.com/vgpu/)。vGPU 选择时查当时版本的准确产品兼容矩阵，不把同系列名称当成支持证明。

## 检查与授权

```sh
sudo python3 scripts/prepare_host.py --profile /root/vm-profile/PROFILE.json --stage check
```

`none` 应确认不会生成 hostdev；`passthrough` 只做只读 PCI/IOMMU/vfio 检查；`vgpu` 只报告准确型号和缺少的官方兼容/驱动/许可核验，不把它降级成 CPU，也不自动安装驱动。检查不通过时先向用户说明设备、宿主任务和重启影响。

从原宿主驱动切换到 vfio-pci、改变 initramfs、重启主机或停止 Qwen 是独立的高影响方案分支，必须另列方案并取得明确授权；不属于普通初始化的自动步骤。整卡直通和 vGPU 的驱动/兼容方案在本工程新 VM 上尚未现场实测，文档或模板校验不能代替实机验收。

## 验收

`passthrough` 只有在 Windows 设备管理器/厂商工具实际看到目标 GPU、驱动安装完成、图形或 CUDA 工作负载运行、宿主其他 GPU 服务仍按约定运行后才算通过。`vgpu` 还必须证明许可、隔离 profile、驱动版本和 Windows 实际设备可用。发生黑屏、宿主驱动丢失、Qwen 中断或 IOMMU 错误时，停止后续安装并保留日志。
