# 验证记录

2026-10-15，Windows 控制端与现有 Ubuntu/KVM `winvm01`。本记录不包含密码或用户数据。

- Python 离线测试 21 项：Skill 安装/升级/本地修改保护；profile 输入/资源/GPU 边界；两实例参数化、不同端口与存储身份、SMT、固件、XML 和 seed 转义。
- PowerShell 5/7 语法通过；本地行为回归验证合法/非法路径、成功、退出 7 和超时 124。
- Skill frontmatter、Markdown 链接、Python 编译和 runtime 快照哈希验证通过。
- 新工具现场验证：宿主 inspect/status、可信 QGA 身份/资源/证书读取；受限凭据导入/DPAPI ACL；WinRM 管理员认证、上传/下载 SHA-256、执行成功、退出 7、超时 124。测试文件按记录哈希清理，未改全局执行策略。
- 整理后的 `/home/vm_run/scripts` 顶层为八个基础脚本；实现迁入 lib，systemd 与 hook 引用已更新。Bash 语法与网络规则 verify 通过，守卫四项回归通过。
- VM 始终运行，QEMU PID 2447751；128 GiB、96 vCPU、140 GiB host cap 与 150 GiB store 保持。本次没有对现有 VM stop/reset/delete/recreate。

当前实例此前已有 RDP 桌面、C-only 恢复与 D 保留、Google/百度及内网出站阻断验收。**新的空主机完整安装、整卡 GPU 直通未在本次另建 VM 实测；vGPU 明确停在独立集成关卡。** 模板/离线测试不能代替现场阶段验收，也未运行 Qwen Flash 模型本身做全流程部署测试。Linux 原生 WinRM 客户端尚不在本工具包内。
