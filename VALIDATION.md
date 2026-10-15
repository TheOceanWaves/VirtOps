# 验证记录

2026-10-15，Windows 控制端与现有 Ubuntu/KVM `winvm01`。本记录不包含密码或用户数据。

- Python 离线测试 21 项：Skill 安装/升级/本地修改保护；profile 输入/资源/GPU 边界；两实例参数化、不同端口与存储身份、SMT、固件、XML 和 seed 转义。
- PowerShell 5/7 语法通过；本地行为回归验证合法/非法路径、成功、退出 7 和超时 124。
- Skill frontmatter、Markdown 链接、Python 编译和 runtime 快照哈希验证通过。
- 新工具现场验证：宿主 inspect/status、可信 QGA 身份/资源/证书读取；受限凭据导入/DPAPI ACL；WinRM 管理员认证、上传/下载 SHA-256、执行成功、退出 7、超时 124。测试文件按记录哈希清理，未改全局执行策略。
- 整理后的 `/home/vm_run/scripts` 顶层为八个基础脚本；实现迁入 lib，systemd 与 hook 引用已更新。Bash 语法与网络规则 verify 通过，守卫四项回归通过。
- VM 始终运行，QEMU PID 2447751；128 GiB、96 vCPU、140 GiB host cap 与 150 GiB store 保持。本次没有对现有 VM stop/reset/delete/recreate。

当前实例此前已有 RDP 桌面、C-only 恢复与 D 保留、Google/百度及内网出站阻断验收。**新的空主机完整安装、整卡 GPU 直通未在本次另建 VM 实测；vGPU 明确停在独立集成关卡。** 模板/离线测试不能代替现场阶段验收，也未运行 Qwen Flash 模型本身做全流程部署测试。Linux 原生 WinRM 客户端尚不在本工具包内。

## 多实例与交接增强验收（2026-10-15）

- Linux root 环境的 Python 离线测试 55 项全部通过（包括真实 shell wrapper、共享 catalog、冲突登记、暂停/未登记 VM 资源预算、owner 状态恢复及受控升级）。Windows PowerShell 5.1 与 PowerShell 7 的 owner 辅助脚本测试通过；账户与 D 格式化使用模拟，不修改真实账户或磁盘。
- 当前 winvm01 已完成管理脚本升级、初始 owner 登记及 status --all 实测。名称、UUID、128 GiB、96 vCPU、RDP 13389、WinRM 15986、150 GiB store 保留；升级前后 live XML 一致，QEMU PID 2447751 未变化。
- 新 owner_verify.ps1 以现有 WINVM01\vmadmin 完成真实 Windows 回环 HTTPS WinRM Negotiate 认证、管理员 token、脚本上传 SHA-256 与执行退出 0 验证；宿主 127.0.0.1:15986 的 TLS 证书与 guest listener 一致。RDP 服务正在运行；本轮不新增声称真实桌面登录验收。
- 当前 guest 无 D 分区，只读 preflight_only 测试成功，未执行账户修改、C 恢复或 D 格式化。真实 D 格式化/恢复、换成另一管理员及第二台实际 VM 并发仍待该具体场景验收。
- 修复了 PowerShell 内建 Host 参数冲突、listener CertificateThumbprint 属性、Invoke-Command ArgumentList 参数、格式化后 NTFS serial 恢复、无 D 预检、共享 catalog 误依赖实例 backend，以及升级存储分配/目录权限误判。
- 本轮没有启动/停止/重置/删除当前 VM，没有修改其网络规则、XML 或其他用户服务，也未用 Qwen Flash 完整执行部署。
