# VirtOps

面向 AI agent 的 Windows / KVM 虚拟机运维 Skill 工程。把“空 Linux 主机初始化”“新建 VM”“日常管理”“C 盘重置”“Windows 内执行任务”分开，按当前任务逐级读取，适合上下文较小的模型使用。

## 给安装此工程的 agent

1. 阅读本文，确认目标 agent 的 Skill 目录。
2. 运行 `python install.py --check`，只校验工程，不连接服务器。
3. Codex 默认安装：`python install.py --install`。目录优先取 `$CODEX_HOME/skills`，否则为当前用户的 `~/.codex/skills`。
4. 其他兼容 Agent Skills 格式的 agent，先确认其配置，再运行 `python install.py --install --skills-dir "其实际的技能目录"`。参数是包含多个 Skill 的父目录，不是最终 Skill 文件夹。
5. 运行 `python install.py --verify-installed`。重新加载技能或在新会话调用 `$windows-vm-sandbox`；不同 agent 的发现/刷新方式依其产品实际行为。

**安装 Skill 只复制本地技能文件，不安装 Windows、不连接 SSH、不更改服务器。** 不需要在 Linux 服务器加 `vmps`、登录提示或其他全局命令。已有实例沿用 `/home/vm_run/scripts`。

首次获取工程：`git clone https://github.com/TuKJet/VirtOps.git`，然后 `cd VirtOps`。在 agent 已获准安装 Skill 的会话中，让它按上述步骤自行检查、安装和验证；遇到执行环境对技能目录的写权限限制，使用该环境正常的授权机制。

```powershell
# Windows，进入本工程目录后执行；优先使用 PowerShell 7
python install.py --check
python install.py --install
python install.py --verify-installed
```

```sh
# Linux/macOS，同一个标准库安装器
python3 install.py --check
python3 install.py --install
python3 install.py --verify-installed
```

升级用 `python install.py --upgrade`。安装器只替换自己管理且未被手工修改的旧文件；发现本地修改、未知文件或其他同名 Skill 会停止，避免覆盖。个人 profile、凭据和执行记录应放在工程及已安装 Skill 目录之外。

## 如何使用

用自然语言指定目标，agent 负责读取对应流程并执行已授权步骤：

- “用 `$windows-vm-sandbox` 看看 Linux 主机上的 VM、内存余量和最近异常。”
- “这是一台只有 Ubuntu 的机器，帮我从零部署 Windows 沙箱。先问我资源、端口和账户，缺镜像就停下来告诉我下载什么。”
- “新建一台 VM，先让我选 CPU、内存、磁盘总预算、发布端口和 Windows 用户名／密码方式。”
- “把这台 VM 的 Windows C 盘恢复到出厂状态，保留 D 盘。”
- “连接这台 Windows，上传并执行脚本，取回结果文件。”
- “交接给另一个 agent，只让它操作 Windows，不给它 Linux 宿主管理凭据。”

`SKILL.md` 只保留路由和共同约束。初始化、新建、重置、Windows 操作、排错分别在 `references/`。每个阶段写明：输入、动作、验收、需要停下询问用户的条件及续作位置。

## 初始化必须先问什么

主机地址/SSH 身份；VM 名称；Windows 版本和语言；内存 GiB、vCPU 数、磁盘**宿主总预算**；是否分配 GPU、专供整卡还是希望 vGPU 共享、宿主是否已占用；RDP 与 WinRM 发布 IP/端口、允许进入的网段；Windows 管理员用户名及密码提供方式。不能把已部署实例的 128 GiB、96 vCPU、150 GiB、无 GPU、13389/15986 或 `vmadmin` 当作新 VM 的默认答案。

GPU 分支目前可生成已绑定 `vfio-pci`、完整 IOMMU 分组的专供整卡直通定义；不会自动抢占宿主 GPU。vGPU 需按确切硬件、厂商兼容矩阵、驱动和许可单独集成，未实现时明确停止，不静默降级。当前实例继续使用软件图形。

密码可由用户在本机安全提示输入，或在用户同意后随机生成并存入受限文件。不会把密码写入聊天、profile、README、Git 或命令行参数。需要下载时交付 Windows 官方 ISO 和 VirtIO 官方 ISO 的入口，等待用户下载完成后续作，不拿来源不明的修改版代替。

## 工程结构

```text
install.py                      本地安装、升级和校验
skill/windows-vm-sandbox/
  SKILL.md                      轻量入口
  agents/openai.yaml            UI 元数据
  references/                   按任务读取的细化步骤与交接契约
  scripts/                      profile 校验、只读盘点、部署生成器、管理和 WinRM 工具
  assets/runtime/               2026-10-15 当前生效运行脚本快照
  assets/templates/             无密码的 Windows 安装模板
  assets/profiles/               profile 示例和字段约束
tests/                          安装、资源边界、参数化和工具测试
```

`assets/runtime` 是经过当前实例验收的参考实现，包含该实例的名称、路径和存储身份；**不能原样复制到新 VM**。初始化生成器必须为新实例重新生成 UUID、存储身份、路径、网络、端口、资源及账户参数。旧的 120/100 GiB 构建器、迁移器、旧盘清理器和镜像层脚本不属于这个工程的部署入口。

## 资源与隔离含义

Windows 内的物理内存固定为用户选择的值；宿主 cgroup 另计 QEMU 开销。内存上限不是资源预留，其他任务也需要预算，暂停 VM 不会释放其内存。运行中低宿主内存只告警；网络隔离或磁盘边界失效仍按实例守卫处理。

默认允许控制端从批准的组网连接 RDP/WinRM，允许会话返回数据；VM 主动向公网、其他组网机器和宿主其他服务新建连接默认拒绝。需要内网 Git、模型 API 或许可证服务时按目标和端口单独审批。控制端替 VM 代理联网属于控制端权限边界。

C-only reset 清除 C 上的程序、用户文件和工作目录，并保留可验证的 D 分区；删除／重建 VM 定义保留磁盘、TPM 和 NVRAM，不能当作重装系统。

## 开发与验证

```sh
python -m unittest discover -s tests -v
python install.py --check
```

Windows 开发机另运行 `./tests/guest_tools_test.ps1` 和 `./tests/guest_behavior_test.ps1`。后者只启动本地临时子进程做退出/超时回归；执行环境需允许结束自己创建的子进程。

仓库不含 Windows ISO、WIM、虚拟磁盘、用户数据或任何真实凭据。当前实例的启停、C-only 恢复与 D 保留、RDP 实际会话、WinRM 文件上传和出站阻断已有现场证据；新主机完整安装仍须按阶段重新验收，不能由模板校验代替。
