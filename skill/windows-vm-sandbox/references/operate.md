# 日常管理

日常管理使用 profile 驱动的 `scripts/host.py`。它通过 profile 的 SSH 身份调用目标机 root-owned controller，不把宿主管理命令复制成一堆新入口，也不改系统全局命令。先确认 profile 的 name、UUID、root 和 SSH 路由与远端事实一致：

```sh
python3 scripts/host.py inspect --profile PROFILE.json
```

`inspect` 是只读操作，检查 libvirt 定义、UUID、资源、存储挂载、工具、监听端口、当前 VM 列表和门槛。输出 `matches_profile=false`、同名但 UUID 不同、root 未挂载或存在 recovery marker 时，停止，不执行生命周期命令。

## 用户可见的八个入口

远端 `/home/vm_run/scripts` 顶层只保留基础命令：`start.sh`、`stop.sh`、`status.sh`、`logs.sh`、`counters.sh`、`reset.sh`、`delete.sh`、`recreate.sh`。底层 Python、网络、QGA、恢复和 guard 放在 `scripts/lib`，用户不直接调用。远程 shell 入口等价于：

```sh
/home/vm_run/scripts/start.sh
/home/vm_run/scripts/stop.sh
/home/vm_run/scripts/status.sh
/home/vm_run/scripts/logs.sh
/home/vm_run/scripts/counters.sh
/home/vm_run/scripts/reset.sh --discard
/home/vm_run/scripts/delete.sh
/home/vm_run/scripts/recreate.sh
```

从本机 agent 使用时统一走：

```sh
python3 scripts/host.py start --profile PROFILE.json
python3 scripts/host.py stop --profile PROFILE.json
python3 scripts/host.py status --profile PROFILE.json
python3 scripts/host.py logs --profile PROFILE.json
python3 scripts/host.py counters --profile PROFILE.json
python3 scripts/host.py delete --profile PROFILE.json
python3 scripts/host.py recreate --profile PROFILE.json
```

每条命令读取 JSON 结果。不要靠“命令返回了”判断成功；关注 `status`、`actual_state`、UUID、cgroup、store、服务和下一步字段。

## 启停和防止全局 OOM

`start` 是幂等的：运行中会检查并返回状态；关机时先检查磁盘、store、网络、TPM、资源和 profile UUID，再按冷启动门槛启动。`start_free_gib` 是按该宿主预算计算的门槛，当前案例是 204 GiB；门槛不足时命令应拒绝启动，不要自动降低 guest RAM、停止其他用户任务或绕过检查。

`stop` 请求 guest 正常关机并等待最多 120 秒；超时只暂停并报告，不强制断电，以免损坏 C/D。低内存运行中只记录告警，不暂停 VM，因为暂停不会释放 QEMU RSS。发生宿主 OOM 时先查 `status`、内核/libvirt 日志和资源消耗，不能把“剩余内存低”误当成 VM 自身超限。

多人使用前结合 `inspect` 与 `status`：inspect 看 UUID、guest RAM/vCPU、marker，status 看状态、cgroup 上限/CPU、store、root/vol 余量和 guard。Windows listener/认证另用 guest 工具验证；NAT 发布端口通常不在宿主 ss 列表中。其他用户启动高内存任务前也应看这些结果；上限不是物理内存预留。

## 日志和网络计数

`logs` 返回生命周期和网络拦截样本；恢复结果另在 recovery JSON。`counters` 查询专用链的 DROP 计数，日志采样不等于全量计数。默认只允许批准 CIDR 进入 RDP/WinRM；guest 主动向公网、宿主和内网新建连接被拒绝。需要 Git/API 时按 IP+端口批准并记录变更。

真实验收仍需端到端：RDP 认证并建立桌面、WinRM 使用选定管理员上传并校验哈希、guest 内对 Google/百度等出站请求失败且宿主日志有 DROP。仅端口监听或一次超时不构成通过。

## 删除与重建定义

`delete` 只删除 libvirt 定义和相关运行注册，不删除 store、虚拟磁盘、TPM、NVRAM、D 数据或恢复基线；运行中必须先正常 stop。`recreate` 读取目标 vol 内保存的 XML，核对 name/UUID/磁盘/TPM/NVRAM 身份后重新注册定义；成功后仍需 `status`，再由用户决定 `start`。这两个动作都不是 Windows 重装或 C-only reset。

如果实际磁盘、TPM、NVRAM、profile UUID 或基线不一致，禁止 recreate，转回初始化/恢复流程。失败中间物只在确认无 qemu/libvirt、loop、mount、fuser 引用后清理。
