
# Windows 端操作

`scripts/guest.ps1` 是控制端到 Windows 的唯一示例入口。它使用 profile 中的 `network.publish_ip`、`network.winrm_port`、`windows.computer_name`、`windows.admin_user`、`winrm_thumbprint` 和 `credentials.local_clixml`，先以 TLS 证书指纹建立 pin，再用 WinRM HTTPS + Negotiate 认证。它不会修改 `TrustedHosts`、启用 Basic、降低全局执行策略或创建新的 agent 用户。

先在控制端保存 DPAPI 凭据：

    .\scripts\credentials.ps1 -Action save -ProfilePath .\profiles\winvm01.json

也可以从宿主上选定的、root 拥有且权限为 `0600` 的 credentials.json 导入；脚本只在内存中读取并立即转成 Windows DPAPI：

    .\scripts\credentials.ps1 -Action import-linux -ProfilePath .\profiles\winvm01.json -LinuxSshHost 192.168.20.5 -LinuxSshUser friction-kj -LinuxCredentialsPath /home/vm_run/vol/state/private/credentials.json

import-linux 要求 SSH 已有可用的非交互密钥和主机指纹；密码、JSON 内容、SecureString 和 SSH 输出不写日志。若 profile 的 `local_clixml` 为空，先补本机路径，或用 `-CredentialPath` 指定保存位置。

## 文件与执行

    .\scripts\guest.ps1 -Action inspect -ProfilePath .\profiles\winvm01.json
    .\scripts\guest.ps1 -Action upload -ProfilePath .\profiles\winvm01.json -LocalPath .\job.ps1 -RemotePath C:\Work\job.ps1
    .\scripts\guest.ps1 -Action run -ProfilePath .\profiles\winvm01.json -LocalPath .\job.ps1 -TimeoutSeconds 600
    .\scripts\guest.ps1 -Action download -ProfilePath .\profiles\winvm01.json -RemotePath C:\Work\result.zip -LocalPath .\artifacts\result.zip

`run` 返回 `exit_code`、`timed_out`、`stdout`、`stderr`、`workdir` 和 `upload_sha256`；上传到独立目录再执行，不依赖前一步 upload 的路径。脚本可用 `$PSScriptRoot` 保存产物，download 使用返回的真实目录。非零退出码传回调用端，超时为 124 并终止本任务子进程树。stdout/stderr 各最多返回 262144 字符，完整产物请写文件取回。工具仅删除自身脚本和空目录，用户产物保留。路径拒绝通配、ADS、reparse point 或越出 `C:\Work`。

验收必须同时看到：证书指纹匹配、WinRM 身份正确、上传 hash 相同、脚本 exit code 正确、输出 JSON 可解析。端口可达或 RDP 能登录不能单独证明 agent 操作成功。

WinRM 是双向请求响应通道：Windows 不能主动越过宿主的出站隔离，但控制端拿到的 stdout、文件和结果可以被一个有外部网络权限的控制端再次转发。因此它是权限边界和操作审计入口，不是物理数据单向闸门。Windows 端 agent 只有 Windows 管理员权限；它没有宿主 SSH、宿主 root 或 libvirt 权限。

当前工具需要 Windows 控制端（PowerShell 5.1 或 Windows 上的 PowerShell 7）。Linux 上的 PowerShell 7 不能直接视作有可用 WSMan。Linux agent 可使用获准的 Windows runner；若要原生 Python/pywinrm，先单独审核依赖、NTLM/HTTPS 及证书 pin 实现，该适配不在现成工具内。不要为此开放 HTTP/Basic，也不要给 Windows 任务 agent 宿主 root 作为替代。

## RDP 剪贴板与文件复制

初始化默认禁用 RDP 剪贴板和驱动器重定向；不能直接承诺用户可以复制粘贴。用户要求通过 RDP 复制文件时，先查询，再为指定实例启用：

    .\scripts\guest.ps1 -Action clipboard -ProfilePath PROFILE.json
    .\scripts\guest.ps1 -Action clipboard -ClipboardMode enable -ProfilePath PROFILE.json

`enable` 将该 VM 的 `fDisableClip` 和 `fDisableCdm` 设为 0，并读回验证；禁止驱动器重定向也会阻止剪贴板传文件。`disable` 将两者设为 1。客户端 `.rdp` 还须配置 `redirectclipboard:i:1`，并同步修改生成该文件的启动器，避免下次启动覆盖。`drivestoredirect:s:` 可保持空，不自动映射本机磁盘。修改后断开并重新连接，工具不停止 RDP 服务、不强制注销会话。组策略或客户端仍可能施加其他限制，实际复制文件才是端到端验收。

参考：[Microsoft 剪贴板重定向说明](https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-clipboard)。
