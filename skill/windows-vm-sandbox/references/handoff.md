
# 交给另一个 agent 或小模型

交接前由人或上层 agent 只提供 profile 路径和本次动作；不要把密码、DPAPI 文件内容、证书私钥或宿主 SSH 命令塞进 prompt。profile 的 `local_clixml` 是凭据句柄，`winrm_thumbprint` 是固定的服务器身份。

推荐按下面的顺序逐步执行，每一步读取 JSON 后再继续：

1. `inspect`，确认 `computer_name`、`identity`、`winrm=Running`。
2. `upload`，把一个明确的 `.ps1` 送进 `C:\Work`，记录 SHA-256。
3. `run`，设置任务需要的最小超时，检查 `exit_code`、`timed_out`、`stderr`。
4. `download`，使用一个不存在的本地目标，记录 SHA-256。
5. 需要停止或重置时，结束 Windows 动作并把控制权交回宿主管理流程；agent 不得调用宿主 SSH、virsh、reset、delete 或修改网络规则。

小模型的硬性停机条件：

- profile 缺少端口、管理员名、DPAPI 凭据或 40 位 thumbprint：停下并报告 `needs_user_input`。
- 证书 pin 不匹配、WinRM 身份不符、hash 不一致、脚本超时或返回非零：停下，不重试超过两次，不删除用户文件。
- 需要访问 `C:\Work` 以外的路径、通配符、共享目录、宿主路径或新账户：停下请求人工决定。
- 网络测试失败时不能为了“排障”开启 Basic、修改 TrustedHosts、取消证书检查、放宽出站防火墙或改变全局执行策略。

每次交接报告只写动作、目标、通过/失败、证据和下一步；绝不写密码、凭据 JSON、完整远端环境变量或不必要的 stdout。运行脚本本身可以写用户要求的产物，但应在 `C:\Work` 下使用专属子目录，并避免删除同事已有文件。
