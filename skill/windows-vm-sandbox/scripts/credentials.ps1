[CmdletBinding()]
param(
 [Parameter(Mandatory)] [ValidateSet("save","import-linux")] [string] $Action,
 [Parameter(Mandatory)] [string] $ProfilePath,
 [string] $CredentialPath,[string] $LinuxSshHost,[string] $LinuxSshUser,[int] $SshPort=22,[string] $SshKeyPath,[string] $BindAddress,[string] $LinuxCredentialsPath
)
$ErrorActionPreference="Stop"; Set-StrictMode -Version Latest
function Fail([string]$m){throw "credentials.ps1: $m"}
$p=Get-Content -LiteralPath $ProfilePath -Raw|ConvertFrom-Json
$target=if($CredentialPath){$CredentialPath}else{[string]$p.credentials.local_clixml}
if([string]::IsNullOrWhiteSpace($target)){Fail "CredentialPath or profile.credentials.local_clixml is required"}
$target=[Environment]::ExpandEnvironmentVariables($target); $parent=Split-Path -Parent $target
if($parent -and -not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Force -Path $parent|Out-Null}
function Save-Dpapi([Management.Automation.PSCredential]$Credential){
 if(Test-Path -LiteralPath $target){Fail "credential destination already exists; choose a new private file"}
 $expected=[string]$p.windows.computer_name + [char]92 + [string]$p.windows.admin_user
 if($Credential.UserName -ine $expected){Fail "credential username must match the profile computer/user"}
 $acl=New-Object Security.AccessControl.FileSecurity; $acl.SetAccessRuleProtection($true,$false)
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 foreach($entry in @($sid,[Security.Principal.SecurityIdentifier]"S-1-5-18")){ $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($entry,"FullControl","Allow"))) }
 $fileInfo=[IO.FileInfo]::new([IO.Path]::GetFullPath($target))
 $stream=[IO.File]::Open($fileInfo.FullName,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write);$stream.Dispose()
 try {
  if($PSVersionTable.PSVersion.Major -ge 6){[IO.FileSystemAclExtensions]::SetAccessControl($fileInfo,$acl)}else{[IO.File]::SetAccessControl($fileInfo.FullName,$acl)}
  $Credential|Export-Clixml -LiteralPath $fileInfo.FullName -Force
 } catch {Remove-Item -LiteralPath $fileInfo.FullName -Force -ErrorAction SilentlyContinue;throw}
 [pscustomobject]@{action="saved";path=$target;user=$Credential.UserName}|ConvertTo-Json
}
if($Action -eq "save"){
 $cred=Get-Credential -Message "输入 Windows 管理员凭据；密码只由 DPAPI 加密保存，不会打印"; if(-not $cred){Fail "credential prompt cancelled"}; Save-Dpapi $cred; exit 0
}
if($Action -eq "import-linux"){
 foreach($n in @("LinuxSshHost","LinuxSshUser","LinuxCredentialsPath")){ $v=Get-Variable -Name $n -ValueOnly; if([string]::IsNullOrWhiteSpace([string]$v)){Fail "${n} is required"} }
 if(-not $LinuxCredentialsPath.EndsWith("/credentials.json") -or $LinuxCredentialsPath.IndexOf([char]10)-ge 0 -or $LinuxCredentialsPath.IndexOf([char]13)-ge 0 -or $LinuxCredentialsPath.IndexOf([char]39)-ge 0 -or $LinuxCredentialsPath.IndexOf([char]34)-ge 0){Fail "LinuxCredentialsPath must be a specific credentials.json path"}
 $ssh=Get-Command ssh.exe -ErrorAction Stop
 $common=@("-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-p",[string]$SshPort)
 if($SshKeyPath){$common += "-i"; $common += $SshKeyPath}
 if($BindAddress){$common += "-o"; $common += ("BindAddress=" + $BindAddress)}
 $remote = "${LinuxSshUser}@${LinuxSshHost}"
 $q=[char]39; $statCommand="sudo -n stat -c "+$q+"%u %a %F"+$q+" -- "+$q+$LinuxCredentialsPath+$q
 $stat = (& $ssh.Source @common $remote $statCommand) -join "`n"
 if($LASTEXITCODE -ne 0 -or $stat.Trim() -ne "0 600 regular file"){Fail "Linux credential file is not verified as root-owned mode 0600"}
 $catCommand = "sudo -n cat -- " + $q + $LinuxCredentialsPath + $q
 $json = (& $ssh.Source @common $remote $catCommand) -join "`n"
 if($LASTEXITCODE -ne 0){Fail "SSH could not read the selected credential file"}
 $obj = $json | ConvertFrom-Json
 $user = [string]$p.windows.admin_user
 $password = $obj.$user
 if([string]::IsNullOrWhiteSpace([string]$password)){Fail "missing password"}
 $secure = ConvertTo-SecureString -String ([string]$password) -AsPlainText -Force
 $username = [string]$p.windows.computer_name + [char]92 + $user
 $cred = New-Object -TypeName Management.Automation.PSCredential -ArgumentList @($username,$secure)
 Save-Dpapi $cred
}
