[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = Join-Path (Split-Path -Parent $PSScriptRoot) "skill\windows-vm-sandbox"
$guest = Join-Path $root "scripts\guest.ps1"
$creds = Join-Path $root "scripts\credentials.ps1"
function Assert([bool]$Condition,[string]$Message){ if(-not $Condition){ throw "FAIL: $Message" } }
function Read-Utf8([string]$Path){ [IO.File]::ReadAllText($Path) }
function Parse([string]$Path){
    $errors=$null
    [Management.Automation.Language.Parser]::ParseFile($Path,[ref]$null,[ref]$errors)|Out-Null
    Assert ($errors.Count -eq 0) "PowerShell AST errors in ${Path}: $(($errors | ForEach-Object Message) -join '; ')"
}
foreach($f in @($guest,$creds)){
    Assert (Test-Path -LiteralPath $f) "missing tool $f"
    $bytes=[IO.File]::ReadAllBytes($f)
    Assert ($bytes.Length -ge 3 -and $bytes[0]-eq 0xEF -and $bytes[1]-eq 0xBB -and $bytes[2]-eq 0xBF) "UTF-8 BOM missing: $f"
    Parse $f
}
$g=Read-Utf8 $guest; $c=Read-Utf8 $creds
Assert ($g -match '\$remote\s*=\s*\$null') "run must not require RemotePath before action dispatch"
Assert ($g -match "Action -in @\('upload','download'\).*LocalPath") "upload/download input gate missing"
Assert ($g -match "Action -in @\('upload','download'\).*Assert-SafeRemotePath") "run still appears to validate RemotePath"
Assert ($g -notmatch 'function Get-Thumbprint\(\[string\] \$Host') "Get-Thumbprint must not shadow read-only Host"
Assert ($g -match 'alternate data stream') "ADS rejection missing"
Assert ($g -match "wildcard") "wildcard rejection missing"
Assert ($g -match "RemotePath must stay below C:\\Work") "C:\Work boundary missing"
Assert ($g -match '\(\(Test-Path -LiteralPath \$d -PathType Container\) -and') "cleanup Test-Path expression is not parenthesized"
Assert ($g -match 'upload_sha256') "run result does not report upload hash"
Assert ($g -match 'exit \(\[int\]\$result\.exit_code\)') "run does not propagate nonzero exit code"
Assert ($g -match 'remoteInfo.*hash') "download remote hash verification missing"
Assert ($g -match 'credential username does not match profile') "DPAPI username/profile check missing"
Assert ($c -match 'FileSystemAclExtensions') "modern ACL API missing"
Assert ($c -match 'BindAddress=') "SSH BindAddress option missing"
"guest_tools structural tests: PASS"
