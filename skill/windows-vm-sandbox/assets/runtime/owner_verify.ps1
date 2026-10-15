[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$RequestPath,
    [int]$TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$stateRoot = 'C:\ProgramData\VirtOps'
$session = $null
$workDir = $null
$remoteScript = $null
$localScript = $null
$requestId = $null

function Fail([string]$Code) { throw [InvalidOperationException]::new($Code) }
function Assert-Condition([bool]$Condition, [string]$Code) { if (-not $Condition) { Fail $Code } }
function Get-RequestId([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($stateRoot).TrimEnd('\') + '\'
    Assert-Condition ($full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) 'REQUEST_PATH_OUTSIDE_STATE_ROOT'
    Assert-Condition ($full -match '^C:\\ProgramData\\VirtOps\\owner-request-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})\.json$') 'REQUEST_PATH_PATTERN'
    return $Matches[1].ToLowerInvariant()
}
function Read-Request([string]$Path, [string]$ExpectedId) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-Condition (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'REQUEST_FILE_REPARSE_POINT'
    $state = Get-Item -LiteralPath $stateRoot -Force -ErrorAction Stop
    Assert-Condition (-not ($state.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'STATE_ROOT_REPARSE_POINT'
    $request = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    Assert-Condition ([int]$request.schema_version -eq 1) 'REQUEST_SCHEMA_VERSION'
    Assert-Condition ([string]$request.request_id -eq $ExpectedId) 'REQUEST_ID_MISMATCH'
    Assert-Condition (-not [String]::IsNullOrEmpty([string]$request.password)) 'REQUEST_PASSWORD_MISSING'
    Assert-Condition ([string]$request.admin_user -match '^[A-Za-z][A-Za-z0-9_.-]{0,31}$') 'REQUEST_USER_FORMAT'
    return $request
}
function Get-TlsThumbprint([string]$PeerHost, [int]$Port) {
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $tcp.ConnectAsync($PeerHost,$Port).Wait(10000) | Out-Null
        Assert-Condition $tcp.Connected 'WINRM_TLS_CONNECT'
        $callback = [Net.Security.RemoteCertificateValidationCallback]{ param($sender,$cert,$chain,$errors) return $true }
        $ssl = [Net.Security.SslStream]::new($tcp.GetStream(),$false,$callback)
        try { $ssl.AuthenticateAsClient($PeerHost); return $ssl.RemoteCertificate.GetCertHashString().ToUpperInvariant() } finally { $ssl.Dispose() }
    } finally { $tcp.Dispose() }
}
function Get-HttpsListenerThumbprint {
    $listeners = @(Get-WSManInstance -ResourceURI 'winrm/config/Listener' -Enumerate -ErrorAction Stop | Where-Object { [string]$_.Transport -ieq 'HTTPS' })
    Assert-Condition ($listeners.Count -eq 1) 'WINRM_HTTPS_LISTENER_COUNT'
    $listener = $listeners[0]
    Assert-Condition ([int]$listener.Port -eq 5986) 'WINRM_HTTPS_LISTENER_PORT'
    $thumb = [string]$listener.CertificateThumbprint
    $thumb = ($thumb -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
    Assert-Condition ($thumb -match '^[0-9A-F]{40}$') 'WINRM_HTTPS_LISTENER_CERTIFICATE'
    return $thumb
}
function New-LocalPinnedSession([object]$Request, [string]$Thumbprint) {
    $secure = ConvertTo-SecureString ([string]$Request.password) -AsPlainText -Force
    $credential = [PSCredential]::new("$($Request.computer_name)\$($Request.admin_user)",$secure)
    $options = New-PSSessionOption -SkipCACheck -SkipCNCheck -OpenTimeout 15000 -OperationTimeout 60000
    return New-PSSession -ComputerName '127.0.0.1' -Port 5986 -UseSSL -Authentication Negotiate -ConfigurationName 'Microsoft.PowerShell' -Credential $credential -SessionOption $options -ErrorAction Stop
}
function Invoke-ChildScript($Session, [string]$ScriptPath, [string]$Directory) {
    Invoke-Command -Session $Session -ScriptBlock {
        param($p,$d)
        $out = Join-Path $d 'stdout.json'; $err = Join-Path $d 'stderr.txt'
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $psi.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$p`""
        $psi.WorkingDirectory = $d; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $proc = [Diagnostics.Process]::new(); $proc.StartInfo = $psi
        if (-not $proc.Start()) { throw 'VERIFY_CHILD_START' }
        $outTask = $proc.StandardOutput.ReadToEndAsync(); $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit(30000)) {
            try { & taskkill.exe /PID $proc.Id /T /F | Out-Null } catch {}
            throw 'VERIFY_CHILD_TIMEOUT'
        }
        if (-not $outTask.Wait(10000) -or -not $errTask.Wait(10000)) { throw 'VERIFY_CHILD_OUTPUT_TIMEOUT' }
        $stdout = $outTask.Result; $stderr = $errTask.Result
        [IO.File]::WriteAllText($out,$stdout,[Text.UTF8Encoding]::new($false)); [IO.File]::WriteAllText($err,$stderr,[Text.UTF8Encoding]::new($false))
        [pscustomobject]@{exit_code=$proc.ExitCode; stdout=$stdout; stderr=$stderr}
    } -ArgumentList @($ScriptPath,$Directory)
}

try {
    Assert-Condition ($TimeoutSeconds -ge 10 -and $TimeoutSeconds -le 600) 'TIMEOUT_RANGE'
    $requestId = Get-RequestId $RequestPath
    $request = Read-Request $RequestPath $requestId
    $listenerThumb = Get-HttpsListenerThumbprint
    $tlsThumb = Get-TlsThumbprint '127.0.0.1' 5986
    Assert-Condition ($tlsThumb -eq $listenerThumb) 'WINRM_TLS_LISTENER_CERT_MISMATCH'
    $session = New-LocalPinnedSession $request $tlsThumb
    $identity = Invoke-Command -Session $session -ScriptBlock {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = [Security.Principal.WindowsPrincipal]::new($wi)
        [pscustomobject]@{ name=$wi.Name; is_admin=$wp.IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544') }
    }
    Assert-Condition ([string]$identity.name -ieq "$($request.computer_name)\$($request.admin_user)") 'VERIFY_IDENTITY_MISMATCH'
    Assert-Condition ([bool]$identity.is_admin) 'VERIFY_ADMIN_TOKEN'
    $workDir = "C:\Work\owner-verify-$requestId"
    $remoteScript = Join-Path $workDir 'identity.ps1'
    $scriptText = '[pscustomobject]@{computer_name=$env:COMPUTERNAME;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;is_admin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.SecurityIdentifier]''S-1-5-32-544'') } | ConvertTo-Json -Compress'
    $localScript = Join-Path $env:TEMP "virtops-owner-verify-$requestId.ps1"
    [IO.File]::WriteAllText($localScript,$scriptText,[Text.UTF8Encoding]::new($true))
    $workState = Invoke-Command -Session $session -ScriptBlock {
        param($d)
        $item = Get-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'VERIFY_WORKDIR_REPARSE' }
        if ($item -and (-not $item.PSIsContainer -or (Get-ChildItem -LiteralPath $d -Force | Select-Object -First 1))) { throw 'VERIFY_WORKDIR_NOT_EMPTY' }
        [bool]$item
    } -ArgumentList @($workDir)
    if (-not [bool]$workState) { Invoke-Command -Session $session -ScriptBlock { param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList @($workDir) }
    Copy-Item -LiteralPath $localScript -Destination $remoteScript -ToSession $session -Force
    $uploadHash = (Get-FileHash -LiteralPath $localScript -Algorithm SHA256).Hash.ToUpperInvariant()
    $remoteHash = [string](Invoke-Command -Session $session -ScriptBlock { param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } -ArgumentList @($remoteScript))
    Assert-Condition ($uploadHash -eq $remoteHash.ToUpperInvariant()) 'VERIFY_UPLOAD_HASH'
    $child = Invoke-ChildScript $session $remoteScript $workDir
    Assert-Condition ([int]$child.exit_code -eq 0) 'VERIFY_CHILD_EXIT'
    $proof = $child.stdout | ConvertFrom-Json
    Assert-Condition ([string]$proof.identity -ieq "$($request.computer_name)\$($request.admin_user)") 'VERIFY_CHILD_IDENTITY'
    Assert-Condition ([bool]$proof.is_admin) 'VERIFY_CHILD_ADMIN'
    [pscustomobject]@{schema_version=1;state='success';request_id=$requestId;username=[string]$identity.name;thumbprint=$tlsThumb;upload_sha256=$uploadHash;execution=[pscustomobject]@{exit_code=[int]$child.exit_code;identity=[string]$proof.identity;is_admin=[bool]$proof.is_admin};rdp_service_running=[bool]((Get-Service -Name TermService -ErrorAction Stop).Status -eq 'Running')} | ConvertTo-Json -Depth 6 -Compress
    exit 0
} catch {
    [pscustomobject]@{schema_version=1;state='failed';request_id=$requestId;code=if($_.Exception.Message -match '^[A-Z0-9_]+$'){$_.Exception.Message}else{'OWNER_VERIFY_FAILED'}} | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($session -and $remoteScript) { try { Invoke-Command -Session $session -ScriptBlock { param($p,$d) foreach($f in @($p,(Join-Path $d 'stdout.json'),(Join-Path $d 'stderr.txt'))){Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue}; if ((Test-Path -LiteralPath $d -PathType Container) -and -not (Get-ChildItem -LiteralPath $d -Force | Select-Object -First 1)) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue } } -ArgumentList @($remoteScript,$workDir) | Out-Null } catch {} }
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if ($localScript -and (Test-Path -LiteralPath $localScript)) { Remove-Item -LiteralPath $localScript -Force -ErrorAction SilentlyContinue }
}
