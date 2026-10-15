[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$RequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:StateRoot = 'C:\ProgramData\VirtOps'
$script:ComputerName = [Environment]::MachineName

function Fail([string]$Code) {
    throw [InvalidOperationException]::new($Code)
}

function Assert-Condition([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Fail $Code }
}

function Get-RequestIdFromPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($script:StateRoot).TrimEnd('\') + '\'
    Assert-Condition ($full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) 'REQUEST_PATH_OUTSIDE_STATE_ROOT'
    Assert-Condition ($full -match '^C:\\ProgramData\\VirtOps\\owner-request-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})\.json$') 'REQUEST_PATH_PATTERN'
    return $Matches[1].ToLowerInvariant()
}

function Assert-SafeRequestPath([string]$Path) {
    $id = Get-RequestIdFromPath $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-Condition (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'REQUEST_FILE_REPARSE_POINT'
    $parent = Get-Item -LiteralPath $script:StateRoot -Force -ErrorAction Stop
    Assert-Condition (-not ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'STATE_ROOT_REPARSE_POINT'
    return $id
}

function Assert-AsciiAdminName([string]$Name) {
    Assert-Condition (-not [String]::IsNullOrWhiteSpace($Name)) 'ADMIN_USER_EMPTY'
    Assert-Condition ($Name -match '^[A-Za-z][A-Za-z0-9_.-]{0,31}$') 'ADMIN_USER_FORMAT'
    $builtins = @('administrator','guest','defaultaccount','wdagutilityaccount','defaultuser0','system','localservice','networkservice')
    Assert-Condition ($builtins -notcontains $Name.ToLowerInvariant()) 'ADMIN_USER_BUILTIN'
}

function Assert-Request([object]$Request, [string]$PathId) {
    Assert-Condition ($null -ne $Request) 'REQUEST_JSON_EMPTY'
    Assert-Condition ([int]$Request.schema_version -eq 1) 'REQUEST_SCHEMA_VERSION'
    Assert-Condition ([string]$Request.request_id -eq $PathId) 'REQUEST_ID_MISMATCH'
    Assert-Condition ([string]$Request.computer_name -ieq $script:ComputerName) 'COMPUTER_NAME_MISMATCH'
    Assert-AsciiAdminName ([string]$Request.admin_user)
    Assert-Condition (-not [String]::IsNullOrEmpty([string]$Request.password)) 'ADMIN_PASSWORD_MISSING'
    Assert-Condition (([string]$Request.data_policy) -in @('preserve','clear')) 'DATA_POLICY'
    Assert-Condition ($Request.PSObject.Properties.Name -contains 'clear_authorized') 'CLEAR_AUTHORIZATION_MISSING'
    if ([string]$Request.data_policy -eq 'clear') {
        Assert-Condition ([bool]$Request.clear_authorized) 'CLEAR_NOT_AUTHORIZED'
        Assert-Condition ($null -ne $Request.d_expected) 'DATA_IDENTITY_MISSING'
    }
    if ($null -ne $Request.d_expected) {
        foreach ($key in @('disk_guid','unique_guid','start_bytes','size_bytes','ntfs_serial')) {
            Assert-Condition ($Request.d_expected.PSObject.Properties.Name -contains $key) "DATA_IDENTITY_$($key.ToUpperInvariant())_MISSING"
        }
        Assert-Condition ([int64]$Request.d_expected.start_bytes -ge 0) 'DATA_IDENTITY_START'
        Assert-Condition ([int64]$Request.d_expected.size_bytes -gt 0) 'DATA_IDENTITY_SIZE'
    }
}

function Get-NormalizedGuid([object]$Value, [string]$Name) {
    $guid = [guid]::Empty
    Assert-Condition ([guid]::TryParse([string]$Value, [ref]$guid)) "DATA_$($Name.ToUpperInvariant())_GUID"
    return $guid.ToString('D').ToLowerInvariant()
}

function Get-NtfsSerial64([string]$DriveLetter) {
    $stream = [IO.FileStream]::new("\\.\$DriveLetter`:",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $sector = [byte[]]::new(512); $offset = 0
        while ($offset -lt 512) {
            $read = $stream.Read($sector,$offset,512-$offset)
            Assert-Condition ($read -gt 0) 'DATA_NTFS_VBR_READ'
            $offset += $read
        }
        Assert-Condition ([Text.Encoding]::ASCII.GetString($sector,3,8) -eq 'NTFS    ') 'DATA_NOT_NTFS'
        return [BitConverter]::ToUInt64($sector,72).ToString('x16')
    } finally { $stream.Dispose() }
}

function Get-DataIdentity {
    $part = Get-Partition -DriveLetter 'D' -ErrorAction Stop
    $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    [pscustomobject]@{
        disk_guid = Get-NormalizedGuid $disk.Guid 'DISK'
        unique_guid = Get-NormalizedGuid $part.Guid 'PARTITION'
        start_bytes = [int64]$part.Offset
        size_bytes = [int64]$part.Size
        ntfs_serial = Get-NtfsSerial64 'D'
        disk_number = [int]$part.DiskNumber
    }
}

function Assert-DataIdentity([object]$Expected, [object]$Actual) {
    foreach ($key in @('disk_guid','unique_guid','start_bytes','size_bytes','ntfs_serial')) {
        Assert-Condition ([string]$Expected.$key -eq [string]$Actual.$key) "DATA_IDENTITY_$($key.ToUpperInvariant())_MISMATCH"
    }
}

function Assert-DataIsSafeToClear([object]$Identity) {
    $bitlocker = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
    Assert-Condition ($null -ne $bitlocker) 'DATA_BITLOCKER_CHECK_UNAVAILABLE'
    $state = Get-BitLockerVolume -MountPoint 'D:' -ErrorAction Stop
    Assert-Condition ([string]$state.VolumeStatus -eq 'FullyDecrypted' -and [string]$state.ProtectionStatus -eq 'Off') 'DATA_BITLOCKER_PRESENT'
    $pending = [Collections.Generic.Stack[string]]::new(); $pending.Push('D:\')
    while ($pending.Count -gt 0) {
        $path = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail 'DATA_EFS_SCAN_REPARSE' }
            if ($item.Attributes -band [IO.FileAttributes]::Encrypted) { Fail 'DATA_EFS_PRESENT' }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
    $disk = Get-Disk -Number ([int]$Identity.disk_number) -ErrorAction Stop
    foreach ($p in @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)) {
        Assert-Condition ([string]$p.Type -notmatch '(?i)unknown') 'DATA_UNKNOWN_PARTITION'
    }
}

function Get-StagePath([string]$RequestId) { Join-Path $script:StateRoot "owner-stage-$RequestId.json" }
function Get-ResultPath([string]$RequestId) { Join-Path $script:StateRoot "owner-result-$RequestId.json" }

function Write-JsonAtomically([string]$Path, [object]$Value) {
    $tmp = "$Path.tmp-$([guid]::NewGuid().ToString('N'))"
    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    [IO.File]::WriteAllText($tmp, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Set-Stage([string]$RequestId, [string]$Stage, [object]$Identity) {
    Write-JsonAtomically (Get-StagePath $RequestId) ([pscustomobject]@{
        schema_version=1; request_id=$RequestId; stage=$Stage; data_identity=$Identity
        updated_utc=[DateTime]::UtcNow.ToString('o')
    })
}

function Get-LocalAdmin([string]$Name) {
    Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
}

function Set-OwnerAccount([string]$Name, [string]$Password) {
    $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $user = Get-LocalAdmin $Name
    if ($null -eq $user) {
        $user = New-LocalUser -Name $Name -Password $secure -AccountNeverExpires -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -Description 'VirtOps selected VM owner'
    } else {
        Set-LocalUser -Name $Name -Password $secure -AccountNeverExpires:$false -PasswordNeverExpires:$false -UserMayChangePassword:$true
        Enable-LocalUser -Name $Name
    }
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $member = @(Get-LocalGroupMember -SID $adminSid -ErrorAction Stop | Where-Object { $_.SID.Value -eq $user.SID.Value })
    if ($member.Count -eq 0) {
        Add-LocalGroupMember -SID $adminSid -Member $Name -ErrorAction Stop
        $member = @(Get-LocalGroupMember -SID $adminSid -ErrorAction Stop | Where-Object { $_.SID.Value -eq $user.SID.Value })
        Assert-Condition ($member.Count -eq 1) 'ADMIN_GROUP_MEMBERSHIP_VERIFY'
    }
    return $user
}

function Disable-OtherCustomUsers([string]$KeepName) {
    $computerSid = (Get-LocalUser -Name $KeepName -ErrorAction Stop).SID.AccountDomainSid.Value
    foreach ($user in @(Get-LocalUser)) {
        if ($user.Name -ieq $KeepName -or -not $user.Enabled) { continue }
        $rid = [int]($user.SID.Value -split '-' | Select-Object -Last 1)
        if ($user.SID.AccountDomainSid.Value -eq $computerSid -and $rid -notin @(500,501)) {
            Disable-LocalUser -Name $user.Name
        }
    }
}

function Invoke-OwnerApply([object]$Request, [string]$RequestId) {
    $resultPath = Get-ResultPath $RequestId
    if (Test-Path -LiteralPath $resultPath) {
        $old = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        if ([string]$old.state -eq 'succeeded') { return $old }
    }
    $stage = $null
    $stagePath = Get-StagePath $RequestId
    if (Test-Path -LiteralPath $stagePath) {
        $stage = Get-Content -LiteralPath $stagePath -Raw | ConvertFrom-Json
        if ([string]$stage.stage -eq 'clear-started') { Fail 'D_CLEAR_INTERRUPTED_REQUIRES_EXPLICIT_RECOVERY' }
    }
    $identity = $null
    if (($Request.PSObject.Properties.Name -contains 'preflight_only') -and [bool]$Request.preflight_only) {
        if ($null -ne $Request.d_expected) {
            $identity = Get-DataIdentity
            Assert-DataIdentity $Request.d_expected $identity
            Assert-DataIsSafeToClear $identity
        } else {
            Assert-Condition ($null -eq (Get-Partition -DriveLetter 'D' -ErrorAction SilentlyContinue)) 'UNEXPECTED_DATA_PARTITION'
        }
        return [pscustomobject]@{schema_version=1;state='succeeded';preflight_only=$true;request_id=$RequestId;data_policy=[string]$Request.data_policy}
    }
    $resumed = $false
    if ($null -ne $stage -and [string]$Request.data_policy -eq 'clear' -and [string]$stage.stage -in @('clear-complete','account-started')) {
        $current = Get-DataIdentity
        foreach ($key in @('disk_guid','unique_guid','start_bytes','size_bytes')) {
            Assert-Condition ([string]$current.$key -eq [string]$Request.d_expected.$key) "DATA_IDENTITY_$($key.ToUpperInvariant())_MISMATCH"
        }
        foreach ($key in @('disk_guid','unique_guid','start_bytes','size_bytes','ntfs_serial')) {
            Assert-Condition ([string]$current.$key -eq [string]$stage.data_identity.$key) "D_CLEAR_STAGE_$($key.ToUpperInvariant())_MISMATCH"
        }
        $identity = $current; $resumed = $true
    } elseif ($null -ne $Request.d_expected) {
        $identity = Get-DataIdentity
        Assert-DataIdentity $Request.d_expected $identity
    }
    if ([string]$Request.data_policy -eq 'clear') {
        if (-not $resumed) {
            Assert-DataIsSafeToClear $identity
            Set-Stage $RequestId 'clear-started' $identity
            Format-Volume -DriveLetter 'D' -FileSystem NTFS -Force -Confirm:$false | Out-Null
            $identity = Get-DataIdentity
            Set-Stage $RequestId 'clear-complete' $identity
        }
    }
    Set-Stage $RequestId 'account-started' $identity
    Set-OwnerAccount ([string]$Request.admin_user) ([string]$Request.password) | Out-Null
    Disable-OtherCustomUsers ([string]$Request.admin_user)
    $result = [pscustomobject]@{
        schema_version=1; request_id=$RequestId; state='succeeded'; computer_name=$script:ComputerName
        admin_user=[string]$Request.admin_user; data_policy=[string]$Request.data_policy
        d_identity=if($null -ne $Request.d_expected){Get-DataIdentity}else{$null}
        services=@('WinRM','TermService'); completed_utc=[DateTime]::UtcNow.ToString('o')
    }
    Write-JsonAtomically $resultPath $result
    return $result
}

$requestId = $null
try {
    $requestId = Assert-SafeRequestPath $RequestPath
    $request = Get-Content -LiteralPath $RequestPath -Raw -ErrorAction Stop | ConvertFrom-Json
    Assert-Request $request $requestId
    $result = Invoke-OwnerApply $request $requestId
    $result | ConvertTo-Json -Depth 8 -Compress
    exit 0
} catch {
    [pscustomobject]@{schema_version=1; request_id=$requestId; state='failed'; code= if($_.Exception.Message -match '^[A-Z0-9_]+$'){$_.Exception.Message}else{'OWNER_APPLY_FAILED'}} | ConvertTo-Json -Compress
    exit 1
}
