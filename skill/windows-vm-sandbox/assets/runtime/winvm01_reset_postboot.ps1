#requires -Version 5.1
<#
Post-boot evidence task for a C-only recovery of winvm01.

Install this baseline file at:
  C:\ProgramData\WinVM01\winvm01_reset_postboot.ps1

The task runs as SYSTEM at every Windows startup.  It is a no-op unless the
root-projected, size-limited reset-request.json exists.  The request is data,
not a script: this file reads only the fixed fields documented below and never
invokes a JSON value as a command, path to execute, or PowerShell expression.

Request schema v1 (all GUID values may include braces):
{
  "schema_version": 1,
  "request_id": "uuid-or-token",
  "disk": {
    "disk_guid": "GPT disk GUID",
    "size_bytes": 0,
    "partitions": {
      "C": {"index": 3, "size_bytes": 0, "unique_guid": "GUID", "ntfs_serial": "hex"},
      "D": {"index": 4, "size_bytes": 0, "unique_guid": "GUID", "ntfs_serial": "hex"}
    }
  },
  "d_validation": {
    "sentinels": [{"path": "D:\safe\known-file.bin", "sha256": "64 lowercase/uppercase hex"}]
  }
}

The context projection comes from QGA evidence. D is optional. If D exists,
validate its identity and any supplied data sentinels. No D data is restored.
#>

[CmdletBinding()]
param(
    [switch]$InstallStartupTask
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = 'C:\ProgramData\WinVM01'
$RequestPath = Join-Path $Root 'reset-request.json'
$ResultPath = Join-Path $Root 'reset-result.json'
$TaskName = '\WinVM01\PostBootResetValidation'
$MaxRequestBytes = 64KB
$ExpectedDiskSizeBytes = [Int64]150 * 1GB

function ConvertTo-NormalGuid {
    param([Parameter(Mandatory=$true)][object]$Value)
    try {
        return ([guid]([string]$Value)).ToString('D').ToLowerInvariant()
    } catch {
        throw "invalid GUID value"
    }
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory=$true)][object]$Object,
        [Parameter(Mandatory=$true)][string]$Name
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "request lacks required field: $Name"
    }
    return $property.Value
}

function Get-ExpectedPartition {
    param(
        [Parameter(Mandatory=$true)][object]$Partitions,
        [Parameter(Mandatory=$true)][string]$Name
    )
    $value = Get-RequiredProperty $Partitions $Name
    $index = [int](Get-RequiredProperty $value 'index')
    $size = [Int64](Get-RequiredProperty $value 'size_bytes')
    $guid = ConvertTo-NormalGuid (Get-RequiredProperty $value 'unique_guid')
    $serial = [string](Get-RequiredProperty $value 'ntfs_serial')
    if ($index -lt 1 -or $size -le 0 -or $serial -notmatch '^[0-9A-Fa-f]{8,16}$') {
        throw "invalid $Name partition evidence"
    }
    return [pscustomobject]@{
        Name = $Name; Index = $index; SizeBytes = $size; Guid = $guid
        NtfsSerial = $serial.ToLowerInvariant()
    }
}

function ConvertTo-NormalNtfsSerial {
    param([Parameter(Mandatory=$true)][object]$Value)
    $serial = ([string]$Value -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
    if ($serial -notmatch '^[0-9a-f]{8,16}$') { throw 'invalid NTFS serial value' }
    return $serial.PadLeft(16, '0')
}

function Test-NtfsSerialMatch {
    param(
        [Parameter(Mandatory=$true)][object]$Expected,
        [Parameter(Mandatory=$true)][object]$Observed
    )
    $rawExpected = ([string]$Expected -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
    $expectedSerial = ConvertTo-NormalNtfsSerial $rawExpected
    $observedSerial = ConvertTo-NormalNtfsSerial $Observed
    # A legacy 8-digit evidence value is the low 32 bits; full 16-digit values match exactly.
    if ($rawExpected.Length -eq 8) {
        return $expectedSerial.Substring(8) -eq $observedSerial.Substring(8)
    }
    return $expectedSerial -eq $observedSerial
}

function Get-DriveNtfsSerial {
    param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Z]$')][string]$Letter)
    $devicePath = "\\.\$Letter`:"
    $stream = $null
    try {
        $stream = [IO.File]::Open($devicePath, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        # Raw volume handles require sector-aligned reads. Read the full VBR
        # at offset zero, then inspect its fields in memory.
        $boot = New-Object byte[] 512
        if ($stream.Read($boot, 0, $boot.Length) -ne $boot.Length -or
            [Text.Encoding]::ASCII.GetString($boot, 3, 8) -ne 'NTFS    ') {
            throw ("{0}: is not an ordinary NTFS volume" -f $Letter)
        }
        return ('{0:x16}' -f [BitConverter]::ToUInt64($boot, 72))
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Set-WinVmAcl {
    if (-not (Test-Path -LiteralPath $Root)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($rule in @(
        (New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),
            [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $propagation, $allow)),
        (New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')),
            [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $propagation, $allow)),
        (New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')),
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, $propagation, $allow))
    )) {
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Root -AclObject $acl
}

function Write-Result {
    param([Parameter(Mandatory=$true)][object]$Value)
    $temporary = Join-Path $Root ('.reset-result-' + [guid]::NewGuid().ToString('N') + '.json')
    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 64KB) {
        throw 'refusing oversized result metadata'
    }
    [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $ResultPath -Force
}

function Read-Request {
    if (-not (Test-Path -LiteralPath $RequestPath -PathType Leaf)) {
        return $null
    }
    $item = Get-Item -LiteralPath $RequestPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'reset request must not be a reparse point'
    }
    if ($item.Length -le 0 -or $item.Length -gt $MaxRequestBytes) {
        throw 'reset request is empty or exceeds 64 KiB'
    }
    $raw = [IO.File]::ReadAllText($RequestPath, [Text.UTF8Encoding]::new($false))
    try {
        return $raw | ConvertFrom-Json
    } catch {
        throw 'reset request is not valid JSON'
    }
}

function Get-BitLockerEvidence {
    param([Parameter(Mandatory=$true)][object]$Partition)
    $volume = Get-Volume -Partition $Partition
    $mounts = @()
    if ($volume.DriveLetter) { $mounts += ('{0}:' -f $volume.DriveLetter) }
    if ($volume.PSObject.Properties['Path'] -and $volume.Path) { $mounts += [string]$volume.Path }
    $bitLocker = @(Get-BitLockerVolume)
    $record = $bitLocker | Where-Object {
        $candidate = @($_.MountPoint | ForEach-Object { [string]$_ })
        (@($candidate | Where-Object { $mounts -contains $_ })).Count -gt 0
    } | Select-Object -First 1
    if ($null -eq $record) {
        throw 'cannot prove D: BitLocker state'
    }
    $volumeStatus = [string]$record.VolumeStatus
    $protectionStatus = [string]$record.ProtectionStatus
    if ($volumeStatus -ne 'FullyDecrypted' -or $protectionStatus -eq 'On') {
        throw "D: BitLocker state is unsafe: volume=$volumeStatus protection=$protectionStatus"
    }
    return [pscustomobject]@{
        Volume = $volume; VolumeStatus = $volumeStatus; ProtectionStatus = $protectionStatus
    }
}

function Restore-DLetter {
    param([Parameter(Mandatory=$true)][object]$TargetPartition)
    $targetGuid = ConvertTo-NormalGuid $TargetPartition.Guid
    $targetLetter = [string]$TargetPartition.DriveLetter
    if ($targetLetter -eq 'D') { return }

    $occupiedPartition = Get-Partition -DriveLetter D -ErrorAction SilentlyContinue
    if ($occupiedPartition) {
        if ((ConvertTo-NormalGuid $occupiedPartition.Guid) -eq $targetGuid) { return }
        throw 'D: belongs to a data partition other than the expected D partition; refusing to move it'
    }
    $occupiedVolume = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue
    if ($occupiedVolume) {
        if ([string]$occupiedVolume.DriveType -notmatch 'CD-ROM|CDROM') {
            throw 'D: is occupied by a non-CDROM volume; refusing to move it'
        }
        if (Get-Volume -DriveLetter Z -ErrorAction SilentlyContinue) {
            throw 'D: is CDROM but Z: is occupied; refusing to change a drive letter'
        }
        Set-Volume -DriveLetter D -NewDriveLetter Z
    }
    Set-Partition -DiskNumber $TargetPartition.DiskNumber -PartitionNumber $TargetPartition.PartitionNumber -NewDriveLetter D
    $confirmed = Get-Partition -DriveLetter D -ErrorAction Stop
    if ((ConvertTo-NormalGuid $confirmed.Guid) -ne $targetGuid) {
        throw 'D: was not assigned to the expected data partition'
    }
}

function Test-DSentinels {
    param([Parameter(Mandatory=$true)][object]$Sentinels)
    $results = @()
    $entries = @($Sentinels)
    if ($entries.Count -lt 1 -or $entries.Count -gt 16) {
        throw 'D sentinel list must contain 1-16 entries'
    }
    foreach ($entry in $entries) {
        $path = [string](Get-RequiredProperty $entry 'path')
        $expectedHash = [string](Get-RequiredProperty $entry 'sha256')
        if ($path -notmatch '^[dD]:\\' -or $path.Contains('..') -or $path.IndexOfAny([char[]]'*?') -ge 0) {
            throw 'sentinel path must be a literal D: file path'
        }
        if ($expectedHash -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'sentinel SHA-256 is malformed'
        }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "D sentinel is absent: $path"
        }
        $resolved = (Resolve-Path -LiteralPath $path).Path
        if (-not $resolved.StartsWith('D:\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'sentinel resolution escaped D:'
        }
        $actualHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash.ToLowerInvariant()) {
            throw "D sentinel hash differs: $path"
        }
        $results += [pscustomobject]@{ path = $path; sha256 = $actualHash }
    }
    return $results
}

function Invoke-PostBootValidation {
    Set-WinVmAcl
    $request = Read-Request
    if ($null -eq $request) {
        Write-Result ([ordered]@{ state = 'noop'; time_utc = [DateTime]::UtcNow.ToString('o'); detail = 'no reset request' })
        return
    }

    $requestId = 'unknown'
    try {
        if ([int](Get-RequiredProperty $request 'schema_version') -ne 1) { throw 'unsupported request schema' }
        $requestId = [string](Get-RequiredProperty $request 'request_id')
        if ($requestId -notmatch '^[A-Za-z0-9._-]{1,80}$') { throw 'invalid request_id' }
        $diskEvidence = Get-RequiredProperty $request 'disk'
        $expectedDiskGuid = ConvertTo-NormalGuid (Get-RequiredProperty $diskEvidence 'disk_guid')
        $expectedDiskSize = [Int64](Get-RequiredProperty $diskEvidence 'size_bytes')
        if ($expectedDiskSize -ne $ExpectedDiskSizeBytes) { throw 'invalid GPT disk size evidence' }
        $parts = Get-RequiredProperty $diskEvidence 'partitions'
        $expectedC = Get-ExpectedPartition $parts 'C'
        $expectedD = $null
        $sentinels = @()
        if ($parts.PSObject.Properties['D']) {
            $expectedD = Get-ExpectedPartition $parts 'D'
            $sentinels = Get-RequiredProperty (Get-RequiredProperty $request 'd_validation') 'sentinels'
        }

        $disk = Get-Disk | Where-Object {
            $_.PartitionStyle -eq 'GPT' -and (ConvertTo-NormalGuid $_.Guid) -eq $expectedDiskGuid
        } | Select-Object -First 1
        if ($null -eq $disk -or [Int64]$disk.Size -ne $expectedDiskSize) {
            throw 'current GPT disk GUID or size differs from reset evidence'
        }
        $currentC = Get-Partition -DriveLetter C -ErrorAction Stop
        if ($currentC.DiskNumber -ne $disk.Number -or $currentC.PartitionNumber -ne $expectedC.Index -or
            (ConvertTo-NormalGuid $currentC.Guid) -ne $expectedC.Guid -or
            [Int64]$currentC.Size -ne $expectedC.SizeBytes) {
            throw 'current C: partition GUID/index/disk differs from reset evidence'
        }
        $currentCSerial = Get-DriveNtfsSerial 'C'
        if (-not (Test-NtfsSerialMatch $expectedC.NtfsSerial $currentCSerial)) {
            throw 'current C: NTFS serial differs from reset evidence'
        }
        $dResult = $null
        $sentinelEvidence = @()
        if ($null -ne $expectedD) {
        $currentD = Get-Partition -DiskNumber $disk.Number | Where-Object {
            $_.PartitionNumber -eq $expectedD.Index -and (ConvertTo-NormalGuid $_.Guid) -eq $expectedD.Guid
        } | Select-Object -First 1
        if ($null -eq $currentD -or [Int64]$currentD.Size -ne $expectedD.SizeBytes) {
            throw 'current D: partition GUID/index/size differs from reset evidence'
        }
        $bitLocker = Get-BitLockerEvidence $currentD
        Restore-DLetter $currentD
        $currentD = Get-Partition -DriveLetter D -ErrorAction Stop
        $currentDSerial = Get-DriveNtfsSerial 'D'
        if (-not (Test-NtfsSerialMatch $expectedD.NtfsSerial $currentDSerial)) {
            throw 'current D: NTFS serial differs from reset evidence'
        }
        $sentinelEvidence = Test-DSentinels $sentinels
        $dResult = [ordered]@{
            guid = $expectedD.Guid; index = $expectedD.Index; letter = [string]$currentD.DriveLetter
            ntfs_serial = $currentDSerial
            volume_status = $bitLocker.VolumeStatus; protection_status = $bitLocker.ProtectionStatus
        }
        }

        $result = [ordered]@{
            state = 'success'; time_utc = [DateTime]::UtcNow.ToString('o'); request_id = $requestId
            disk = [ordered]@{ guid = $expectedDiskGuid; number = $disk.Number; size_bytes = [Int64]$disk.Size; serial = ([string]$disk.SerialNumber).Trim() }
            c = [ordered]@{ guid = $expectedC.Guid; index = $expectedC.Index; letter = 'C'; ntfs_serial = $currentCSerial }
            d = $dResult
            sentinels = $sentinelEvidence
        }
        Write-Result $result
        Move-Item -LiteralPath $RequestPath -Destination (Join-Path $Root ('reset-request.handled.' + $requestId + '.json')) -Force
    } catch {
        $safeError = ($_.Exception.Message -replace '[\r\n]+', ' ').Substring(0, [Math]::Min(400, ($_.Exception.Message -replace '[\r\n]+', ' ').Length))
        Write-Result ([ordered]@{
            state = 'failed'; time_utc = [DateTime]::UtcNow.ToString('o'); request_id = $requestId; error = $safeError
        })
        if (Test-Path -LiteralPath $RequestPath -PathType Leaf) {
            Move-Item -LiteralPath $RequestPath -Destination (Join-Path $Root ('reset-request.failed.' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '.json')) -Force
        }
        throw
    }
}

function Register-PostBootTask {
    Set-WinVmAcl
    $script = $PSCommandPath
    if (-not $script -or -not (Test-Path -LiteralPath $script -PathType Leaf)) {
        throw 'script path is unavailable for task registration'
    }
    $hostExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $hostExe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $script + '"')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

if ($InstallStartupTask) {
    Register-PostBootTask
    return
}

Invoke-PostBootValidation
