[CmdletBinding()]
param(
    [string]$Vm = 'winvm01',
    [string]$DiskPath = '/home/vm_run/vol/current.qcow2'
)

# QGA runs this as LocalSystem.  It only observes guest state and, when a
# target D: exists on the system disk, creates a fixed-size integrity sentinel.
# It deliberately does not set BitLocker/device-encryption policy or change
# drive letters, partitions, EFS, TPM, or network configuration.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-NormalizedGuid {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $guid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Value, [ref]$guid)) {
        throw "$Name is absent or is not a GUID."
    }
    return $guid.ToString('D').ToLowerInvariant()
}

function Get-NtfsSerial64 {
    param([Parameter(Mandatory = $true)][ValidatePattern('^[A-Z]$')][string]$DriveLetter)

    # NTFS stores its 64-bit volume serial at byte offset 72 (0x48) of the
    # 512-byte VBR.  Win32_LogicalDisk.VolumeSerialNumber is a different,
    # 32-bit GetVolumeInformation value and must not be used for reset proof.
    $devicePath = '\\.\' + $DriveLetter + ':'
    $stream = [System.IO.FileStream]::new(
        $devicePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    try {
        $bootSector = [byte[]]::new(512)
        $position = 0
        while ($position -lt $bootSector.Length) {
            $read = $stream.Read($bootSector, $position, $bootSector.Length - $position)
            if ($read -le 0) {
                throw "Unable to read a complete NTFS VBR from $DriveLetter`:"
            }
            $position += $read
        }
        if ([System.Text.Encoding]::ASCII.GetString($bootSector, 3, 8) -ne 'NTFS    ') {
            throw "$DriveLetter`: does not expose an NTFS VBR."
        }
        return ([System.BitConverter]::ToUInt64($bootSector, 72).ToString('x16'))
    }
    finally {
        $stream.Dispose()
    }
}

function Get-PartitionEvidence {
    param(
        [Parameter(Mandatory = $true)]$Partition,
        [Parameter(Mandatory = $true)][string]$DriveLetter
    )

    return [ordered]@{
        index          = [int64]$Partition.PartitionNumber
        start_bytes    = [uint64]$Partition.Offset
        size_bytes     = [uint64]$Partition.Size
        unique_guid    = Get-NormalizedGuid -Value $Partition.Guid -Name "$DriveLetter partition GUID"
        ntfs_serial    = Get-NtfsSerial64 -DriveLetter $DriveLetter
    }
}

function Test-CleanEfsOnC {
    # /u finds encrypted files on local drives, /n makes no change, and /b
    # aborts at an error.  A non-zero exit is deliberately fail-closed.
    $cipherOutput = @(& "$env:SystemRoot\System32\cipher.exe" /u /n /b 2>&1 | ForEach-Object { [string]$_ })
    $cipherExitCode = $LASTEXITCODE
    if ($cipherExitCode -ne 0) {
        throw "cipher /u /n /b failed with exit code $cipherExitCode; refusing to claim C: has no EFS files."
    }

    foreach ($line in $cipherOutput) {
        # cipher lists discovered files by their local absolute path.  Do not
        # try to recognize localized status text; any reported C: path fails.
        if ($line -match '(?i)(^|\s)C:\\') {
            throw 'cipher reported at least one C: EFS file; refusing reset context.'
        }
    }
    return $true
}

function Get-BitLockerState {
    param([Parameter(Mandatory = $true)][string]$MountPoint)

    $volume = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
    return [ordered]@{
        fully_decrypted = ([string]$volume.VolumeStatus -eq 'FullyDecrypted')
        protection_off  = ([string]$volume.ProtectionStatus -eq 'Off')
    }
}

function Get-DValidationSentinel {
    $directory = 'D:\WinVM01ResetProbe'
    $path = Join-Path $directory 'sentinel.bin'

    if (Test-Path -LiteralPath $directory) {
        $existingDirectory = Get-Item -LiteralPath $directory -Force
        if (-not $existingDirectory.PSIsContainer -or
            (([int]$existingDirectory.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'D reset probe directory is not a normal directory.'
        }
    }
    else {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    if (Test-Path -LiteralPath $path) {
        $existingFile = Get-Item -LiteralPath $path -Force
        if ($existingFile.PSIsContainer -or
            (([int]$existingFile.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $existingFile.Length -ne 4096) {
            throw 'D reset sentinel is not a normal 4096-byte file.'
        }
    }
    else {
        $bytes = [byte[]]::new(4096)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($bytes)
        }
        finally {
            $rng.Dispose()
        }
        [System.IO.File]::WriteAllBytes($path, $bytes)
    }

    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($hash -notmatch '^[0-9a-f]{64}$') {
        throw 'D reset sentinel SHA-256 is malformed.'
    }
    return [ordered]@{
        path   = $path
        sha256 = $hash
    }
}

try {
    $cPartition = Get-Partition -DriveLetter 'C' -ErrorAction Stop
    $disk = Get-Disk -Number $cPartition.DiskNumber -ErrorAction Stop
    if ([string]$disk.PartitionStyle -ne 'GPT') {
        throw 'C: is not on a GPT disk.'
    }

    $diskGuid = Get-NormalizedGuid -Value $disk.Guid -Name 'GPT disk GUID'
    $cEvidence = Get-PartitionEvidence -Partition $cPartition -DriveLetter 'C'

    $cBitLocker = Get-BitLockerState -MountPoint 'C:'
    if (-not $cBitLocker.fully_decrypted -or -not $cBitLocker.protection_off) {
        throw 'C: is not fully decrypted with BitLocker protection off.'
    }
    [void](Test-CleanEfsOnC)

    $partitions = [ordered]@{ C = $cEvidence }
    $dValidation = $null
    $dPartition = Get-Partition -DriveLetter 'D' -ErrorAction SilentlyContinue
    if ($null -ne $dPartition -and [uint32]$dPartition.DiskNumber -eq [uint32]$disk.Number) {
        $dVolume = Get-Volume -DriveLetter 'D' -ErrorAction Stop
        if ([string]$dVolume.FileSystem -ne 'NTFS') {
            throw 'D: is on the Windows disk but is not NTFS.'
        }

        $dBitLocker = Get-BitLockerState -MountPoint 'D:'
        $dEncrypted = (-not $dBitLocker.fully_decrypted) -or (-not $dBitLocker.protection_off)
        $sentinel = Get-DValidationSentinel
        $dEvidence = Get-PartitionEvidence -Partition $dPartition -DriveLetter 'D'
        $dEvidence.Add('sentinel_hash', $sentinel.sha256)
        $partitions.Add('D', $dEvidence)
        $dValidation = [ordered]@{ sentinels = @($sentinel) }
    }
    else {
        $dEncrypted = $false
    }

    $efiType = [guid]'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
    $efiCandidates = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop | Where-Object {
            $candidateGuid = [guid]::Empty
            [guid]::TryParse([string]$_.GptType, [ref]$candidateGuid) -and $candidateGuid -eq $efiType
        })
    if ($efiCandidates.Count -ne 1) {
        throw "Expected exactly one GPT EFI system partition, found $($efiCandidates.Count)."
    }
    $efi = $efiCandidates[0]

    $context = [ordered]@{
        vm        = $Vm
        disk_path = $DiskPath
        disk      = [ordered]@{
            disk_guid  = $diskGuid
            size_bytes = [uint64]$disk.Size
            partitions = $partitions
        }
        security  = [ordered]@{
            c_fully_decrypted = $true
            c_protection_off  = $true
            c_efs_encrypted   = $false
            d_encrypted       = [bool]$dEncrypted
        }
        efi_observed = [ordered]@{
            index       = [int64]$efi.PartitionNumber
            start_bytes = [uint64]$efi.Offset
            size_bytes  = [uint64]$efi.Size
            unique_guid = Get-NormalizedGuid -Value $efi.Guid -Name 'EFI partition GUID'
        }
    }
    if ($null -ne $dValidation) {
        $context.Add('d_validation', $dValidation)
    }

    $context | ConvertTo-Json -Depth 8 -Compress
}
catch {
    Write-Error "winvm01 reset context collection failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 2
}
