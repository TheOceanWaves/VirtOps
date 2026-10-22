[CmdletBinding()]
param([Parameter(Mandatory)][string]$BuilderAdmin,[switch]$DiscardBuilder)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Only the explicitly designated disposable builder is accepted. A normal
# user's installed VM is not a template and must never pass this preflight.
$cs=Get-CimInstance Win32_ComputerSystem
if($cs.PartOfDomain){throw 'BUILDER_DOMAIN_JOINED'}
$builder=Get-LocalUser -Name $BuilderAdmin -ErrorAction Stop
$custom=@(Get-LocalUser|Where-Object {[int]($_.SID.Value.Split('-')[-1]) -ge 1000})
if($custom.Count -ne 1 -or $custom[0].SID.Value -ne $builder.SID.Value){throw 'BUILDER_OTHER_ACCOUNTS'}
$profiles=@(Get-CimInstance Win32_UserProfile|Where-Object {-not $_.Special})
if(@($profiles|Where-Object {$_.SID -ne $builder.SID.Value -or $_.Loaded}).Count){throw 'BUILDER_PROFILE_IN_USE_OR_FOREIGN'}
if(@(Get-Volume|Where-Object {$_.DriveLetter -and $_.DriveLetter -ne 'C' -and $_.DriveType -eq 'Fixed'}).Count){throw 'BUILDER_DATA_VOLUME_PRESENT'}
if((Get-ChildItem -LiteralPath C:\Work -Force -ErrorAction Stop|Measure-Object).Count){throw 'BUILDER_WORKSPACE_NOT_EMPTY'}
$encryption=Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
if([string]$encryption.VolumeStatus -ne 'FullyDecrypted' -or [string]$encryption.ProtectionStatus -ne 'Off'){throw 'BUILDER_DISK_ENCRYPTED'}
$c=Get-Partition -DriveLetter C -ErrorAction Stop
$edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
if($edition -notmatch '^(Professional|Enterprise)'){throw 'BUILDER_EDITION'}
$result=[ordered]@{state='preflight_passed';builder_account=$builder.Name;edition=$edition;architecture='amd64';c_partition=@{index=[int]$c.PartitionNumber;start_bytes=[long]$c.Offset;size_bytes=[long]$c.Size;unique_guid=([guid]$c.Guid).ToString()}}
if(-not $DiscardBuilder){$result|ConvertTo-Json -Depth 4 -Compress;exit 0}
# Source profile data removal is authorized by the explicit dedicated-builder
# operation. No other account/profile or data volume is deleted.
foreach($profile in $profiles){Remove-CimInstance -InputObject $profile -ErrorAction Stop}
Remove-LocalUser -SID $builder.SID -ErrorAction Stop
$administrator=Get-LocalUser|Where-Object {$_.SID.Value.EndsWith('-500')}
Set-LocalUser -SID $administrator.SID -Password ([Security.SecureString]::new())
Disable-LocalUser -SID $administrator.SID
$winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword,DefaultUserName,DefaultDomainName -ErrorAction SilentlyContinue
Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
$listeners=@(Get-ChildItem WSMan:\localhost\Listener)
foreach($listener in $listeners){
    $pin=(Get-Item ($listener.PSPath+'\CertificateThumbprint') -ErrorAction SilentlyContinue).Value
    if($pin){Remove-Item -LiteralPath ('Cert:\LocalMachine\My\'+$pin) -Force -ErrorAction Stop}
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
Get-ChildItem 'Cert:\LocalMachine\Remote Desktop' -ErrorAction SilentlyContinue|Remove-Item -Force
foreach($dir in @('C:\Windows\Panther','C:\Windows\Panther\Unattend')){
    Get-ChildItem -LiteralPath $dir -Filter '*unattend*.xml' -ErrorAction SilentlyContinue|Remove-Item -Force
}
Remove-Item -LiteralPath C:\Windows\Setup\Scripts\remote-windows-provision.ps1 -Force -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Temp -Filter '*-provision.*' -ErrorAction SilentlyContinue|Remove-Item -Force
# Sysprep resets machine identity. The host waits for shutdown and independently
# reads Windows Setup's offline ImageState before publishing anything.
$sysprep=Join-Path $env:SystemRoot 'System32\Sysprep\Sysprep.exe'
$process=Start-Process -FilePath $sysprep -ArgumentList '/generalize','/oobe','/shutdown','/quiet' -PassThru
$result.state='sysprep_started';$result.builder_account_removed=$true
$result|ConvertTo-Json -Depth 4 -Compress
