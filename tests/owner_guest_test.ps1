[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$tool = Join-Path (Split-Path -Parent $PSScriptRoot) 'skill\windows-vm-sandbox\assets\runtime\owner_apply.ps1'
$verify = Join-Path (Split-Path -Parent $PSScriptRoot) 'skill\windows-vm-sandbox\assets\runtime\owner_verify.ps1'
if (-not (Test-Path -LiteralPath $tool)) { throw "missing owner helper: $tool" }
$bytes = [IO.File]::ReadAllBytes($tool)
if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) { throw 'owner helper must be UTF-8 BOM' }
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($tool, [ref]$null, [ref]$errors)
if ($errors.Count) { throw "owner helper parse failed: $(($errors | ForEach-Object Message) -join '; ')" }

$script:StateRoot = 'C:\ProgramData\VirtOps'
$script:ComputerName = 'TESTVM'
$wanted = @('Fail','Assert-Condition','Get-RequestIdFromPath','Assert-AsciiAdminName','Assert-Request','Assert-DataIdentity','Get-NormalizedGuid','Get-StagePath','Get-ResultPath','Write-JsonAtomically','Set-Stage','Invoke-OwnerApply')
foreach ($name in $wanted) {
    $fn = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
    if ($null -eq $fn) { throw "missing pure validation function: $name" }
    Invoke-Expression $fn.Extent.Text
}

function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
function Reject([scriptblock]$Action, [string]$Message) {
    $failed = $false
    try { & $Action } catch { $failed = $true }
    Assert $failed $Message
}

Assert-AsciiAdminName 'alice_01'
Assert ((Get-NormalizedGuid ([guid]::Parse('AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA')) 'TEST') -eq 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') 'GUID normalization failed'
Reject { Get-NormalizedGuid 'not-a-guid' 'TEST' } 'invalid GUID accepted'

# Mock only the account, volume and identity primitives. This exercises the
# clear-complete retry branch without touching LocalAccounts or a real disk.
$mockRoot = Join-Path (Join-Path $PSScriptRoot '.validation') ('virtops-owner-mock-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $mockRoot -Force | Out-Null
$script:StateRoot = $mockRoot
$script:formatCalls = 0
function Get-DataIdentity { [pscustomobject]@{disk_guid='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';unique_guid='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';start_bytes=4096;size_bytes=8192;ntfs_serial='1111222233334444';disk_number=7} }
function Assert-DataIdentity([object]$Expected,[object]$Actual) { foreach($k in @('disk_guid','unique_guid','start_bytes','size_bytes','ntfs_serial')) { if([string]$Expected.$k -ne [string]$Actual.$k){throw 'mock identity mismatch'} } }
function Assert-DataIsSafeToClear([object]$Identity) { throw 'format path should not be entered during clear-complete retry' }
function Format-Volume { $script:formatCalls++ ; throw 'format path unexpectedly called' }
function Set-OwnerAccount([string]$Name,[string]$Password) { $script:accountCalls++ }
function Disable-OtherCustomUsers([string]$Name) { }
$script:accountCalls=0
$mockId='22222222-2222-4222-8222-222222222222'
$mockIdentity=Get-DataIdentity
Set-Stage $mockId 'clear-complete' $mockIdentity
$oldIdentity=[pscustomobject]@{disk_guid=$mockIdentity.disk_guid;unique_guid=$mockIdentity.unique_guid;start_bytes=$mockIdentity.start_bytes;size_bytes=$mockIdentity.size_bytes;ntfs_serial='old-before-format';disk_number=$mockIdentity.disk_number}
$mockRequest=[pscustomobject]@{data_policy='clear';d_expected=$oldIdentity;admin_user='alice';password='secret';clear_authorized=$true}
$mockResult=Invoke-OwnerApply $mockRequest $mockId
Assert ([string]$mockResult.state -eq 'succeeded') 'clear-complete retry did not finish account handoff'
Assert ($script:formatCalls -eq 0) 'clear-complete retry formatted D twice'
Assert ($script:accountCalls -eq 1) 'clear-complete retry did not apply owner account'
$script:preflightCalls=0
function Assert-DataIsSafeToClear([object]$Identity) { [void]($script:preflightCalls++); return }
$preflightId='33333333-3333-4333-8333-333333333333'
$preflightRequest=[pscustomobject]@{preflight_only=$true;data_policy='preserve';d_expected=$mockIdentity;admin_user='alice';password='secret';clear_authorized=$false}
$preflightResult=@(Invoke-OwnerApply $preflightRequest $preflightId)
Assert ($preflightResult.Count -eq 1) 'preflight emitted unexpected extra output'
Assert ([string]$preflightResult[0].state -eq 'succeeded' -and [bool]$preflightResult[0].preflight_only) 'preflight did not return success'
Assert ($script:preflightCalls -eq 1) 'preflight did not run read-only data safety checks'
Assert ($script:accountCalls -eq 1) 'preflight modified account state'
Assert (-not (Test-Path -LiteralPath (Get-StagePath $preflightId))) 'preflight wrote a transition stage'
function Get-Partition { param($DriveLetter,$ErrorAction) return $null }
$preflightRequest.d_expected=$null
$noDataResult=Invoke-OwnerApply $preflightRequest '44444444-4444-4444-8444-444444444444'
Assert ([bool]$noDataResult.preflight_only) 'C-only guest preflight failed without a D partition'
Assert ($script:accountCalls -eq 1) 'C-only preflight modified account state'
Assert ([IO.Path]::GetFullPath($mockRoot).StartsWith(([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)) 'mock cleanup escaped tests directory'
Remove-Item -LiteralPath $mockRoot -Recurse -Force
Reject { Assert-AsciiAdminName 'Administrator' } 'built-in Administrator accepted'
Reject { Assert-AsciiAdminName '管理员' } 'non-ASCII account accepted'
Reject { Assert-AsciiAdminName 'has space' } 'space-containing account accepted'

$base = [pscustomobject]@{
    schema_version=1; request_id='11111111-1111-4111-8111-111111111111'; computer_name='TESTVM'
    admin_user='alice'; password='DoNotPrintThisSecret!'; data_policy='preserve'
    data_expected=$null; clear_authorized=$false
}
# The production contract calls the field d_expected.
$base | Add-Member -NotePropertyName d_expected -NotePropertyValue $null
Assert-Request $base $base.request_id
$base | Add-Member -NotePropertyName preflight_only -NotePropertyValue $true
Assert-Request $base $base.request_id
Reject { Assert-Request ([pscustomobject]@{schema_version=1;request_id=$base.request_id;computer_name='OTHER';admin_user='alice';password='x';data_policy='preserve';d_expected=$null;clear_authorized=$false}) $base.request_id } 'computer mismatch accepted'
Reject { Assert-Request ([pscustomobject]@{schema_version=1;request_id=$base.request_id;computer_name='TESTVM';admin_user='alice';password='x';data_policy='clear';d_expected=$null;clear_authorized=$false}) $base.request_id } 'unauthorized clear accepted'
Reject { Assert-Request ([pscustomobject]@{schema_version=1;request_id=$base.request_id;computer_name='TESTVM';admin_user='alice';password='x';data_policy='clear';d_expected=[pscustomobject]@{disk_guid='a';unique_guid='b';start_bytes=0;size_bytes=0;ntfs_serial='c'};clear_authorized=$true}) $base.request_id } 'zero-size D identity accepted'

$expected = [pscustomobject]@{disk_guid='disk';unique_guid='unique';start_bytes=1048576;size_bytes=2097152;ntfs_serial='ABCD'}
$actual = [pscustomobject]@{disk_guid='disk';unique_guid='unique';start_bytes=1048576;size_bytes=2097152;ntfs_serial='ABCD'}
Assert-DataIdentity $expected $actual
Reject { Assert-DataIdentity $expected ([pscustomobject]@{disk_guid='other';unique_guid='unique';start_bytes=1048576;size_bytes=2097152;ntfs_serial='ABCD'}) } 'D identity mismatch accepted'

$source = [IO.File]::ReadAllText($tool)
Assert (-not ($source -match 'Format-Volume.+-DriveLetter\s+\x27C')) 'helper can format C drive'
Assert ($source -match "Format-Volume -DriveLetter 'D'") 'D format is not literal drive D'
Assert ($source -match 'D_CLEAR_INTERRUPTED_REQUIRES_EXPLICIT_RECOVERY') 'interrupted D clear is not fail-closed'
Assert ($source -match "clear-complete','account-started") 'completed D clear cannot resume safely'
Assert ($source -match 'DATA_BITLOCKER_CHECK_UNAVAILABLE') 'missing BitLocker check is not fail-closed'
Assert ($source -match 'DATA_NTFS_VBR_READ') 'NTFS VBR read guard missing'
Assert ($source -match 'UserMayChangePassword') 'Set-LocalUser uses wrong password-change parameter'
Assert ($source -match 'Get-LocalGroupMember.+S-1-5-32-544|Get-LocalGroupMember -SID') 'admin group membership is not verified'
Assert ($source -match 'S-1-5-32-544') 'Administrators SID is not pinned'
Assert (-not ($source -match 'Set-ExecutionPolicy|New-NetFirewallRule|Disable-BitLocker')) 'helper changes global policy or network'
Assert (-not ($source -match 'Write-Host.*password|Write-Output.*password')) 'helper prints password'

if (-not (Test-Path -LiteralPath $verify)) { throw "missing owner verifier: $verify" }
$verifyBytes = [IO.File]::ReadAllBytes($verify)
if ($verifyBytes.Length -lt 3 -or $verifyBytes[0] -ne 0xEF -or $verifyBytes[1] -ne 0xBB -or $verifyBytes[2] -ne 0xBF) { throw 'owner verifier must be UTF-8 BOM' }
$verifyErrors = $null
$verifyAst = [Management.Automation.Language.Parser]::ParseFile($verify, [ref]$null, [ref]$verifyErrors)
if ($verifyErrors.Count) { throw "owner verifier parse failed: $(($verifyErrors | ForEach-Object Message) -join '; ')" }
$listenerFunction = $verifyAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-HttpsListenerThumbprint' }, $true) | Select-Object -First 1
if ($null -eq $listenerFunction) { throw 'missing HTTPS listener certificate function' }
Invoke-Expression $listenerFunction.Extent.Text
function Get-WSManInstance { [pscustomobject]@{ Transport='HTTPS'; Port=5986; CertificateThumbprint=('B' * 40) } }
Assert ((Get-HttpsListenerThumbprint) -eq ('B' * 40)) 'listener CertificateThumbprint was not read'
$invokeNodes = @($verifyAst.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-Command' }, $true))
Assert ($invokeNodes.Count -ge 5) 'verifier Invoke-Command call sites were not found'
foreach ($node in $invokeNodes) {
    $hasParamBlock = @($node.CommandElements | Where-Object { $_ -is [Management.Automation.Language.ScriptBlockExpressionAst] -and $null -ne $_.ScriptBlock.ParamBlock }).Count -gt 0
    $hasArgumentList = @($node.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'ArgumentList' }).Count -gt 0
    if ($hasParamBlock) { Assert $hasArgumentList 'Invoke-Command param block lacks explicit -ArgumentList' }
}
$verifySource = [IO.File]::ReadAllText($verify)
Assert ($verifySource -match 'Copy-Item.+-ToSession') 'verifier does not prove WinRM upload'
Assert ($verifySource -match 'Get-FileHash') 'verifier does not hash uploaded script'
Assert ($verifySource -match 'ExecutionPolicy RemoteSigned') 'verifier does not use child RemoteSigned execution'
Assert ($verifySource -match '127\.0\.0\.1.*5986') 'verifier does not use local WinRM HTTPS'
Assert ($verifySource -match 'SkipCACheck.*SkipCNCheck') 'verifier TLS session options missing'
Assert ($verifySource -match 'WINRM_TLS_LISTENER_CERT_MISMATCH') 'verifier does not pin listener certificate'
Assert ($verifySource -match 'CertificateThumbprint') 'verifier does not use WSMan CertificateThumbprint'
Assert ($verifySource -notmatch '\$listener\.Certificate\b') 'verifier uses obsolete WSMan Certificate property'
Assert ($verifySource -match 'S-1-5-32-544') 'verifier does not prove Administrators token'
Assert ($verifySource -match 'TermService') 'verifier does not report RDP service'
Assert ($verifySource -match 'Remove-Item.+remote') 'verifier cleanup is missing'
Assert ($verifySource -match 'ReadToEndAsync') 'verifier child output is unbounded before timeout'
Assert ($verifySource -notmatch '\}\s+@\(') 'verifier still passes Invoke-Command arguments positionally'
Assert ($verifySource -match 'VERIFY_WORKDIR_NOT_EMPTY') 'verifier can overwrite a pre-existing work directory'
Assert ($verifySource -match 'Microsoft.PowerShell') 'verifier does not pin the standard endpoint'
Assert ($verifySource -notmatch 'function Get-TlsThumbprint\(\[string\] \$Host') 'verifier shadows PowerShell built-in Host variable'
Assert (-not ($verifySource -match 'Set-ExecutionPolicy|New-NetFirewallRule|Add-LocalUser|Disable-LocalUser|Format-Volume')) 'verifier mutates guest security or data'
'owner verifier structural tests: PASS (AST, TLS pin, WinRM transfer, child execution, cleanup; no guest mutation)'

'owner helper structural tests: PASS (AST, identity, authorization, path/policy guards; no account or D mutation)'
