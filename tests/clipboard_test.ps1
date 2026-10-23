[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tool = Join-Path (Split-Path -Parent $PSScriptRoot) 'skill/windows-vm-sandbox/scripts/guest.ps1'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($tool, [ref]$null, [ref]$errors)
if ($errors.Count) { throw 'Tool parse failed' }
$blocks = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.ScriptBlockExpressionAst] -and
    $node.ScriptBlock.ParamBlock -and
    ($node.ScriptBlock.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') -eq 'clipboardMode'
}, $true))
if ($blocks.Count -ne 1) { throw 'Unique clipboard operation not found' }
$operation = $blocks[0].ScriptBlock.GetScriptBlock()
$script:policy = @{ fDisableClip = 1; fDisableCdm = 1; fDisableCpm = 1 }
$script:writes = 0
function Get-ItemPropertyValue {
    param($LiteralPath, $Name, $ErrorAction)
    $script:policy[$Name]
}
function New-Item { param($Path, [switch]$Force) }
function New-ItemProperty {
    param($LiteralPath, $Name, $PropertyType, $Value, [switch]$Force)
    if ($PropertyType -ne 'DWord') { throw 'Expected DWORD' }
    $script:policy[$Name] = $Value
    $script:writes++
}
$result = & $operation 'inspect'
if ($script:writes -ne 0 -or $result.after.fDisableClip -ne 1 -or $result.reconnect_required) {
    throw 'Inspect must be read-only'
}
foreach ($mode in @('enable','enable','disable')) {
    $result = & $operation $mode
    $expected = if ($mode -eq 'enable') { 0 } else { 1 }
    if ($result.after.fDisableClip -ne $expected -or $result.after.fDisableCdm -ne $expected) {
        throw 'Both clipboard and file copy policy must match the requested mode'
    }
    if (-not $result.reconnect_required -or $script:policy.fDisableCpm -ne 1) {
        throw 'Must request reconnection and preserve unrelated printer policy'
    }
}
if ($script:writes -ne 6) { throw 'Unexpected policy writes' }
'clipboard tests: PASS (read-only inspect, enable, idempotence, disable, unrelated policy preserved)'
