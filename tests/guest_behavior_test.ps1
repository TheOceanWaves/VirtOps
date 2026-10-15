[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$project=Split-Path -Parent $PSScriptRoot
$tool=Join-Path $project 'skill/windows-vm-sandbox/scripts/guest.ps1'
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($tool,[ref]$null,[ref]$errors)
if($errors.Count){throw 'Tool parse failed'}
$functions=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Fail','Assert-SafeRemotePath')},$true)
foreach($function in $functions){Invoke-Expression $function.Extent.Text}
foreach($path in @('C:\Windows\bad.ps1','C:\Work\..\Windows\bad.ps1','C:\Work\file:ads','C:\Work\*.txt','C:\Work')){
    $failed=$false
    try{$null=Assert-SafeRemotePath $path}catch{$failed=$true}
    if(-not $failed){throw "Path should be rejected: $path"}
}
if((Assert-SafeRemotePath 'C:\Work\task\input.txt') -ne 'C:\Work\task\input.txt'){throw 'Valid path rejected'}
$blocks=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.ScriptBlockExpressionAst] -and $n.ScriptBlock.ParamBlock -and
    ($n.ScriptBlock.ParamBlock.Parameters.Name.VariablePath.UserPath -join ',') -eq 'script,timeout'
},$true))
if($blocks.Count -ne 1){throw 'Unique child process implementation not found'}
$run=$blocks[0].ScriptBlock.GetScriptBlock()
$directory=Join-Path $project ('.validation/process-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$previousTemp=$env:TEMP
$env:TEMP=Join-Path $directory 'captures'
New-Item -ItemType Directory -Path $env:TEMP | Out-Null
try {
    foreach($case in @(
        @{script="[Console]::Write('ok');exit 0";timeout=10;code=0},
        @{script='exit 7';timeout=10;code=7},
        @{script='Start-Sleep -Seconds 20';timeout=1;code=124}
    )){
        $path=Join-Path $directory 'case.ps1'
        [IO.File]::WriteAllText($path,$case.script,[Text.UTF8Encoding]::new($true))
        $result=& $run $path $case.timeout
        if($result.exit_code -ne $case.code){throw "Exit mismatch: expected $($case.code), got $($result.exit_code)"}
        if($result.timed_out -ne ($case.code -eq 124)){throw 'Timeout status mismatch'}
        Remove-Item -LiteralPath $path
    }
} finally {
    if(-not (Get-ChildItem -LiteralPath $env:TEMP -Force | Select-Object -First 1)){Remove-Item -LiteralPath $env:TEMP}
    $env:TEMP=$previousTemp
    # Nonrecursive: preserve unexpected files if any test fails.
    if((Test-Path -LiteralPath $directory) -and -not (Get-ChildItem -LiteralPath $directory -Force | Select-Object -First 1)){Remove-Item -LiteralPath $directory}
}
'guest behavior tests: PASS (path, success, exit 7, timeout 124; no network)'
