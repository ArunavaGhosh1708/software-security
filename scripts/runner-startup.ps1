param(
    [ValidateSet('Install','Start','Stop','Status','Remove')][string]$Action = 'Status',
    [string[]]$Configs = @('.data/runner-hosted-settings.json','.data/runner-evalsai-settings.json')
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$taskName = 'SentinelPrivateRunners'
if ($Action -eq 'Status') { Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Select-Object TaskName,State; return }
if ($Action -eq 'Stop') { Stop-ScheduledTask -TaskName $taskName; return }
if ($Action -eq 'Remove') { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false; return }
if ($Action -eq 'Start') { Start-ScheduledTask -TaskName $taskName; return }
$pythonExe = (Get-Command python).Source
$resolvedConfigs = @($Configs | ForEach-Object { (Resolve-Path -LiteralPath (Join-Path $repoRoot $_)).Path })
foreach ($configPath in $resolvedConfigs) {
    if ($configPath.Contains('"')) { throw 'Invalid configuration path.' }
}
$manifest=Join-Path $repoRoot '.data/runner-service.json'
@{python=$pythonExe;configs=$resolvedConfigs} | ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding UTF8
$serviceScript=Join-Path $PSScriptRoot 'runner-service.ps1'
$shellExe=(Get-Command powershell.exe).Source
$arguments='-NoProfile -NonInteractive -WindowStyle Hidden -File "'+$serviceScript+'" -Manifest "'+$manifest+'"'
$taskAction = New-ScheduledTaskAction -Execute $shellExe -Argument $arguments -WorkingDirectory $repoRoot
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$taskSettings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force | Select-Object TaskName,State
Start-ScheduledTask -TaskName $taskName
