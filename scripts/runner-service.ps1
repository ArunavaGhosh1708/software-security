param([Parameter(Mandatory=$true)][string]$Manifest)
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot
$settings=Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
$dockerDesktop='C:\Program Files\Docker\Docker\Docker Desktop.exe'
if ((Test-Path -LiteralPath $dockerDesktop) -and !(Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $dockerDesktop -WindowStyle Hidden
}
$runnerArguments=@('-u','-m','runner.supervisor','--refresh-advisories')
foreach ($config in $settings.configs) { $runnerArguments+=@('--config',[string]$config) }
& ([string]$settings.python) @runnerArguments
exit $LASTEXITCODE
