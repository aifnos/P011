# P011 screenshot entry point. All host outputs stay under WorkRoot\logs.
[CmdletBinding()]
param(
    [ValidateSet('App','Framebuffer')][string]$Source='App',
    [string]$WorkRoot='D:\project\P011',
    [string]$PackageDir='',
    [ValidateRange(1,12)][int]$Shots=1,
    [ValidateRange(2,60)][int]$Interval=5
)
$ErrorActionPreference='Stop'
if (-not $PackageDir) { $PackageDir=Join-Path $WorkRoot 'PlayLab' }
$entry=Join-Path $PackageDir 'P011-PlayLab.ps1'
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) { throw 'Extract the complete PlayLab 1.2 package first.' }
$runner=[scriptblock]::Create((Get-Content -LiteralPath $entry -Raw -Encoding UTF8))
if ($Source -eq 'Framebuffer') {
    Write-Host 'Source=Framebuffer: read-only fb0; an image is NOT proof that it is the active Wayland scanout.'
    & $runner -Mode Screen -WorkRoot $WorkRoot -PackageDir $PackageDir -Shots $Shots -Interval $Interval
} else {
    Write-Host 'Source=App: the PlayLab 1.2 Demo/Calibrate process must already be running.'
    for ($i=0; $i -lt $Shots; $i++) {
        & $runner -Mode Capture -WorkRoot $WorkRoot -PackageDir $PackageDir
        if ($i+1 -lt $Shots) { Start-Sleep -Seconds $Interval }
    }
}
