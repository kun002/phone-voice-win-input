param(
    [string]$HostName = "0.0.0.0",
    [int]$Port = 8765,
    [string]$Token = "",
    [switch]$Gui,
    [switch]$NoQr,
    [switch]$DryRun,
    [switch]$NoToken,
    [switch]$ResetToken,
    [switch]$StrictPort,
    [switch]$NoClipboardProtect,
    [switch]$NoTargetClickRestore,
    [switch]$NoForegroundRestore,
    [switch]$ReturnPreviousForeground,
    [int]$TargetLockTimeout = -1,
    [string]$Hotkey = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonArgs = @(
    "$ProjectRoot\phone_voice_win_input.py",
    "--host", $HostName,
    "--port", $Port
)

if ($Token) { $PythonArgs += @("--token", $Token) }
if ($Gui) { $PythonArgs += "--gui" }
if ($NoQr) { $PythonArgs += "--no-qr" }
if ($DryRun) { $PythonArgs += "--dry-run" }
if ($NoToken) { $PythonArgs += "--no-token" }
if ($ResetToken) { $PythonArgs += "--reset-token" }
if ($StrictPort) { $PythonArgs += "--strict-port" }
if ($NoClipboardProtect) { $PythonArgs += "--no-clipboard-protect" }
if ($NoTargetClickRestore) { $PythonArgs += "--no-target-click-restore" }
if ($NoForegroundRestore) { $PythonArgs += "--no-foreground-restore" }
if ($ReturnPreviousForeground) { $PythonArgs += "--return-previous-foreground" }
if ($TargetLockTimeout -ge 0) { $PythonArgs += @("--target-lock-timeout", $TargetLockTimeout) }
if ($Hotkey) { $PythonArgs += @("--hotkey", $Hotkey) }
if ($ExtraArgs) { $PythonArgs += $ExtraArgs }

python @PythonArgs
