$ErrorActionPreference = "Continue"
$output = & python .\phone_voice_win_input.py --self-test 2>&1
$exitCode = $LASTEXITCODE
$output | ForEach-Object { Write-Output $_ }
if ($exitCode -ne 0) {
    $message = ($output -join "`n").Replace("%", "%25").Replace("`r", "%0D").Replace("`n", "%0A")
    Write-Output "::error title=Self-test failed::$message"
    exit $exitCode
}