# Windows PowerShell Lifecycle Script for Gateway Application
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$ScriptDir\startup.py" @args
exit $LASTEXITCODE
