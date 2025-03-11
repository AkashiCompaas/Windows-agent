@echo off

setlocal enableDelayedExpansion

reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && SET OS=32BIT || SET OS=64BIT


if %OS%==32BIT (
    SET logFile="%programfiles%\ossec-agent\logs\scheduled-tasks.log"
)

if %OS%==64BIT (
    SET logFile="%programfiles(x86)%\ossec-agent\logs\scheduled-tasks.log"
)

set input=
for /f "delims=" %%a in ('powershell -command "$logInput = Read-Host; Write-Output $logInput"') do (
    set input=%%a
)

powershell -command "$string = '%input%'; $match = select-string 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree.*\\\\(\S*)\\r\\n' -inputobject $string; $taskName = $match.Matches.groups[1].value; $task = Get-ScheduledTask | where TaskName -EQ $taskName; $jsonTask = $task.Actions | ConvertTo-Json -Compress; try{$stream = [System.IO.StreamWriter]::new( '%logFile%', $true );'{\"ScheduledTaskAR\": ' + $jsonTask + ', \"TaskName\": \"' + $taskName + '\"}' | ForEach-Object{ $stream.WriteLine( $_ ) }}finally{$stream.close()}; exit"
