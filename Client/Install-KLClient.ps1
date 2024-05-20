<#
.SYNOPSIS
    Installation script for KnightLAPS solution Client.
.DESCRIPTION
    This script is a part of KnightLAPS solution, which handles the password rotation on the device.
.EXAMPLE
    .\Install-KLClient.ps1

.NOTES
    FileName:    Install-KLClient.ps1
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2024-04-21
    Updated:     2024-04-21

    Version history:
    1.0.0 - (2024-04-21) Script created
#>

#Variables
$Application    = "KnightLAPS"
$KnightFolder   = "C:\Program Files\KnightLAPS"
$ConfigFile     = $KnightFolder +"\KLC.ini"
$TmpFolder      = [System.Environment]::GetEnvironmentVariable("TEMP", "Machine")
$LogPath        = "$TmpFolder\KL-Client-installation.log"
$TaskName       = "KL-Client"
$TaskFolder     = $Application
$User           = "System"
$EventLogSource = $Application
$EventLOGName   = $Application
$ScriptFiles    = @(
    "KLC.ps1",
    "KLC.ini",
    "README.md"
)

# Log file function
function Write-Log {
    param([string]$Message)
    Add-Content -Path $logPath -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss"): $Message"
}


# Create folder and copy the client script
# into the new folder
try {
    # Check whether the folder already exists
    if (-not (Test-Path -Path $KnightFolder)) {
        # Folder does not exist, create it
        Write-Log "Folder does not exist"
        New-Item -ItemType Directory -Path $KnightFolder | Out-Null
        Write-Log "Folder '$KnightFolder' was created."
    } else {
        Write-Log "Folder '$KnightFolder' was existed."
    }
} catch {
    # Error handling
    Write-Log "Can not create folder '$KnightFolder' aborting the installation"
    exit 1
}

# Copy files in the folder
if (Test-Path $KnightFolder) {
    try {
        # Copy the script file
        foreach ($File in $ScriptFiles){
            $sourcePath = "$PSScriptRoot\$File"
            if (-Not (Test-Path -Path $sourcePath)) {
                Write-Log "Source file not found: $sourcePath"
                exit 1
            }
            Copy-Item -Path $sourcePath -Destination $KnightFolder -Force -ErrorAction Stop | Out-Null
            Write-Log "File copied successfully: $KnightFolder\$File"
        }

        # Set new permissions for folder and files
        Write-Log "Set folder permission of SYSTEM and Administratoren"
        icacls $KnightFolder /inheritance:r /grant:r "Administratoren:(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F" | Out-Null
        Write-Log "Folder permission successfully set"

    } catch {
        Write-Log "Error when copying the file: $_ or by set the new permissions"
        Exit 1
    }

}
else {
    # Folder does not exist - Do something else here
    Write-host "Folder Doesn't Exists!" -f Red
}


# Create Event Log
if (-not [System.Diagnostics.EventLog]::SourceExists($EventLOGName)) {
    # Register new event log
    try{
      New-EventLog -LogName $EventLOGName -Source $EventLogSource -ErrorAction Stop
      Write-Log "New Event registert "
      # Test the event log
      Write-EventLog -LogName $EventLOGName -Source $EventLogSource -EventId 10 -EntryType "Information" -Message "The new event log it works"
    } catch [System.Exception] {
        Write-Log "Error: Failed to create new event log: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Log "The event log source '$EventLOGName' is already registered."
}

#
# Create a scheduled task from the client configuration
#
$ConfigObj = Get-Content -Path $ConfigFile | ConvertFrom-Json
foreach ($Task in $ConfigObj.Tasks) {
    try {
        $TaskNameUser = $TaskName + "-" + $Task.UserName
        if (! (Get-ScheduledTask | Where-Object { $_.TaskName -eq $TaskNameUser })) {
            $Action = New-ScheduledTaskAction -Execute "$PSHOME\PowerShell.exe" -Argument " -NoLogo -NoProfile -WindowStyle Hidden -File $KnightFolder\KLC.ps1 -TaskID 1"
            $Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval $Task.WeeksInterval -DaysOfWeek $Task.DaysOfWeek -At $Task.RunTaskOnClock -RandomDelay (New-TimeSpan -Minutes 30)
            $settings = New-ScheduledTaskSettingsSet -RestartCount:5 -RestartInterval (New-TimeSpan -Minutes 15) -Priority 7 `
            -StartWhenAvailable `
                   -AllowStartIfOnBatteries `
                   -DontStopIfGoingOnBatteries `
                   -DontStopOnIdleEnd `
                   -RunOnlyIfNetworkAvailable `
                   -ExecutionTimeLimit (New-TimeSpan -Minutes 60)
            $ScheduledTask = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Description "KLC TaskID :$($Task.Id)"
            Register-ScheduledTask -TaskName $TaskNameUser -InputObject $ScheduledTask -User $User -TaskPath $TaskFolder | Out-Null
            $MSG = "Create Windows task $($TaskNameUser) from file configuration with ID $($Task.Id)."
            Write-EventLog -LogName $EventLOGName -Source $EventLogSource -EventId 1009 -EntryType "Information" -Message $MSG
            Write-Log $MSG
        } else {
               $MSG = "Cannot create Windows task '$($TaskNameUser)' with ID $($Task.Id) because there is already a task with the same name."
                Write-EventLog -LogName $EventLOGName -Source $EventLogSource -EventId 4009 -EntryType "Error" -Message $MSG
                Write-Log $MSG
        }
    }
    catch {
        $MSG = "Unknown error could not create the Windows task $($TaskNameUser) with ID $($Task.Id) from the client configuration.$($_.Exception.Message)"
        Write-EventLog -LogName $EventLOGName -Source $EventLogSource -EventId 5009 -EntryType "Error" -Message $MSG
        Write-Log $MSG
    }


}
Write-Log "Installation from KnightLAPS client was successfull"
Exit 0





