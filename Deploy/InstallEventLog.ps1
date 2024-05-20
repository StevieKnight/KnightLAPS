Process {
    # Create new event log if it doesn't already exist
    $EventName = "1KnightLAPS-Client"
    $EventSource = "1KnightLAPS-Client"
    $KnightLAPSEvent = Get-WinEvent -LogName $EventName -ErrorAction SilentlyContinue
    if ($null -eq $KnightLAPSEvent) {
        try {
            New-EventLog -LogName $EventName -Source $EventSource -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Error: Failed to create new event log: $($_.Exception.Message)"
        }
    }
    exit 1
}