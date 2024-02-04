<#
.SYNOPSIS
    Client from KnightLAPS solution. This client handles the password rotation on the device.
.DESCRIPTION
    This script is a part of KnightLAPS solution, which handles the password rotation on the device.

    It uses the local administrator account with SID S-1-5-21-*-500 or it used the username from 
    paramet for using. It call Azure Function API for generate new password. For this request, many
    parameters must be collected from the device. It will be needed for identifying the device in 
    the Azure Function. If the check okay in the function, get the new password from the function.   

.EXAMPLE
    .\KnightLAPSClient.ps1

.NOTES
    FileName:    KnightLAPSClient.ps1
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2023-05-01
    Updated:     2023-05-01

    Version history:
    1.0.0 - (2023-05-01) Script created
#>

param (
    [Parameter(Mandatory = $false, HelpMessage = "Specify Azure Function host")]
    [ValidateNotNullOrEmpty()]
    [string] $KnightHost = "localhost:7071", 

    [parameter(Mandatory=$false, HelpMessage = "Use specify username, instead of use local administrator")]
    [string]$UserName,
    
    [parameter(Mandatory=$false, HelpMessage = "Change default password length")]
    [int]$PWLength = 10,

    [parameter(Mandatory=$true, HelpMessage = "Azure Function security code")]
    [string]$Code


)

# Construct the required URI for the Azure Function URL
$SetSecretURI = 'http://{0}/api/GetNewSecret?code={1}' -f $KnightHost, $Code

# Define event log variables
$EventLogName = 'KnightLAPS-Client'
$EventLogSource = 'KnightLAPS-Client'

#Init Exitcode with default value
$ExitCode = 0

# Use TLS 1.2 connection when calling Azure Function
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


function Get-EIDInfo {
    <#
    .SYNOPSIS
    # Collected information from device about Entra ID status
    
    .NOTES
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2023-08-01
    Updated:     2023-08-01

    Version history:
    1.0.0 - (2023-08-01) Function created
    #>
    Process {
        # Create empty dataset
        $Data = [ordered]@{
            EID = $null
            TP  = $null
            PK  = $null
        }

        # First step, get a rigistry key 
        $KeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
        $ADKey = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'PSChildName'  
        if ($ADKey -match '^[A-Z0-9]{40}$') {
            # Step tow, read ms-organization-access certificate 
            $MSOACert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -Recurse | Where-Object { $PSItem.Thumbprint -eq $ADKey }
            if ($null -ne $MSOACert) {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 10 -Message 'Collecting EID information from the device'
               
                $Data.PK = [System.Convert]::ToBase64String($MSOACert.GetPublicKey())
                $Data.TP = $MSOACert.Thumbprint
                $Data.EID = ($MSOACert | Select-Object -ExpandProperty 'Subject') -replace 'CN=', ''
               
                return $Data
            }
            else {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 53 "Certificate with Thumbprint $($ADKey) not found." 
            }
        }
        else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 10 -Message 'The device is not joind to Entra ID'
        }
    }
}

#
# Main Start
#
Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Information -EventId 10 -Message 'The KnightLAPS-Client for local administrator account password rotation started...'

# Collect information from devices
# About Entra ID status
$EntraData = Get-EIDInfo

# Define the local administrator user name
if ([string]::IsNullOrEmpty($UserName)){
    # Read local admin with identifier S-1-5-21-*-500
    $LocalUser = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-21-*-500' -and $_.PrincipalSource -eq 'Local' -and $_.Enabled -eq $true} 
    
} else {
    # Read local user object from device 
    $LocalUser = Get-LocalUser | Where-Object { $_.Name -match $UserName -and $_.PrincipalSource -eq 'Local' -and $_.Enabled -eq $true }
}

if (! $LocalUser.count -eq 1){
    Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Error -EventId 10 -Message 'Not local user found on the device. Tell your administrator'
}



# Get the device serienumber, when exist
$DeviceSerialNumber = Get-CimInstance -Class 'Win32_BIOS' | Select-Object -ExpandProperty 'SerialNumber'
# UUID from computer
$CUUID = get-wmiobject Win32_ComputerSystemProduct | Select-Object -ExpandProperty 'UUID'
#Build password rotation request
$RequestPayload = [ordered]@{
    DeviceName      = $env:COMPUTERNAME 
    EntraDeviceID   = $EntraData.EID
    CUUID           = $CUUID
    Thumbprint      = $EntraData.TP
    PublicKey       = $EntraData.PK
    Username        = $LocalUser.Name
    DeviceSN        = $DeviceSerialNumber 
    PasswordLength  = $PWLength
    DeviceSuffix    = 'DSH'
    Override        = $true   
}

try {
    
    #Calling the Azure function for getting a secret
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 11 -Message 'Calling Azure Knight function for password generation and secret update'
    $Response = Invoke-WebRequest -Method 'POST' -Uri $SetSecretURI -Body ($RequestPayload | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop 
     
    if (($Response.RawContentLength -gt 0 ) -and $Response.StatusCode -eq 200) {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 10 -Message 'Response from Azure Knight Function '
            
        # Password handling
        $SPwd = ConvertTo-SecureString -String $Response.Content -AsPlainText -Force                  
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 10 -Message 'Set new password from KnightLAPS'
                  
        # Password set on account
        try {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 30 -Message 'KnightLAPS: Local administrator account  exists, updating password'

            # Determine if changes are being made to the built-in local administrator account, if so don't attempt to set properties for password changes
            if ($LocalUser.SID -match 'S-1-5-21-.*-500') {
                Set-LocalUser -Name $LocalUser.Name -Password $SPwd -PasswordNeverExpires $true -ErrorAction Stop
            }
            else {
                Set-LocalUser -Name $LocalUser.Name -Password $SPwd -PasswordNeverExpires $true -UserMayChangePassword $false -ErrorAction Stop
            }
            
            # Handle output for extended details in MEM portal
           
        }
        catch [System.Exception] {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 31 -Message "KnightLAPS: Failed to rotate password for '$($LocalUser.Name)' local user account. Error message: $($PSItem.Exception.Message)"
            $ExitCode = 1
        }   

    }
    else {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 13 'Unknow response error' 
        $ExitCode = 1
    }
    
}

catch [System.Exception] {

    # Read the orginal bodytext from api resonse
    if (![string]::IsNullOrEmpty($PSItem.Exception.Response)) {
        $reader = New-Object System.IO.StreamReader($PSItem.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errMSG = $reader.ReadToEnd()
      
        switch ($PSItem.Exception.Response.StatusCode) {
            'Forbidden' {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Warning -EventId 14 -Message "KnightLAPS Forbidden: $errMSG"
                $ExitCode = 1
            }
            'BadGateway' {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Warning -EventId 14 -Message "KnightLAPS BadGateway: $errMSG"
                $ExitCode = 1
            }
            'BadRequest' {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Warning -EventId 14 -Message "KnightLAPS BadRequest: $errMSG"
                $ExitCode = 1
            }
        
            Default {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 13 -Message "KnightLAPS: $errMSG"
                $ExitCode = 1
            }
        }

    }
    # All another exceptions write message in eventlog
    [string] $Msg = $PSItem.Exception.Message
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 15 -Message $Msg
    $ExitCode = 1

}

exit $ExitCode
