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
    .\KLC.ps1

.NOTES
    FileName:    KLC.ps1
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2023-05-01
    Updated:     2023-05-01

    Version history:
    1.0.0 - (2023-05-01) Script created
    1.0.1 - (2024-04-28) - Adding the function for the configuration
                           file and checking the incoming variables.
                         - Adding admin right check
                         - Adding multi device Entry "Device-Username"

#>

param (
    [Parameter(Mandatory = $false, HelpMessage = "Specify Azure Function host")]
    [ValidateNotNullOrEmpty()]
    [string] $KnightHost = '',

    [parameter(Mandatory=$false, HelpMessage = "Use specify username, instead of use local administrator")]
    [string]$UserName = '',

    [parameter(Mandatory=$false, HelpMessage = "Change default password length")]
    [string]$PWLength = '',

    [parameter(Mandatory=$false, HelpMessage = "Azure Function security code")]
    [string]$Code = '',

    [parameter(Mandatory=$false, HelpMessage = "Client device type")]
    [ValidateSet("Client", "Server","")]
    [string]$DeviceType = '',

    [parameter(Mandatory=$false, HelpMessage = "Client location")]
    [string]$Location = '',

    [parameter(Mandatory=$false, HelpMessage = "Task Id for selecting part of configuration file")]
    [string]$TaskId = '',

    [parameter(Mandatory=$false, HelpMessage = "For the debug information on command line")]
    [switch]$Debugging


)
# Configfile
$ConfigFile = "$PSScriptRoot\KLC.ini"

#Regulare expressions
$RegHostName = '^(https?):\/\/([a-zA-Z0-9.-]+):(0*[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'
$RegUserName = '^[a-zA-Z0-9_.äöüßÄÖÜ-]{1,20}$'
$RegPWLength = '^([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$'
$RegDeviceType = '^(Server|Client)$'
$RegLocation = '^[a-zA-Z0-9_-]{1,20}$'
$RegCode     = '^[a-zA-Z0-9_-]{54}==$'

# Define event log variables
$EventLogName = 'KnightLAPS'
$EventLogSource = 'KnightLAPS'

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
            $MSOACert = Get-ChildItem -Path 'Cert:\LocalMachine\My' -Recurse | Where-Object { $_.Thumbprint -eq $ADKey }
            if ($null -ne $MSOACert) {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1013 -Message 'Collecting EID information from the device'
                $Data.PK = [System.Convert]::ToBase64String($MSOACert.GetPublicKey())
                $Data.TP = $MSOACert.Thumbprint
                $Data.EID = ($MSOACert | Select-Object -ExpandProperty 'Subject') -replace 'CN=', ''
                return $Data
            }
            else {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 4013 "Certificate with Thumbprint $($ADKey) not found."
            }
        }
        else {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1014 -Message 'The device is not joind to Entra ID'
        }
    }
}
function Get-ConfigParam {
    <#
    .SYNOPSIS
    # Get the configuration parameters from cli or
      configuration file klc.ini and check them.

    .NOTES
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2024-05-04
    Updated:     2024-05-04

    Version history:
    1.0.0 - (2024-05-04) Function created
    #>

    param (
        [System.Object]$ConfigObj,
        [string] $ParamName,
        [string] $ParamValue,
        [string] $RegEx,
        [string] $TaskId
    )
    $VariableCheck = ""
    #Check is value string or int
    if ($ParamValue) {
        $VariableCheck = $ParamValue
        Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Information -EventId 1011 -Message "Cli-Param $($ParamName): '$($VariableCheck)' is used"
    } elseif ($ConfigObj.psobject.Properties.Name -contains $ParamName) {
                 $VariableCheck = $ConfigObj.psobject.Properties[$ParamName].value
             } elseif($TaskId) {
                   if ($ConfigObj.psobject.Properties.Name -contains "Tasks"){
                        $task = $ConfigObj.Tasks | Where-Object { $_.id -eq $TaskId }
                        if($task){
                            if ($task.psobject.Properties.Name -contains $ParamName) {
                                $VariableCheck = $task.psobject.Properties[$ParamName].value
                                Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Information -EventId 1012 -Message "Task $($TaskID) $($ParamName) : '$($VariableCheck)' is used"
                            }
                        } else {
                            Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Error -EventId 5012 -Message "Task configuration with the id $($TaskId) not found. The process has now been stopped"
                            exit 1
                        }
                    }
                } else {
                    Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Error -EventId 5012 -Message "No found commandline parameter $($ParamName) or TaskID. The process has now been stopped."
                    exit 1
    }


    #
    # Check cli or config value
    if ($VariableCheck -match $RegEx){
        return $VariableCheck
     } else {
            Write-Debugging -Message "Invalid parameter $($ParamName):'$($VariableCheck)'"
            Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Error -EventId 5013 -Message "Invalid parameter $($ParamName):'$($VariableCheck)'. The process has now been stopped."
            exit 1
     }
}
function Get-HasScriptAdminRights {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Write-Debugging {
    param($Message)

    if ($Debugging){
        Write-Host $Message -ForegroundColor Red
    }
}
<# ToDo function Signature content with private key
function SignatureContent {
    param (
        [string] $Content,
        [string] $Thumbprint
    )
} #>


#
# Main Start
#
if (Get-HasScriptAdminRights) {
    Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Information -EventId 1 -Message 'Starting the client script'

    #
    # Init config settings
    #
    $ConfigObj = Get-Content -Path $ConfigFile | ConvertFrom-Json

    # If cli value has priority over the values from the config file
    $KnightHost = Get-ConfigParam -ConfigObj $ConfigObj -ParamName "KnightHost" -ParamValue $KnightHost -RegEx $RegHostName -TaskId $TaskId
    $UserName   = Get-ConfigParam -ConfigObj $ConfigObj -ParamName "UserName"   -ParamValue $UserName -RegEx $RegUserName -TaskId $TaskId
    $PWLength   = Get-ConfigParam -ConfigObj $ConfigObj -ParamName "PWLength"   -ParamValue $PWLength -RegEx $RegPWLength -TaskId $TaskId
    $DeviceType = Get-ConfigParam -ConfigObj $ConfigObj -ParamName "DeviceType" -ParamValue $DeviceType -RegEx $RegDeviceType -TaskId $TaskId
    $Location   = Get-ConfigParam -ConfigObj $ConfigObj -ParamName "Location"   -ParamValue $DeviceLocation -RegEx $RegLocation -TaskId $TaskId
    $Code       = Get-ConfigParam -ConfigObj $ConfigObj -ParamName "Code"       -ParamValue $Code -RegEx $RegCode -TaskId $TaskId


    # Construct the required URI for the Azure Function URL
    $SetSecretURI = '{0}/api/GetNewSecret?code={1}' -f $KnightHost, $Code

    # Collect information from devices
    # About Entra ID status
    $EntraData = Get-EIDInfo

    # Define the local administrator user name
    if ([string]::IsNullOrEmpty($UserName)){
        # Read local admin with identifier S-1-5-21-*-500
        $LocalUser = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-21-*-500' -and $_.PrincipalSource -eq 'Local' -and $_.Enabled -eq $true}

    } else {
        # Read local user object from device
        $LocalUser = Get-LocalUser | Where-Object { $_.Name -eq $UserName -and $_.PrincipalSource -eq 'Local' -and $_.Enabled -eq $true }
    }

    if (! $LocalUser.count -eq 1){
        Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Error -EventId 5014 -Message "No local user with the name '$($UserName)' could be found on the device. The process has now been stopped."
        exit 1
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
        DeviceType      = $DeviceType
        Location        = $Location
        #Override        = $true
    }

    try {

        #Calling the Azure function for getting a secret
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1020 -Message "Send a web request to $($KnightHost) endpoint to generate a password and update the secret"
        Write-Debugging -Message "Request send to $($KnightHost):"
        Write-Debugging -Message "$($RequestPayload | ConvertTo-Json)"
        $Response = Invoke-WebRequest -Method 'POST' -Uri $SetSecretURI -Body ($RequestPayload | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop
        Write-Debugging -Message "Response from to $($KnightHost):"
        Write-Debugging -Message $Response.RawContent
        if (($Response.RawContentLength -gt 0 ) -and $Response.StatusCode -eq 200) {
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1021 -Message "Receive respons to my request from Host $($KnightHost) endpoint "

            # Password handling
            $SPwd = ConvertTo-SecureString -String $Response.Content -AsPlainText -Force
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1031 -Message 'Starting process to handle new password'

            # Password set on account
            try {

                # Determine if changes are being made to the built-in local administrator account, if so don't attempt to set properties for password changes
                if ($LocalUser.SID -match 'S-1-5-21-.*-500') {
                    Set-LocalUser -Name $LocalUser.Name -Password $SPwd -PasswordNeverExpires $true -ErrorAction Stop
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1032 -Message 'The local administrator account exists, the password is now updated'
                }
                else {
                    Set-LocalUser -Name $LocalUser.Name -Password $SPwd -PasswordNeverExpires $true -UserMayChangePassword $false -ErrorAction Stop
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 1033 -Message 'The local user account exists, the password is now updated'
                }

            }
            catch [System.Exception] {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5034 -Message "Failed to rotate password for '$($LocalUser.Name)' local user account. Error message: $($_.Exception.Message)"
                $ExitCode = 1
            }
        }
        else {
            Write-Information -MessageData $Response.Content
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5022 "The answer from Host $($KnightHost) that was received was not what was expected. An unknown error"
            $ExitCode = 1
        }
    }

    catch [System.Exception] {

        # Read the orginal bodytext from api resonse
        if (![string]::IsNullOrEmpty($_.Exception.Response)) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $errMSG = $reader.ReadToEnd()

            switch ($_.Exception.Response.StatusCode) {
                'Forbidden' {
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5023 -Message "Forbidden $errMSG"
                    $ExitCode = 1
                }
                'BadGateway' {
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5024 -Message "BadGateway $errMSG"
                    $ExitCode = 1
                }
                'BadRequest' {
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5025 -Message "BadRequest $errMSG"
                    $ExitCode = 1
                }

                Default {
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5029 -Message "Unknown Server error 500: $errMSG"
                    $ExitCode = 1
                }
            }
        }
        if($ExitCode -ne 1){
            # All another exceptions write message in eventlog
            [string] $errMSG = $_.Exception.Message
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5029 -Message "Unknown Server error 500 $errMSG"
            $ExitCode = 1
        }


    }

} else {
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 5010 -Message "The client needs admin rights to work correctly"
    $ExitCode = 1
}
Write-EventLog -LogName $EventLogName -Category 5 -Source $EventLogSource -EntryType Information -EventId 3 -Message 'Finish the client script'
exit $ExitCode
