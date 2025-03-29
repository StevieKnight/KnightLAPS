using namespace System.Net
<#
.SYNOPSIS
The Azure Function from KnightLAPS solution for processing the client new password requests.

.DESCRIPTION
This Azure Function is a part of KnightLAPS solution. It handel the client request. When
a new request come in, than check the function the information from device. A distinction
is made between Azure join devices and devices that are standalone. After the device check
the function generates new password and save it in 1Password keyvault and send the
password to device.

.NOTES
    FileName:    GetNewSecret.ps1
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2023-05-01
    Updated:     2024-05-20

    Version history:
    1.0.0 - (2023-05-01) Script created
    1.0.1 - 2024-05-11  All incoming data verified
    1.0.2 - 2024-05-20  Add vault mapping location
                        device type.
#>
# Input bindings are passed in via param block.
param(
    [Parameter(Mandatory = $true)]
    $Request,

    [Parameter(Mandatory = $false)]
    $TriggerMetadata
)
# Define default variable
$TrustDevice = $false
$Exception = $false
$StatusCode = [HttpStatusCode]::OK
$body = ''

#1Password settings

$VaultsFile = "$($PSScriptRoot)\$($env:VaultFile)"
Write-Output $VaultsFile
$KeyVaultHost = $env:KeyVaultHost
$1PasswordHost = $env:OnePasswordHost
$1PasswordAccessTokenName = $env:OnePasswordAccessTokenName

#Password policy settings
$PWAllowedCharacters = $env:PWAllowedCharacters
$PWMinAge = $env:PWAgeinDay

function CheckRequestVariable {
    param (

        [string] $VariabValue,
        [string] $RegEx,
        [bool]   $Mandatory

    )
    if ([string]::IsNullOrEmpty($VariabValue) -and $Mandatory) {
        throw 'is empty or null and is mandatory'
    }
    else {
        if (! [string]::IsNullOrEmpty($VariabValue)) {
            if ($VariabValue -match $RegEx) {
                $VariabValue
            }
            else {
                throw "$($VariabValue) is irregular"
            }
        }
    }
}

if (-not [string]::IsNullOrEmpty($Request.Body)) {

    #
    # Get authorization token for local deployment (MSAL) or
    # azure plattform with (MSI). Check in which environment
    # the function currently being excuted.
    #
    # The MSAL part can be deleted for live use!
    #
    try {
        # WEBSITE_INSTANCE_ID is only available in azure
        if ([string]::IsNullOrEmpty($env:WEBSITE_INSTANCE_ID)) {
            Write-Output 'Azure function running in local deployment'
            if (Get-Module -ListAvailable -Name MSAL.PS) {
                # Azure App-registation login data
                $connectionDetails = @{
                    'TenantId'     = $env:TenantId
                    'ClientId'     = $env:ClientId
                    'ClientSecret' = $env:ClientSecret | ConvertTo-SecureString -AsPlainText -Force
                }
                # Vault token
                $AZTokenVault = Get-MsalToken @connectionDetails -Scopes 'https://vault.azure.net/.default'
                $AuthHeaderVault = @{ Authorization = $AZTokenVault.CreateAuthorizationHeader() }
                # Graph token
                $AZTokenVault = Get-MsalToken @connectionDetails -Scopes 'https://graph.microsoft.com/.default'
                $AuthHeaderGraph = @{ Authorization = $AZTokenVault.CreateAuthorizationHeader() }
            }
            else {
                # No MSAL module installed
                Write-Warning 'Module MSAL.ps does not exist. Install from https://www.powershellgallery.com/packages/MSAL.PS'
                $StatusCode = [HttpStatusCode]::Forbidden
                $body = 'Azure function does not have all required module available.'
            }

        }
        else {
            Write-Output 'Azure function running on Azure plattform'
            # Check whether MSI is activated
            if ($env:MSI_SECRET -and $env:MSI_ENDPOINT) {
                Write-Output 'MSI is activated'
                $MSIEndpoint = $env:MSI_ENDPOINT
                $MSISecret = $env:MSI_SECRET
                $APIVersion = '2017-09-01'

                #Vault token
                $ResourceURI = 'https://vault.azure.net'
                $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"
                $Response = Invoke-RestMethod -Uri $AuthURI -Method 'Get' -Headers @{ 'Secret' = "$($MSISecret)" }
                $AuthHeaderVault = @{ 'Authorization' = "Bearer $($Response.access_token)"
                    'ExpiresOn'                       = $Response.expires_on
                }

                #Graph token
                $ResourceURI = 'https://graph.microsoft.com'
                $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"
                $Response = Invoke-RestMethod -Uri $AuthURI -Method 'Get' -Headers @{ 'Secret' = "$($MSISecret)" }
                $AuthHeaderGraph = @{ 'Authorization' = "Bearer $($Response.access_token)"
                    'ExpiresOn'                       = $Response.expires_on
                }

            }
            else {
                $AFError = 'No Managed Service Identit activated'
                Write-Warning $AFError
                $StatusCode = [HttpStatusCode]::ServiceUnavailable
                $body = "503 Service Unavailable: $AFError"
            }
        }
    }
    catch {
        $AFError = $_.Exception.Message
        Write-Warning "503 Service Unavailable: $AFError"
        $StatusCode = [HttpStatusCode]::ServiceUnavailable
        $body = '503 Service Unavailable: Please ask your trusted administrator'
        $Exception = $true

    }

    #
    # Start processing the incoming request
    #
    Write-Output "New incoming request from a client: $($Request.Body.DeviceName) "

    #Check the mandatory parameters if they are set
    try {
        $ExceptionInfo = ''

        #Device Name
        $EntraADDeviceNameRegex = '^[a-zA-Z0-9-_\s]{1,64}$'
        $ExceptionInfo = 'DeviceName'
        $DeviceName = CheckRequestVariable $Request.Body.DeviceName $EntraADDeviceNameRegex $true

        # Entra device id
        $EntraDeviceIDRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        $ExceptionInfo = 'DeviceID'
        $EntraDeviceID = CheckRequestVariable $Request.Body.EntraDeviceID $EntraDeviceIDRegex $false


        # Thumbprint
        $ThumbprintRegex = '^[0-9a-fA-F]{40}$'
        $ExceptionInfo = 'CA Thumbprint'
        if ([string]::IsNullOrEmpty($EntraDeviceID)) {
            $Thumbprint = CheckRequestVariable $Request.Body.Thumbprint $ThumbprintRegex $false
        }
        else {
            $Thumbprint = CheckRequestVariable $Request.Body.Thumbprint $ThumbprintRegex $true
        }
        # Windows UUID
        $WindowsUUIDRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        $ExceptionInfo = 'Windows UUID'
        $DeviceUUID = CheckRequestVariable $Request.Body.CUUID $WindowsUUIDRegex $true

        # Username
        $UsernameRegex = '^[a-zA-Z0-9_-]{1,64}$'
        $ExceptionInfo = 'Username'
        $Username = CheckRequestVariable $Request.Body.Username $UsernameRegex $true

        # UserDeviceName
        $DeviceUserName = "$($DeviceName)-$($Username)"

        # ToDo signature content mit X509 certficate
        # PublicKey
        #$Base64Regex = "^[A-Za-z0-9\+/=]+$"
        #$ExceptionInfo = "CA Publickey"
        #$PublicKey     = CheckRequestVariable $Request.Body.PublicKey $Base64Regex $false

        # Device serial number
        $DeviceSN = $Request.Body.DeviceSN

        # DeviceType
        $DeviceTypeRegex = '^(Server|Client)$'
        $ExceptionInfo = 'DeviceType'
        $DeviceType = CheckRequestVariable $Request.Body.DeviceType $DeviceTypeRegex $false

        # DeviceLocation
        $LocationRegex = '^[a-zA-Z0-9_-]{1,20}$'
        $ExceptionInfo = 'Device location'
        $DeviceLocation = CheckRequestVariable $Request.Body.Location $LocationRegex $false

        # Password length from device has priority
        $NumberRegex = '^(?:[8-9]|[1-9]\d|1[01]\d|12[0-8])$'
        $ExceptionInfo = 'Password length'
        $PWLength = CheckRequestVariable $Request.Body.PasswordLength $NumberRegex $false
        if ([string]::IsNullOrEmpty($PWLength)) {
            Write-Output "$($DeviceName) Use the default password length of $($env:PWLength) characters"
            $PWLength = $env:PWLength
        }
        else {
            Write-Output "$($DeviceName) Use the device request password length of $($PWLength) characters"
        }

        # ToDo: Overwrite password allowed before date limit is over
        # $OverrideAllow = $Request.Body.Override

        #
        # If the Entra ID joined device, then
        # the Entra device ID must be set.
        #
        if ([string]::IsNullOrEmpty($EntraDeviceID)) {
            #Entra device id is not set
            Write-Output "$($DeviceName) device is not a Entra ID device checks the UUID starting.."
            try {
                #Read the whitlist file
                $content = Get-Content "$PSScriptRoot\uuid.dat"
                if ($content.Contains($DeviceUUID)) {
                    Write-Information "Device with $($DeviceUUID) found"
                    # TODo
                    # Check another source for check the device information
                    #
                    $TrustDevice = $true
                }
                else {
                    Write-Warning "$($DeviceName) device is not allow to rotate password"
                }
            }
            catch {
                Write-Warning 'Can not load UUID.dat file'
                $Exception = $true
            }
        }
        else {
            # Is the EntraDeviceID formatted correctly?
            if ($EntraDeviceID -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                Write-Output "$($DeviceName) has send an Entra device ID, validate the accepted data with Entra ID"

                # Is the device id registered in entra id
                $URI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($EntraDeviceID)'"
                $EntraDevice = (Invoke-RestMethod -Method 'Get' -Uri $URI -ContentType 'application/json' -Headers $AuthHeaderGraph -ErrorAction SilentlyContinue).value
                if ($EntraDevice.count -eq 1) {
                    Write-Output "$($DeviceName) is registered in Entra ID"
                    Write-Output "$($DeviceName) checking thumprint from device with saved item in Entra ID:$($Thumbprint)"
                    $Key = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EntraDevice.alternativeSecurityIds.key))
                    if ($Key.Split('>')[1].SubString(0, 40) -eq $Thumbprint) {
                        Write-Output "$($DeviceName) device certificate thumbprint check succesfull"
                        if ($true -eq $EntraDevice.accountEnabled) {
                            Write-Output "$($DeviceName) is trusted and device is enabled in Entra ID"
                            $TrustDevice = $true
                        }
                    }
                }
                else {
                    Write-Warning "$($DeviceName) is not in an Entra ID registered"
                }
            }
            else {
                Write-Warning "$($DeviceName) the Entra device ID is not formatted correctly"
            }
        }
    }
    catch {
        $StatusCode = [HttpStatusCode]::BadRequest
        $body = "Request body entry '$($ExceptionInfo)' with value $($_.Exception.Message)"
        $Exception = $true
    }

    #
    # Read vault mapping file
    #
    try {
        $VaultsObj = Get-Content -Path $VaultsFile | ConvertFrom-Json
    }
    catch {
        Write-Warning "Cannot load the $($VaultsFile) file"
        $Exception = $true
    }


    #
    # All securtiy checks done and the device is trust
    #
    if ($TrustDevice -eq $True -and $Exception -eq $false) {
        # Get Azure Key Vault Key for 1Password
        if (![string]::IsNullOrEmpty($KeyVaultHost) -and ![string]::IsNullOrEmpty($1PasswordAccessTokenName)) {

            try {
                $KeyVaultURL = 'https://{0}/secrets/{1}?maxresults=1&api-version=7.4' -f $KeyVaultHost, $1PasswordAccessTokenName
                $KeyResponse = Invoke-RestMethod -Uri $KeyVaultURL -Method Get -Headers $AuthHeaderVault -ContentType 'application/json;charset=utf-8'
            }
            catch {
                Write-Warning 'KnightLAPS exception: Azure Key Vault web call exception'
                $Exception = $true
            }

            # Exception from connect to Azure KeyVault and recieved token
            if ($Exception -eq $false -and ![string]::IsNullOrEmpty($KeyResponse)) {
                Write-Output "$($DeviceName) received access permission token for the 1Password service"
                if (![string]::IsNullOrEmpty($1PasswordHost)) {
                    $1PassRespons = Connect-OPWServer -ConnectionHost $1PasswordHost -BearerToken $KeyResponse.value
                    if ($1PassRespons.status -eq 200) {
                        Write-Output "$($DeviceName) connected to $($1PasswordHost) the 1Password service"

                        #Check is device in one password vault
                        $NewPW = -Join ($PWAllowedCharacters.tochararray() | Get-Random -Count $PWLength | ForEach-Object { [char]$_ })

                        #Specify which vault is intended for the request:
                        #1-Step: Location/vault
                        #2-Step: Location/device type/vault
                        $VaultName = ''
                        foreach ($Location in $VaultsObj.Location) {
                            if ($Location.psobject.Properties['Name'].Value -eq $DeviceLocation ) {
                                if ([string]::IsNullOrEmpty($VaultName)) {
                                    # Is a vault on the first json level
                                    if ( $Location.psobject.Properties.Name -contains 'vault') {
                                        $VaultName = $Location.psobject.Properties['vault'].value
                                        Write-Output "$($DeviceName) $($Username) is assigned to the vault $($VaultName)"
                                    }
                                    else {
                                        # seconde json level with device type
                                        foreach ($DeviceTyp in $Location.DeviceType) {
                                            if ($DeviceTyp.psobject.Properties['type'].Value -eq $DeviceType) {
                                                $VaultName = $DeviceTyp.psobject.Properties['vault'].Value
                                                Write-Output "$($DeviceName) $($Username) is assigned to the vault $($VaultName)"

                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if ([string]::IsNullOrEmpty($VaultName)) {
                            Write-Output "$($DeviceName) unknown device type $($DeviceType)"
                            $Exception = $true
                        }
                        else {
                            # Get VaultUUID from 1Password service
                            $1PassRespons = Get-OPWVaults
                            if ($1PassRespons.status -eq 200) {
                                foreach ($Vault in $1PassRespons.payload) {
                                    if ($Vault.name -eq $VaultName) {
                                        $1PasswordVault = $Vault.id
                                        Write-Output "$($DeviceName) $($Username) use now vault $($VaultName) with ID: $($1PasswordVault)"
                                    }
                                }

                                if ([string]::IsNullOrEmpty($1PasswordVault)) {
                                    Write-Output "$($DeviceName) no '$($VaultName)' vault found"
                                    $Exception = $true
                                }
                            }
                            else {
                                Write-Output "$($DeviceName) error search for ID from '$($VaultName)' vault"
                                $Exception = $true
                            }
                        }



                        if (! $Exception) {
                            # Get device name from 1password vault
                            $Response = Get-OPWitem -title $DeviceUserName -VaultUUID $1PasswordVault
                            if ($Response.status -eq '404') {

                                #Device is not in Vault and create new entry in 1 password vault
                                Write-Information "$($DeviceName) $($Username) entry not found in '$($VaultName)' vault, it is created now"
                                $Entry = New-OPWItemObject -title $DeviceUserName -VaultUUID $1PasswordVault -Category 'LOGIN'
                                $Entry.AddLogin($Username, $NewPW)
                                $Entry.AddText('Serialnumber:', $DeviceSN)
                                $Entry.AddText('UUID:', $DeviceUUID)
                                $Respons = Add-OPWItem -InputObject $Entry
                                if ($Respons.status -eq 200) {
                                    Write-Output "$($DeviceName) $($Username) entry was created in '$($VaultName)' vault"
                                    $StatusCode = [HttpStatusCode]::OK
                                    $body = $NewPW
                                }
                                else {
                                    $body = $Response.Message
                                    $StatusCode = $Response.Status
                                    Write-Warning "$($DeviceName) $($Username) entry can not created in '$($VaultName)' vault. $($body)"
                                }

                            }
                            elseif ($Response.status -eq '200') {
                                # Validate minimum rotation date
                                # Has it been long enough since the last change?
                                # ToDo: Overwrite password allowed before date limit is over
                                if ((Get-Date).ToUniversalTime() -ge ($Response.Payload.updatedAt).ToUniversalTime().AddDays($PWMinAge)) {
                                    Write-Output "$($DeviceName) $($Username) entry found in '$($VaultName)' vault. Update entry now."
                                    $ItemUUID = $Response.Payload.id
                                    $JSONPatch = New-OPWJsonPatch
                                    $JsonPatch.Add('replace', '/fields/password/value', $NewPW)
                                    $Respons = Update-OPWItem -id $ItemUUID -VaultUUID $1PasswordVault -InputObject $JSONPatch
                                    if ($Response.status -eq '200') {
                                        Write-Output "$($DeviceName) $($Username) entry updated in '$($VaultName)' vault"
                                        $StatusCode = [HttpStatusCode]::OK
                                        $body = $NewPW
                                    } else {
                                        $body = $Response.Message
                                        $StatusCode = $Response.Status
                                        Write-Warning "$($DeviceName) $($Username) entry can not updated in '$($VaultName)' vault. $($body)"
                                    }
                                }
                                else {
                                    $StatusCode = [HttpStatusCode]::Forbidden
                                    $body = "$($DeviceName) $($Username) entry update from password is not allowed, last password change was long enough ago"
                                    Write-Warning $body
                                }
                            }
                            else {
                                $body = $Response.Message
                                $StatusCode = $Response.Status
                                Write-Warning $body
                            }
                            # Remove 1Password connection
                            Disconnect-OPWServer

                        }
                        else {
                            $StatusCode = [HttpStatusCode]::BadRequest
                            $body = "$($DeviceName) $($Username) cannot be assigned to the vault"
                            Write-Warning "$($DeviceName) $($Username) $($body)"
                        }

                    }
                    else {
                        $StatusCode = [HttpStatusCode]::BadGateway
                        $body = '1Password Service {0} cannot establisch the session' -f $1PasswordHost
                        Write-Warning "$($DeviceName) $($Username) $($body)"
                    }
                }
                else {
                    $StatusCode = [HttpStatusCode]::BadGateway
                    $body = 'No 1Password host defined in the configuration'
                    Write-Warning "$($DeviceName) $($Username) $($body)"
                }
            }
            else {
                $StatusCode = [HttpStatusCode]::BadRequest
                $body = 'Azure Key Vault cannot read the 1Password authentication key'
                Write-Warning "$($DeviceName) $($Username) $($body)"
            }
        }
        else {
            $StatusCode = [HttpStatusCode]::BadRequest
            $body = 'No KeyVault host defined in the configuration or access token missing'
            Write-Warning "$($DeviceName) $($Username) $($body)"

        }

    }
    else {
        $StatusCode = [HttpStatusCode]::BadRequest
        $body = "$($StatusCode.value__): Device checks or request validation faild, the request is rejected. $($body)"
        Write-Warning "$($DeviceName) $($Username) $($body)"
    }
}
else {
    $StatusCode = [HttpStatusCode]::BadRequest
    $body = "$($StatusCode.value__):  Request body from client is empty"
    Write-Warning "$($DeviceName) $($Username) $($body)"
}
Write-Output "$($DeviceName) request handling finished"
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = $body
    })

