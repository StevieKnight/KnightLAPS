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
    Updated:     2023-05-01

    Version history:
    1.0.0 - (2023-05-01) Script created
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
$KeyVaultHost = $env:KeyVaultHost
$1PasswordHost = $env:OnePasswordHost
$1PasswordVault = $env:VaultUUID
$1PasswordAccessTokenName = $env:OnePasswordAccessTokenName

#Password policy settings
$PWAllowedCharacters = $env:PWAllowedCharacters
$PWMinAge = $env:PWAgeinDay


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
                Write-Host 'Module MSAL.ps does not exist. Install from https://www.powershellgallery.com/packages/MSAL.PS'
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
                'ExpiresOn' = $Response.expires_on }

                #Graph token
                $ResourceURI = 'https://graph.microsoft.com'
                $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"
                $Response = Invoke-RestMethod -Uri $AuthURI -Method 'Get' -Headers @{ 'Secret' = "$($MSISecret)" }
                $AuthHeaderGraph = @{ 'Authorization' = "Bearer $($Response.access_token)"
                'ExpiresOn' = $Response.expires_on }   

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
    Write-Output "New incoming request from a KnightLAPS client: $($Request.Body.DeviceName) "

    #Validate request body and mapping variables
    $DeviceName     = $Request.Body.DeviceName
    $EntraDeviceID  = $Request.Body.EntraDeviceID
    $DeviceUUID     = $Request.Body.CUUID
    $Thumbprint     = $Request.Body.Thumbprint
    #$PublicKey     = $Request.Body.PublicKey
    $Username       = $Request.Body.Username
    $DeviceSN       = $Request.Body.DeviceSN
    #$DeviceSuffix  = $Request.Body.DeviceSuffix
    #$OverrideAllow = $Request.Body.Override
    
    # Password length from device has priority  
    $PWLength = $Request.Body.PasswordLength
    if ([string]::IsNullOrEmpty($PWLength)){
        Write-Output "$($DeviceName) Use the default password length of $($env:PWLength) characters"
        $PWLength = $env:PWLength
    } else {
        Write-Output "$($DeviceName) Use the device request password length of $($PWLength) characters"
    }
    

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
                Write-Information "Device with $DeviceUUID found"
                # TODo 
                # Check another source for check the device information
                #
                $TrustDevice = $true
            }
            else {
                Write-Warning "$($DeviceName) device is not allow to rotate passwort with KnightLAPS"
            }  
        }
        catch {
            Write-Warning 'KnightLAPS exception: Can not laod UUID.dat'
            $Exception = $true
        }
        
        
        
    }
    else {
        # Is the EntraDeviceID formatted correctly?
        if ($EntraDeviceID -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
            Write-Output "$($DeviceName) has send an Entra device ID, the next will start..."
            
            # Is the device id registered in entra id
            $URI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($EntraDeviceID)'"
            $EntraDevice = (Invoke-RestMethod -Method 'Get' -Uri $URI -ContentType 'application/json' -Headers $AuthHeaderGraph -ErrorAction SilentlyContinue).value
            if ($EntraDevice.count -eq 1) {
                Write-Output "$($DeviceName) is registered in Entra ID"
                Write-Output "$($DeviceName) Checking thumprint from device with saved item in Entra ID:$($Thumbprint)"
                $Key = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EntraDevice.alternativeSecurityIds.key))
                if ($Key.Split('>')[1].SubString(0, 40) -eq $Thumbprint) {
                    Write-Output "$($DeviceName) thumbprint check succesfull"
                    Write-Output "$($DeviceName) Checking if the device is registered in the Entra ID"
                    if ($true -eq $EntraDevice.accountEnabled) {
                        Write-Output "$($DeviceName) is trusted and enabled in Entra ID"
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

    
    #
    # All securtiy checks done and the device is trust
    #
    if ($TrustDevice -eq $True) {   

        # Gave exception before in process 
        if ($Exception -eq $false) {

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
                    Write-Output "$($DeviceName) Received access permission token for the 1Password service"
                    if (![string]::IsNullOrEmpty($1PasswordHost)) {
                        $1PassRespons = Connect-OPWServer -ConnectionHost $1PasswordHost -BearerToken $KeyResponse.value
                        if ($1PassRespons.status -eq 200) {
                            Write-Output "$($DeviceName) 1Password Service connected..."
                
                            #Check is device in one password vault
                            $NewPW = -Join ($PWAllowedCharacters.tochararray() | Get-Random -Count $PWLength | ForEach-Object { [char]$_ })
                            
                            # Get device name from 1password vault
                            $Response = Get-OPWitem -title $DeviceName -VaultUUID $1PasswordVault
                            
                            if ($Response.status -eq '404') {
                            
                                #Device is not in Vault and create new entry in 1 password vault      
                                Write-Information "$($DeviceName) Device not found in 1Password vault, it is created now"
                                $Entry = New-OPWItemObject -title $DeviceName -VaultUUID $1PasswordVault -Category 'LOGIN'
                            
                                $Entry.AddLogin($Username, $NewPW)
                                $Entry.AddText('Serialnumber:', $DeviceSN)
                                $Entry.AddText('UUID:', $DeviceUUID)
                                $respons = Add-OPWItem -InputObject $Entry
                                if ($respons.status -eq 200) {
                                    Write-Output $respons.message
                                }

                            }
                            elseif ($Response.status -eq '200') {
                                # Validate minimum rotation date
                                # Has it been long enough since the last change?
                                if ((Get-Date).ToUniversalTime() -ge ($Response.Payload.updatedAt).ToUniversalTime().AddDays($PWMinAge)) {
                                    Write-Output "$($DeviceName) found in vault. Update entry."
                                    $ItemUUID = $Response.Payload.id
                                    $JSONPatch = New-OPWJsonPatch
                                    $JsonPatch.Add('replace', '/fields/password/value', $NewPW)
                                    $Respons = Update-OPWItem -id $ItemUUID -VaultUUID $1PasswordVault -InputObject $JSONPatch
                                    if ($Response.status -eq '200') {
                                        Write-Output "$($DeviceName) Entry updated in 1password vault"
                                        $StatusCode = [HttpStatusCode]::OK
                                        $body = $NewPW
                                    }
                                   
                                }
                                else {
                                    $body = "$($DeviceName) Update from password is not allowed, last password change was long enough ago"
                                    $StatusCode = [HttpStatusCode]::Forbidden
                                    Write-Warning $body
                                }
                            }
                            # Remove 1Password connection 
                            Disconnect-OPWServer
    
                        }
                        else {
                            $body = '1Password Service {0} cannot establisch the session' -f $1PasswordHost 
                            $StatusCode = [HttpStatusCode]::BadRequest
                            Write-Warning $($DeviceName) $body
                        }  
                    }
                    else {
                        $body = 'No 1Password host defined in the configuration'
                        $StatusCode = [HttpStatusCode]::BadGateway
                        Write-Warning $($DeviceName) $body
                    }
                }
                else {
                    $body = 'Can´t read 1Password Authkey from Azure Key Vault'
                    $StatusCode = [HttpStatusCode]::BadRequest
                    Write-Warning $($DeviceName) $body
                }
            }
            else {
                $body = 'No KeyVault host defined in the configuration or access token missing'
                Write-Warning $($DeviceName) $body
                $StatusCode = [HttpStatusCode]::BadRequest
            }
        }
    }
    else {
        $StatusCode = [HttpStatusCode]::BadRequest
        $body = "Status $($StatusCode.value__): Device checks and request validation faild, the request is rejected..."
        Write-Warning $($DeviceName) $body
    }
}
else {
    $StatusCode = [HttpStatusCode]::BadRequest
    $body = "Status $($StatusCode.value__):  Request body from client is empty"
    Write-Warning $($DeviceName) $body
}
Write-Output "$($DeviceName) request handling finished"
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = $body
    })
