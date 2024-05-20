# KNIGHT-LAPS solution

Looking for another way to change passwords on client computer regularly, I came up an idea to combine this with password management tool [1Password](https://1password.com). I have looked at other solutions in this business. Brand new is the Microsoft solution in Intune,
it can only manage client from Entra ID (Azure AD). I need this solution also for not Entra ID devices from other Windows domains. Other solution from [msendpointmg.com](https://msendpointmgr.com/cloudlaps/) is CloudLAPS. It is great tool with many cool additional features. It was built before MS released its own solution.

I integrated many ideas from both solution in my project. In my software the biggest differenc is the storage of passwords in 1 Password vault. So all password can be saved
in the same place in the company.

I wrote this solution in my spare time on the weekends or in the evening. They are not yet fully completed, still have some idea for the future.


## Requirements for this solution:

- 1Password Cloud Account [www.1password.com](https://1password.com)
- 1Password [Connect Server](https://developer.1password.com/docs/connect).
    - 1password-credentials.json and AuthToken.

  I have installed this in Azure WebAPP. This configuration is described [here](https://github.com/StevieKnight/1PCSWebAPP).
- Screts automation workflow allow access to 1 Password Vaults. The steps are described [here](https://github.com/StevieKnight/1PCSWebAPP#create-secrets-automation-workflow)
- Company KeyVault or a new KeyVault for save Connection String from 1Password Connect Server
- Azure Function for Powershell and everything that goes with it.
- Minimum one client computer to install

For distribution, an MDM solution would be helpful, but you can also install it manually on the computer where the password is to be changed.
## Installation of Knight LAPS solution
### Microsoft Azure

The core of the solution running in [Azure Function](https://learn.microsoft.com/en-us/azure/azure-functions/). You need to install the following:

1. Create a the Azure resources groups with the name : rg-knight-solution and select the Azure region that best suits your organization.
2. Download Biecp file for the deployment or use git to download complete source directory.
```ps
Invoke-RestMethod "https://raw.githubusercontent.com/StevieKnight/KnightLAPS/main/Deploy/KnightLAPS.bicep" -OutFile ".\KnightLAPS.bicep"
```

4. Deploy the Azure resources with the powershell console and the "KnightLAPS.biecp" file. The biecp file has no description out on the console, so here is a short description of the biecp file.
    1. Do you need following infos from 1password:
        - 1Password Connect Server Hostname
        - AuthToken for Connect Server
        - Vault UUID for save the logins
    2. Change the naming from azure resources to company specifications
    3. If you want to use exsiting part from azure resource, edit file and change it. e.g comany azure keyvault or logworkspace.
5.  Change into the directory in which the BIECP file of KnightLAPS was saved and start the process with following command in powershell
```ps
New-AzResourceGroupDeployment -ResourceGroupName rg-KnightLAPS -TemplateFile .\KnightLAPS.bicep
```

6. After deployment, you still need to set the permissions for MS-Graph so that the Azure function can read information about devices.
To do this, download the Powershell script and start it. You will need Tenent ID, the name of the Azure function app and a user with  global admin rights.

```ps
Invoke-RestMethod https://raw.githubusercontent.com/StevieKnight/KnightLAPS/main/Deploy/Add-MSIPermissions.ps1 -OutFile "Add-MSIPermissions.ps1"
```


## The Client

The client establishes a connection to Azure Function in the cloud and controls which local user on the computer is allowed to change the password and when. It determines, based on its parameters, how often a password should be changed for a specific user. These parameters may originate from a configuration file in the client directory or can be passed as arguments when the client is invoked. Parameters passed during client invocation take precedence, allowing configuration from the file to be overridden if necessary.

The client is installed in "C:\Program Files\KnightLAPS" and is executed via the task scheduler. The password change can be set up for different local users.

### Logging
All events are written to the Windows event log under an extra menu itme: **Application and service logs -> KnightLAPS**
These are the event numbers

- 1 - Starting the client script
- 3 - Finish the client script
- 1009 - Create Windows task KL-Client-%USER% from file configuration with ID %ID%
- 4009 - Cannot create Windows task "KL-Client-%USER%" with ID %ID% because there is already a task with the same name
- 5009 - Unknown error could not create the Windows task "KL-Client-%USER%" with ID %ID% from the client configuration. %EXCEPTIONMESSAGE%.
- 1011 - Cli-Param %PARAM%: '%VALUE%' is used
- 1012 - Task %ID% %PARAM% : %VALUE% is used
- 4012 - Task configuration with the id % not found.
- 4012 - No found commandline parameter %PARAM% or TaskID. The process has now been stopped.
- 4012 - Task configuration with the id %ID% not found. The process has now been stopped.
- 1013 - Collecting EID information from the device
- 1014 - The device is not joind to Entra ID
- 1020 - Send a web request to the KnightLAPS endpoint to generate a password and update the secret
- 1021 - Receive respons to my request from Host %HOSTNAME% endpoint
- 1031 - Starting process to handle new password
- 1032 - The local administrator account exists, the password is now updated
- 5010 - The client needs admin rights to work correctly
- 5013 - Invalid parameter %PARAM%:'%VALUE%'.The process has now been stopped.
- 5014 - No local user with the name '%Username%' could be found on the device. The process has now been stopped.
- 5029 - Unknown %ERRORMESSAGE%
- 5024 - BadGateway 502 1Password Service %1PASSWORDHOST% cannot establisch the session
- 5024 - BadGateway 502 No 1Password host defined in the configuration
- 5025 - BadRequest 400 Azure Key Vault cannot read the 1Password authentication key
- 5025 - BadRequest 400 No KeyVault host defined in the configuration or access token missing
- 5025 - BadRequest 400 Device checks or request validation faild, the request is rejected
- 5025 - BadRequest 400 Request body from client is empty

### Security

The client collects a range of information about itself and sends it to the Azure function for identification and authorization. If the computer is not registered with the Entra ID, the UUID must be sent to the Azure function.

- Entra Device ID
- Client UUID
- Thumbprint from MDM Certificate
- PublicKey from MDM Certificate

EventLog anlegen beim Installieren
 - KnightLAPS-Client


C:\Program Files\Knight-LAPS\KLC.ps1


Fehlercodes
503: No Managed Service Identit activated : Azure Function is running in Azure can not found MSI.


Der KnightLAPS-Client soll folgende Daten liefern
Name des Computers
-> Alternativnamen _ ersetzt durch -
Modell
Seriennummer
Azure Identidy




Trust Check option
==================

1. Entra ID joined devices

    - The device is registiert in Entra ID and the device id is the same in both systems.
    - Check the thumbprint from device certificate (MS-Organization-Access) with information in Entra ID thumbprint.
    - Check is the device enabled in Entra ID.

2. Device to another domain or workgroups

    - The UUID from device must be on the whitlist. The whitelist is a file on azure function directory. The name is UUID.dat.

 ToDo: Develop another check

User Cases
=============

1. Entra ID verknüfte Geräte

    - Ein neues Gerät fragt zum erstenmal nach einem Passwort für den Lokal Administrator Account.
    - Ein vorhandes Gerät fragt nach einem neuen Passwort, die Zeit ist noch nicht um wann geändert werden darf.
    - Ein Vorhandes Gerät fragt nach einem neuen Passwort und die Zeit Wartezeit ist abgelaufen.
    - Ein Vorhandes Gerät fragt mit einem anderen Passwortlänge.

2. Geräte aus anderen Domäne / Workgroups
    - Ein neues Gerät fragt zum erstenmal nach einem Passwort für den Lokal Administrator Account
    - Ein vorhandes Gerät fragt nach einem neuen Passwort, die Zeit ist noch nicht um wann geändert werden darf.
    - Ein Vorhandes Gerät fragt nach einem neuen Passwort und die Zeit Wartezeit ist abgelaufen.
    - Ein Vorhandes Gerät fragt mit einem anderen Passwortlänge

