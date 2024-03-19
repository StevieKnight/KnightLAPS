# KNIGHT-LAPS solution

Looking for another way to change passwords on client computer regularly, I came up an idea to combine this with password management tool [1Password](https://1password.com). I have looked at other solutions in this business. Brand new is the Microsoft solution in Intune,
it can only manage client from Entra ID (Azure AD). I need this solution also for not Entra ID devices from other Windows domains. Other solution from [msendpointmg.com](https://msendpointmgr.com/cloudlaps/) is CloudLAPS. It is great tool with many cool additional features. It was built before MS released its own solution.

I integrated many ideas from both solution in my project. In my software the biggest differenc is the storage of passwords in 1 Password vault. So all password can be saved
in the same place in the company.

I wrote this solution in my spare time on the weekends or in the evening.They are not yet fully completed, still have some idea for the future.


## Requirements for this solution:

- 1Password Cloud Account [www.1password.com](https://1password.com)
- 1Password [Connect Server](https://developer.1password.com/docs/connect).
    - 1password-credentials.json and AuthToken.

  I have installed this in Azure WebAPP. This configuration is described [here](https://github.com/StevieKnight/1PCSWebAPP).
- Screts automation workflow allow access to 1 Password Vaults. The steps are described [here](https://github.com/StevieKnight/1PCSWebAPP#create-secrets-automation-workflow)
- Company KeyVault or a new KeyVault for save Connection String from 1Password Connect Server
- Entra ID app registration for authorizations to graph & keyvault
- Azure Function for Powershell and everything that goes with it.
- Minimum one client computer to install

For distribution, an MDM solution would be helpful, but you can also install it manually on the computer where the password is to be changed.
## Installation of Knight LAPS solution
### Microsoft Azure

The core of the solution running in [Azure Function](https://learn.microsoft.com/en-us/azure/azure-functions/). You need to install the following:

1. Create Entra ID app registration
    1. Open the url [EntraID Admin Portal](https://entra.microsoft.com) and navigate to Applications -> App registrations. Click to  "New registration" to create new App.
    2. The name "Knight LAPS Solution" can be entered in the name field.
    3. Check if the checkbox "Account in this organizational directory only" is selected.
    4. Click to "Register"
    5. Copy the application (client) ID from the overview blade. You will need it later on.
2. Create a the Azure resources groups with the name : rg-knight-solution and select the Azure region that best suits your organization.
3. Deploy the Azure resources with the powershell console and the KnightLAPS.biecp file. The biecp file has no description out on the console, so here is a short description of the biecp file.
    1. Do you need following infos from 1password:
        - 1Password Connect Server Hostname
        - AuthToken for Connect Server
        - Vault UUID for save the logins
    2. Change the naming from azure resources to company specifications
    3. If you want to use exsiting part from azure resource, edit file and change it. e.g comany azure keyvault or logworkspace.
4.  Change into the directory form KnightLAPS and start the process with following command in powershell:
```ps
New-AzResourceGroupDeployment -ResourceGroupName rg-KnightLAPS -TemplateFile .\KnightLAPS.bicep
```



## The Client


EventLog anlegen beim Installieren
 - KnightLAPS-Client


C:\Program Files\Knight-LAPS\knightLaps.ps1


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

