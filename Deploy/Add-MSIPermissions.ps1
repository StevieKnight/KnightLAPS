<#
.SYNOPSIS
This script set in Azuze permissions for MS Graph

.DESCRIPTION
So that the Azure function APP can access the Graph API with Managed Service Identity (MSI).
The rights must be set for this. Unfortunately, this cannot yet be set via the web interface.
be set.

.NOTES
    FileName:    Add-MSIPermissions.ps1
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2024-02-04
    Updated:     2024-02-04

    Version history:
    1.0.0 - (2024-02-04) Script created
#>

# Assign static variables

param(
    [Parameter(Mandatory = $true,
    HelpMessage="Enter your Enter Tenant ID.")]
    $TenantID,

    [Parameter(Mandatory = $true,
    HelpMessage="Enter the object ID that you want to authorize in MS Graph using MSI.")]
    $MSIObjectID
)
# Authenticate against Azure AD, as Global Administrator
Connect-AzureAD -TenantId $TenantID

$MSGraphAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph (graph.microsoft.com) application ID
$MSGraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$($MSGraphAppId)'"
$RoleNames = @("Device.Read.All")

# Assign each roles to Managed System Identity, first validate they exist
foreach ($RoleName in $RoleNames) {
    $AppRole = $MSGraphServicePrincipal.AppRoles | Where-Object { $PSItem.Value -eq $RoleName -and $PSItem.AllowedMemberTypes -contains "Application" }
    if ($null -ne $AppRole) {
        New-AzureAdServiceAppRoleAssignment -ObjectId $MSIObjectID -PrincipalId $MSIObjectID -ResourceId $MSGraphServicePrincipal.ObjectId -Id $AppRole.Id
    }
}