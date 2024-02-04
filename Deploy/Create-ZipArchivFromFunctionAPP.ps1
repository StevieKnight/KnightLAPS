<#
.SYNOPSIS
This script create ZIP archiv for zip deployment with biecp

.DESCRIPTION
In order for the Azure function APP to be deployed automatically, some file
must be downloaded when deploying. This can be realized with a ZIP file.
This script packs the necessary files together and saves them in an archive under
Packages

.NOTES
    FileName:    Create-ZipArchivFromFunctionAPP.ps1
    Author:      Stevie Knight
    Contact:     @StevieKnight
    Created:     2024-02-04
    Updated:     2024-02-04

    Version history:
    1.0.0 - (2024-02-04) Script created
#>
# Define variables
$TMPFolder = ".\" + $(New-Guid)
$PackagesFolder = ".\..\Packages"
$Filename = "KnigthLAPS-Function-APP-current.zip"

# Create temp folder
if (!(Test-Path $TMPFolder)) {New-Item -Path $TMPFolder -ItemType Directory | Out-Null}

# Copy files in the temp folder
Copy-Item -Path "..\Function\GetNewSecret\" -Destination $TMPFolder -Recurse
Copy-Item -Path "..\Function\host.json" -Destination  $TMPFolder
Copy-Item -Path "..\Function\profile.ps1" -Destination  $TMPFolder
Copy-Item -Path "..\Function\requirements.psd1" -Destination $TMPFolder

# Compress the contents of the temp folder and save the ZIP file
$compress = @{
    Path = "$TMPFolder\*"
    CompressionLevel = "Fastest"
    DestinationPath = $PackagesFolder+"\"+$Filename
    }
Compress-Archive @compress -Force
# Delete the temp folder
if ((Test-Path $TMPFolder)) {Remove-Item $TMPFolder -Recurse -Force}

