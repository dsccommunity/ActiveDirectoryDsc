<#PSScriptInfo
.VERSION 1.0.1
.GUID d343e3b3-0a2b-47c4-9445-b2c9b915f588
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/ActiveDirectoryDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/ActiveDirectoryDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.RELEASENOTES
Updated author, copyright notice, and URLs.
#>

#Requires -Module ActiveDirectoryDsc

<#
    .DESCRIPTION
    This configuration will manage the Tombstone Lifetime setting of the
    Active Directory forest.
#>
Configuration ADForestProperties_TombstoneLifetime_Config
{
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
        ADForestProperties 'ContosoProperties'
        {
            ForestName        = 'contoso.com'
            TombstoneLifetime = 200
        }
    }
}
