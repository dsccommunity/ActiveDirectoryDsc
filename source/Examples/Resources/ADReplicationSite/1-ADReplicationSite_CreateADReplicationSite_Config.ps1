<#PSScriptInfo
.VERSION 1.0.1
.GUID db6e6810-76eb-464f-9514-92bc91ec28de
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
        This configuration will create an Active Directory replication site
        called 'Seattle'.
#>
Configuration ADReplicationSite_CreateADReplicationSite_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADReplicationSite 'SeattleSite'
        {
            Ensure = 'Present'
            Name   = 'Seattle'
        }
    }
}
