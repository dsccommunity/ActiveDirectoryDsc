<#PSScriptInfo
.VERSION 1.0.1
.GUID 8fced2a6-bb34-400c-a44e-2c484e3bc9e3
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
        This configuration will remove the Active Directory replication site
        called 'Cupertino'.
#>
Configuration ADReplicationSite_RemoveADReplicationSite_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADReplicationSite 'CupertinoSite'
        {
            Ensure = 'Absent'
            Name   = 'Cupertino'
        }
    }
}
