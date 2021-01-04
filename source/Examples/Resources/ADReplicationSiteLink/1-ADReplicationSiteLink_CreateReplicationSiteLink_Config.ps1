<#PSScriptInfo
.VERSION 1.0.1
.GUID c3f14177-bf96-4296-aa1c-4a9f08c8e34e
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
        This configuration will create an AD Replication Site Link.
#>
Configuration ADReplicationSiteLink_CreateReplicationSiteLink_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADReplicationSiteLink 'HQSiteLink'
        {
            Name                          = 'HQSiteLInk'
            SitesIncluded                 = @('site1', 'site2')
            Cost                          = 100
            ReplicationFrequencyInMinutes = 15
            Ensure                        = 'Present'
        }
    }
}
