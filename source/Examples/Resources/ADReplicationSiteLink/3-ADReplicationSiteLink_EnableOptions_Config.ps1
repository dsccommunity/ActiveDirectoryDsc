<#PSScriptInfo
.VERSION 1.0.1
.GUID c44c6907-d900-4cd8-b48a-2d39013a8bb9
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
        This configuration will modify an existing AD Replication Site Link by enabling Replication Options.
#>
Configuration ADReplicationSiteLink_EnableOptions_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADReplicationSiteLink 'HQSiteLink'
        {
            Name                          = 'HQSiteLInk'
            SitesIncluded                 = 'site1'
            SitesExcluded                 = 'site2'
            Cost                          = 100
            ReplicationFrequencyInMinutes = 20
            OptionChangeNotification      = $true
            OptionTwoWaySync              = $true
            OptionDisableCompression      = $true
            Ensure                        = 'Present'
        }
    }
}
