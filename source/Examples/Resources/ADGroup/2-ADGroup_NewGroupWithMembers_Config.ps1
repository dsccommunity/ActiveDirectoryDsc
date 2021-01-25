<#PSScriptInfo
.VERSION 1.0.1
.GUID 0d6564cf-5492-4922-b4ef-4c20da0b7b3f
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
        This configuration will create a new domain-local group with three members.
#>
Configuration ADGroup_NewGroupWithMembers_Config
{
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
        ADGroup 'dl1'
        {
            GroupName  = 'DL_APP_1'
            GroupScope = 'DomainLocal'
            Members    = 'john', 'jim', 'sally'
        }
    }
}
