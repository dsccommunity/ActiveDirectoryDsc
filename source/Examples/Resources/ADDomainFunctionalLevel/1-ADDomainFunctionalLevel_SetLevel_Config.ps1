<#PSScriptInfo
.VERSION 1.0.1
.GUID 1629d7ce-e8a8-4cba-ae0f-efe795470dd8
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
        This configuration will change the domain functional level to
        a Windows Server 2012 R2 Domain.
#>
Configuration ADDomainFunctionalLevel_SetLevel_Config
{
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
        ADDomainFunctionalLevel 'ChangeDomainFunctionalLevel'
        {
            DomainIdentity = 'contoso.com'
            DomainMode     = 'Windows2012R2Domain'
        }
    }
}
