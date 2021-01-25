<#PSScriptInfo
.VERSION 1.0.1
.GUID 09a75817-166a-4c9e-8d94-46b64526e01b
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
        This configuration will change the forest functional level to
        a Windows Server 2012 R2 Forest.
#>
Configuration ADForestFunctionalLevel_SetLevel_Config
{
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
        ADForestFunctionalLevel 'ChangeForestFunctionalLevel'
        {
            ForestIdentity = 'contoso.com'
            ForestMode     = 'Windows2012R2Forest'
        }
    }
}
