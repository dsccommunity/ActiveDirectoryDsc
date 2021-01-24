<#PSScriptInfo
.VERSION 1.0.1
.GUID 0c29d71c-5787-49e6-97e9-c74583028f63
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
        This configuration will add a Service Principal Name to a user account.
#>
Configuration ADServicePrincipalName_AddUserServicePrincipalName_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADServicePrincipalName 'SQL01Svc'
        {
            ServicePrincipalName = 'MSSQLSvc/sql01.contoso.com:1433'
            Account              = 'SQL01Svc'
        }
    }
}
