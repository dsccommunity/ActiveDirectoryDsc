<#PSScriptInfo
.VERSION 1.0
.GUID 0c29d71c-5787-49e6-97e9-c74583028f63
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT (c) Microsoft Corporation. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xActiveDirectory/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xActiveDirectory
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.PRIVATEDATA
#>

#Requires -module xActiveDirectory

<#
    .DESCRIPTION
        This configuration will add a Service Principal Name to a user account.
#>

Configuration AddUserServicePrincipalName_Config
{
    Import-DscResource -Module xActiveDirectory

    Node localhost
    {
        xADServicePrincipalName 'SQL01Svc'
        {
            ServicePrincipalName = 'MSSQLSvc/sql01.contoso.com:1433'
            Account              = 'SQL01Svc'
        }
    }
}
