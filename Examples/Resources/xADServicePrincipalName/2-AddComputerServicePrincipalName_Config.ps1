<#PSScriptInfo
.VERSION 1.0
.GUID 634194bb-189a-4b26-bd80-7c01270026ea
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
        This configuration will add a Service Principal Name to a computer account.
#>

Configuration AddComputerServicePrincipalName_Config
{
    Import-DscResource -Module xActiveDirectory

    Node localhost
    {
        xADServicePrincipalName 'web.contoso.com'
        {
            ServicePrincipalName = 'HTTP/web.contoso.com'
            Account              = 'IIS01$'
        }
    }
}
