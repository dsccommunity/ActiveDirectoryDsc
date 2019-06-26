<#PSScriptInfo
.VERSION 1.0
.GUID 5f105122-a318-46f4-a7e9-7dc745c57878
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
        This configuration will wait for an AD Domain to respond before returning.
#>

Configuration WaitForADDomain_Config
{
    Import-DscResource -Module xActiveDirectory

    Node localhost
    {
        xWaitForADDomain 'contoso.com'
        {
            DomainName           = 'contoso.com'
            RetryIntervalSec     = 60
            RetryCount           = 10
            RebootRetryCount     = 1
        }
    }
}
