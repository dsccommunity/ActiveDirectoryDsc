<#PSScriptInfo
.VERSION 1.0.1
.GUID 0d9d34c3-c750-45f8-8611-74087e958fe1
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
        This configuration will wait for an Active Directory domain controller
        to respond within 600 seconds in the domain 'contoso.com' before
        returning and allowing the configuration to continue to run. If the timeout
        is reached an error will be thrown.
        This will use the user credential passed in the built-in PsDscRunAsCredential
        parameter when determining if the domain is available.
#>
Configuration WaitForADDomain_WaitForDomainControllerWithLongerDelay_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        WaitForADDomain 'contoso.com'
        {
            DomainName           = 'contoso.com'
            WaitTimeout          = 600

            PsDscRunAsCredential = $Credential
        }
    }
}
