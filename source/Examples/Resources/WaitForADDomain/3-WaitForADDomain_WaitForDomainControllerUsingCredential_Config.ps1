<#PSScriptInfo
.VERSION 1.0.1
.GUID d0713e4e-274b-4510-949e-39bce2ef2158
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
        to respond within 300 seconds (default) in the domain 'contoso.com'
        before returning and allowing the configuration to continue to run.
        If the timeout is reached an error will be thrown.
        This will use the user credential passed in the parameter Credential
        when determining if the domain is available.
#>
Configuration WaitForADDomain_WaitForDomainControllerUsingCredential_Config
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
            DomainName = 'contoso.com'
            Credential = $Credential
        }
    }
}
