<#PSScriptInfo
.VERSION 1.0.1
.GUID 77c6a983-7bb0-4457-88e2-3e4f36727748
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
        This configuration will create a new domain tree in an existing forest with
        a Domain Functional Level of Windows Server 2016 (WinThreshold).
        The credential parameter must contain the domain qualified credentials of a
        user in the forest who has permissions to create a new domain tree.
#>
Configuration ADDomain_NewDomainTree_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $SafeModePassword
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node 'localhost'
    {
        WindowsFeature 'ADDS'
        {
            Name   = 'AD-Domain-Services'
            Ensure = 'Present'
        }

        WindowsFeature 'RSAT'
        {
            Name   = 'RSAT-AD-PowerShell'
            Ensure = 'Present'
        }

        ADDomain 'fabrikam.com'
        {
            DomainName                    = 'fabrikam.com'
            Credential                    = $Credential
            SafemodeAdministratorPassword = $SafeModePassword
            DomainType                    = 'TreeDomain'
            DomainMode                    = 'WinThreshold'
            ParentDomainName              = 'contoso.com'
        }
    }
}
