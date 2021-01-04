<#PSScriptInfo
.VERSION 1.0.1
.GUID 05a243fd-5f16-44f9-8031-4c9f4a475cb8
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
        This configuration will add a domain controller to the domain
        contoso.com.
#>
Configuration ADDomainController_AddDomainControllerToDomainMinimal_Config
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

    node localhost
    {
        WindowsFeature 'InstallADDomainServicesFeature'
        {
            Ensure = 'Present'
            Name   = 'AD-Domain-Services'
        }

        WindowsFeature 'RSATADPowerShell'
        {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-PowerShell'

            DependsOn = '[WindowsFeature]InstallADDomainServicesFeature'
        }

        WaitForADDomain 'WaitForestAvailability'
        {
            DomainName = 'contoso.com'
            Credential = $Credential

            DependsOn  = '[WindowsFeature]RSATADPowerShell'
        }

        ADDomainController 'DomainControllerMinimal'
        {
            DomainName                    = 'contoso.com'
            Credential                    = $Credential
            SafeModeAdministratorPassword = $SafeModePassword

            DependsOn                     = '[WaitForADDomain]WaitForestAvailability'
        }
    }
}
