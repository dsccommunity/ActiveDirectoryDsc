<#PSScriptInfo
.VERSION 1.0.1
.GUID ba30df50-0873-4c2c-872b-96f5c825910d
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
    This configuration will add a read-only domain controller to the domain contoso.com
    and specify a list of account, whose passwords are allowed/denied for synchronisation.
#>
Configuration ADDomainController_AddReadOnlyDomainController_Config
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

        ADDomainController 'Read-OnlyDomainController(RODC)'
        {
            DomainName                          = 'contoso.com'
            Credential                          = $Credential
            SafeModeAdministratorPassword       = $SafeModePassword
            ReadOnlyReplica                     = $true
            SiteName                            = 'Default-First-Site-Name'
            AllowPasswordReplicationAccountName = @('pvdi.test1', 'pvdi.test')
            DenyPasswordReplicationAccountName  = @('SVC_PVS', 'TA2SCVMM')

            DependsOn                           = '[WaitForADDomain]WaitForestAvailability'
        }
    }
}
