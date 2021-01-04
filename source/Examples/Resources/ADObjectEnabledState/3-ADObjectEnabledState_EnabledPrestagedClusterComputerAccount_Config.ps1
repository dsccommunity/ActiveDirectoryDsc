<#PSScriptInfo
.VERSION 1.0.1
.GUID 1da557bb-07a1-4461-8f64-df0d62b30305
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
#Requires -Module xFailoverCluster

<#
    .DESCRIPTION
        This configuration will configure a cluster using a pre-staged computer
        account, and enforcing the pre-staged computer account to be enabled.
#>
Configuration ADObjectEnabledState_EnabledPrestagedClusterComputerAccount_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName xFailoverCluster -ModuleVersion '1.14.1'

    node localhost
    {
        xCluster 'CreateCluster'
        {
            Name                          = 'CLU_CNO01'
            StaticIPAddress               = '192.168.100.20/24'
            DomainAdministratorCredential = $Credential
        }

        ADObjectEnabledState 'EnforceEnabledPropertyToEnabled'
        {
            Identity    = 'CLU_CNO01'
            ObjectClass = 'Computer'
            Enabled     = $true

            DependsOn   = @(
                '[xCluster]CreateCluster'
            )
        }
    }
}
