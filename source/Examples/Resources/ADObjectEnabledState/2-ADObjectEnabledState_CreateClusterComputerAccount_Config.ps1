<#PSScriptInfo
.VERSION 1.0.1
.GUID b4d414dc-e230-4055-bdc3-fae268493881
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
        This configuration will create a computer account disabled, configure
        a cluster using the disabled computer account, and enforcing the
        computer account to be enabled.
#>
Configuration ADObjectEnabledState_CreateClusterComputerAccount_Config
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
        ADComputer 'ClusterAccount'
        {
            ComputerName      = 'CLU_CNO01'
            EnabledOnCreation = $false
        }

        xCluster 'CreateCluster'
        {
            Name                          = 'CLU_CNO01'
            StaticIPAddress               = '192.168.100.20/24'
            DomainAdministratorCredential = $Credential

            DependsOn                     = '[ADComputer]ClusterAccount'
        }

        ADObjectEnabledState 'EnforceEnabledPropertyToEnabled'
        {
            Identity    = 'CLU_CNO01'
            ObjectClass = 'Computer'
            Enabled     = $true

            DependsOn   = '[xCluster]CreateCluster'
        }
    }
}
