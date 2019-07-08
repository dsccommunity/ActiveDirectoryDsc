<#PSScriptInfo
.VERSION 1.0.0
.GUID 6c3b8deb-2fdb-4d81-b74d-81dbfe86fcd7
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
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module xActiveDirectory

<#
    .DESCRIPTION
        This configuration will create an Active Directory computer account
        disabled. The property Enabled will not be enforced.
#>

Configuration AddComputerAccountDisabled_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainAdministratorCredential
    )

    Import-DscResource -ModuleName xActiveDirectory

    node localhost
    {
        xADComputer 'CreateDisabled'
        {
            ComputerName      = 'CLU_CNO01'
            EnabledOnCreation = $false
        }
    }
}
