<#PSScriptInfo
.VERSION 1.0.0
.GUID ba7fb687-dad4-40b2-9776-c6b49386c297
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
        This configuration will create two Active Directory computer accounts
        enabled. The property Enabled will not be enforced in either case.
#>

Configuration AddComputerAccount_Config
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
        xADComputer 'CreateEnabled_SQL01'
        {
            ComputerName = 'SQL01'
        }

        xADComputer 'CreateEnabled_SQL02'
        {
            ComputerName      = 'SQL02'
            EnabledOnCreation = $true
        }
    }
}
