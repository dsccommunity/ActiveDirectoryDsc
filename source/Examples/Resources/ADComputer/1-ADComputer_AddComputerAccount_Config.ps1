<#PSScriptInfo
.VERSION 1.0.1
.GUID ba7fb687-dad4-40b2-9776-c6b49386c297
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
        This configuration will create two Active Directory computer accounts
        enabled. The property Enabled will not be enforced in either case.
#>
Configuration ADComputer_AddComputerAccount_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
        ADComputer 'CreateEnabled_SQL01'
        {
            ComputerName         = 'SQL01'

            PsDscRunAsCredential = $Credential
        }

        ADComputer 'CreateEnabled_SQL02'
        {
            ComputerName         = 'SQL02'
            EnabledOnCreation    = $true

            PsDscRunAsCredential = $Credential
        }
    }
}
