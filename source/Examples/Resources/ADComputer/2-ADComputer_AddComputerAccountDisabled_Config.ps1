<#PSScriptInfo
.VERSION 1.0.1
.GUID 6c3b8deb-2fdb-4d81-b74d-81dbfe86fcd7
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
        This configuration will create an Active Directory computer account
        disabled. The property Enabled will not be enforced.
#>
Configuration ADComputer_AddComputerAccountDisabled_Config
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
        ADComputer 'CreateDisabled'
        {
            ComputerName         = 'CLU_CNO01'
            EnabledOnCreation    = $false

            PsDscRunAsCredential = $Credential
        }
    }
}
