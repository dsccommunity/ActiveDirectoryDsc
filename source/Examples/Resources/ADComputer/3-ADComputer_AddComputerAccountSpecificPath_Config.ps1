<#PSScriptInfo
.VERSION 1.0.1
.GUID 1a18e0a9-2a4b-4406-939e-ac2bb7b6e917
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
        on the specified domain controller and in the specific organizational
        unit.
#>
Configuration ADComputer_AddComputerAccountSpecificPath_Config
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
        ADComputer 'CreateComputerAccount'
        {
            DomainController = 'DC01'
            ComputerName     = 'SQL01'
            Path             = 'OU=Servers,DC=contoso,DC=com'
            Credential       = $Credential
        }
    }
}
