<#PSScriptInfo
.VERSION 1.0.1
.GUID 96b94fc3-2b96-47b7-82e8-d0551ec2e738
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
        This configuration will set an Active Directory domain's default password
        policy to set the minimum password length and complexity.
#>
Configuration ADDomainDefaultPasswordPolicy_ConfigureDefaultPasswordPolicy_Config
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter(Mandatory = $true)]
        [System.Boolean]
        $ComplexityEnabled,

        [Parameter(Mandatory = $true)]
        [System.Int32]
        $MinPasswordLength
    )

    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADDomainDefaultPasswordPolicy 'DefaultPasswordPolicy'
        {
            DomainName        = $DomainName
            ComplexityEnabled = $ComplexityEnabled
            MinPasswordLength = $MinPasswordLength
        }
    }
}
