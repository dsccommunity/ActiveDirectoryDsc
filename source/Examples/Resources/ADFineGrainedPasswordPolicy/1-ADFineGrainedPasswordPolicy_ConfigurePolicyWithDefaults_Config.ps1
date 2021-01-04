<#PSScriptInfo
.VERSION 1.0.0
.GUID 78858ff6-a4dc-4cfb-8af5-07113f6b900a
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/ActiveDirectoryDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/ActiveDirectoryDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.RELEASENOTES
#>

#Requires -Module ActiveDirectoryDsc

<#
    .DESCRIPTION
        This configuration will create an Active Directory domain fine-grained password
        policy with default settings.
#>

Configuration ADFineGrainedPasswordPolicy_ConfigurePolicyWithDefaults_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADFineGrainedPasswordPolicy 'FineGrainedPasswordPolicy'
        {
            Name       = 'DomainUsers'
            Precedence = 10
        }
    }
}
