<#PSScriptInfo
.VERSION 1.0.1
.GUID d8518e26-7fc3-4902-a1d3-e5ebf93489d8
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/ActiveDirectoryDsc/blob/master/LICENSE
.PROJECTURI https://github.com/dsccommunity/ActiveDirectoryDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.RELEASENOTES
Updated author, copyright notice, and URLs.
#>

#Requires -Module ActiveDirectoryDsc

<#
    .DESCRIPTION
        This configuration will create an Active Directory domain fine-grained password
        policy with specific settings settings.
#>

Configuration ADFineGrainedPasswordPolicy_ConfigurePolicyWithSpecifics_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADFineGrainedPasswordPolicy 'FineGrainedPasswordPolicy'
        {
            Name                            = 'DomainUsers'
            DisplayName                     = 'Domain Users Fine Grained Password Policy'
            Subjects                        = 'Domain Users'
            ComplexityEnabled               = $true
            LockoutDuration                 = '00:30:00'
            LockoutObservationWindow        = '00:30:00'
            LockoutThreshold                = 5
            MaxPasswordAge                  = '42.00:00:00'
            MinPasswordAge                  = '1.00:00:00'
            MinPasswordLength               = 15
            PasswordHistoryCount            = 24
            ReversibleEncryptionEnabled     = $false
            ProtectedFromAccidentalDeletion = $true
            Precedence                      = 10
        }
    }
}
