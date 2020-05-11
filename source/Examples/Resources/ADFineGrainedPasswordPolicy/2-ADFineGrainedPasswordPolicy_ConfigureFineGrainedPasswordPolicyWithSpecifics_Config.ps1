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

Configuration ADFineGrainedPasswordPolicy_ConfigureFineGrainedPasswordPolicyWithSpecifics_Config
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String[]]
        $Subjects,

        [Parameter()]
        [System.Boolean]
        $ComplexityEnabled,

        [Parameter()]
        [String]
        $LockoutDuration,

        [Parameter()]
        [String]
        $LockoutObservationWindow,

        [Parameter()]
        [System.UInt32]
        $LockoutThreshold,

        [Parameter()]
        [String]
        $MinPasswordAge,

        [Parameter()]
        [String]
        $MaxPasswordAge,

        [Parameter()]
        [System.UInt32]
        $MinPasswordLength,

        [Parameter()]
        [System.UInt32]
        $PasswordHistoryCount,

        [Parameter()]
        [System.Boolean]
        $ReversibleEncryptionEnabled,

        [Parameter()]
        [System.Boolean]
        $ProtectedFromAccidentalDeletion,

        [Parameter(Mandatory = $true)]
        [System.UInt32]
        $Precedence
    )

    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADFineGrainedPasswordPolicy 'FineGrainedPasswordPolicy'
        {
            Name                            = $Name
            DisplayName                     = $DisplayName
            Subjects                        = $Subjects
            ComplexityEnabled               = $ComplexityEnabled
            LockoutDuration                 = $LockoutDuration
            LockoutObservationWindow        = $LockoutObservationWindow
            LockoutThreshold                = $LockoutThreshold
            MaxPasswordAge                  = $MaxPasswordAge
            MinPasswordAge                  = $MinPasswordAge
            MinPasswordLength               = $MinPasswordLength
            PasswordHistoryCount            = $PasswordHistoryCount
            ReversibleEncryptionEnabled     = $ReversibleEncryptionEnabled
            ProtectedFromAccidentalDeletion = $ProtectedFromAccidentalDeletion
            Precedence                      = $Precedence
        }
    }
}
