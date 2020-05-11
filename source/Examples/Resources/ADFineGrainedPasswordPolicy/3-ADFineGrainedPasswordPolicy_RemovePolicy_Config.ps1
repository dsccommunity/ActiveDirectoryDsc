<#PSScriptInfo
.VERSION 1.0.1
.GUID d1d88021-930b-4928-8f1f-7a002e374847
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
        This configuration will remove an Active Directory domain fine-grained password policy.
#>

Configuration ADFineGrainedPasswordPolicy_RemovePolicy_Config
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.UInt32]
        $Precedence,

        [Parameter()]
        [System.String]
        $Ensure = 'Absent'
    )

    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADFineGrainedPasswordPolicy 'FineGrainedPasswordPolicy'
        {
            Name       = $Name
            Precedence = $Precedence
            Ensure     = $Ensure
        }
    }
}
