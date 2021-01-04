<#PSScriptInfo
.VERSION 1.0.0
.GUID f2ecc331-e242-4204-a6b1-54fd68c852b7
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/ActiveDirectoryDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/ActiveDirectoryDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.RELEASENOTES
Initial release
#>

#Requires -Module ActiveDirectoryDsc

<#
    .DESCRIPTION
        This configuration will create a new domain-local group in contoso with
        two members; one from the contoso domain and one from the fabrikam domain.
        This qualified SamAccountName format is required if any of the users are in a
        one-way trusted forest/external domain.
#>
Configuration ADGroup_NewGroupOneWayTrust_Config
{
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node localhost
    {
        ADGroup 'ExampleExternalTrustGroup'
        {
            GroupName           = 'ExampleExternalTrustGroup'
            GroupScope          = 'DomainLocal'
            MembershipAttribute = 'SamAccountName'
            Members             = @(
                'contoso\john'
                'fabrikam\toby'
            )
        }
    }
}
