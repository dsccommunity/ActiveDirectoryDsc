<#PSScriptInfo
.VERSION 1.0.1
.GUID 6c3b1da3-f139-42e5-89e9-b9c9986122c8
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
        This configuration will create a KDS root key. If the date is set to a time
        slightly ahead in the future, the key won't be usable for at least 10 hours
        from the creation time.
#>
Configuration ADKDSKey_CreateKDSRootKey_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADKDSKey 'ExampleKDSRootKey'
        {
            Ensure        = 'Present'
            EffectiveTime = '1/1/2030 13:00'
            # Date must be set to at time in the future
        }
    }
}
