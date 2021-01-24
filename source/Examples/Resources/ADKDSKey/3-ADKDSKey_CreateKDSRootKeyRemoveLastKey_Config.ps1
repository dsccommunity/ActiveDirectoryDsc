<#PSScriptInfo
.VERSION 1.0.1
.GUID 2847174e-ab1c-44a0-8b4f-2ad70219b52b
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
        This configuration will remove the last KDS root key. Use with caution.
        If gMSAs are installed on the network, they will not be able to reset
        their passwords and it may cause services to fail.
#>
Configuration ADKDSKey_CreateKDSRootKeyRemoveLastKey_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADKDSKey 'ExampleKDSRootKeyForceRemove'
        {
            Ensure        = 'Absent'
            EffectiveTime = '1/1/2030 13:00'
            ForceRemove   = $true # This will allow you to remove the key if it's the last one
        }
    }
}
