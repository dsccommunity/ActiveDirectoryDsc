<#PSScriptInfo
.VERSION 1.0.1
.GUID 9736d8e5-f4e6-4ae9-9e3f-41267f4026a5
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
        This configuration will create a group managed service account in the default 'Managed Service Accounts'
        container.
#>
Configuration ADManagedServiceAccount_CreateGroupManagedServiceAccount_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADManagedServiceAccount 'ExampleGroupMSA'
        {
            Ensure             = 'Present'
            ServiceAccountName = 'Service01'
            AccountType        = 'Group'
        }
    }
}
