<#PSScriptInfo
.VERSION 1.0.1
.GUID f758390b-0576-416a-9110-a0b26263415e
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
        This configuration will create a group managed service account in the specified path.
#>
Configuration ADManagedServiceAccount_CreateGroupManagedServiceAccountCustomPath_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        Node localhost
        {
            ADManagedServiceAccount 'ExampleGroupMSA'
            {
                Ensure             = 'Present'
                ServiceAccountName = 'Service01'
                AccountType        = 'Group'
                Path               = 'OU=ServiceAccounts,DC=contoso,DC=com'
            }
        }
    }
}
