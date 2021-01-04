<#PSScriptInfo
.VERSION 1.0.1
.GUID b743c31a-6db6-4aad-93fb-7f209042d8c1
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
        This configuration will create a group managed service account with members in the default 'Managed Service
        Accounts' container.
#>
Configuration ADManagedServiceAccount_CreateGroupManagedServiceAccountWithMembers_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADManagedServiceAccount 'AddingMembersUsingSamAccountName'
        {
            Ensure                    = 'Present'
            ServiceAccountName        = 'Service01'
            AccountType               = 'Group'
            ManagedPasswordPrincipals = 'User01', 'Computer01$'
        }

        ADManagedServiceAccount 'AddingMembersUsingDN'
        {
            Ensure                    = 'Present'
            ServiceAccountName        = 'Service02'
            AccountType               = 'Group'
            ManagedPasswordPrincipals = 'CN=User01,OU=Users,DC=contoso,DC=com', 'CN=Computer01,OU=Computers,DC=contoso,DC=com'
        }
    }
}
