<#PSScriptInfo
.VERSION 1.0.1
.GUID 2b2ad944-0a4f-457e-b8ad-98e86767d77c
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
        This configuration will add a group permission to allow read and write
        (ReadProperty, WriteProperty) of all properties of computer objects in
        an OU and any sub-OUs that may get created.
#>
Configuration ADObjectPermissionEntry_ReadWriteComputerObjectProperties_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADObjectPermissionEntry 'ADObjectPermissionEntry'
        {
            Ensure                             = 'Present'
            Path                               = 'OU=ContosoComputers,DC=contoso,DC=com'
            IdentityReference                  = 'CONTOSO\ComputerAdminGroup'
            ActiveDirectoryRights              = 'ReadProperty', 'WriteProperty'
            AccessControlType                  = 'Allow'
            ObjectType                         = '00000000-0000-0000-0000-000000000000'
            ActiveDirectorySecurityInheritance = 'Descendents'
            InheritedObjectType                = 'bf967a86-0de6-11d0-a285-00aa003049e2' # Computer objects
        }
    }
}
