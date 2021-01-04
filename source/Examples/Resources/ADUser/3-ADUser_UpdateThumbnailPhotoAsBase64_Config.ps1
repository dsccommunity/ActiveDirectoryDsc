<#PSScriptInfo
.VERSION 1.0.1
.GUID 697115a8-3004-4eca-b400-f861c6914279
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
        This configuration will update a user with a thumbnail photo using
        a jpeg image encoded as a Base64 string.
#>
Configuration ADUser_UpdateThumbnailPhotoAsBase64_Config
{
    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADUser 'Contoso\ExampleUser'
        {
            UserName       = 'ExampleUser'
            DomainName     = 'contoso.com'
            ThumbnailPhoto = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QB .... STRING TRUNCATED FOR LENGTH'
        }
    }
}
