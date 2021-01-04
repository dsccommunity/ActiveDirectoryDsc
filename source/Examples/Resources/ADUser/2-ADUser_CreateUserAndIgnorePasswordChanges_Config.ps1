<#PSScriptInfo
.VERSION 1.0.1
.GUID 3bf5100b-238e-435a-8a98-67d756c5cdeb
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
        This configuration will create a user with a password and then ignore
        when the password has changed. This might be used with a traditional
        user account where a managed password is not desired.
#>
Configuration ADUser_CreateUserAndIgnorePasswordChanges_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Password
    )

    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADUser 'Contoso\ExampleUser'
        {
            Ensure              = 'Present'
            UserName            = 'ExampleUser'
            Password            = $Password
            PasswordNeverResets = $true
            DomainName          = 'contoso.com'
            Path                = 'CN=Users,DC=contoso,DC=com'
        }
    }
}
