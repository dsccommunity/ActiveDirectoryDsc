<#PSScriptInfo
.VERSION 1.0.1
.GUID b293f599-2660-424d-8200-61d399e44257
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
        This configuration will create a user with a managed password.
        This might be used to manage the lifecycle of a service account.
#>
Configuration ADUser_CreateUserAndManagePassword_Config
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
            Ensure     = 'Present'
            UserName   = 'ExampleUser'
            Password   = $Password
            DomainName = 'contoso.com'
            Path       = 'CN=Users,DC=contoso,DC=com'
        }
    }
}
