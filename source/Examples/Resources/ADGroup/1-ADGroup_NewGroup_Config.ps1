<#PSScriptInfo
.VERSION 1.0.1
.GUID f24bbdb8-4f0d-47a4-9281-d40092322cd5
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
        This configuration will create a new domain-local group
#>
Configuration ADGroup_NewGroup_Config
{
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $GroupName,

        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [System.String]
        $Scope = 'Global',

        [ValidateSet('Security', 'Distribution')]
        [System.String]
        $Category = 'Security',

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description
    )

    Import-DscResource -Module ActiveDirectoryDsc

    Node localhost
    {
        ADGroup 'ExampleGroup'
        {
            GroupName   = $GroupName
            GroupScope  = $Scope
            Category    = $Category
            Description = $Description
            Ensure      = 'Present'
        }
    }
}
