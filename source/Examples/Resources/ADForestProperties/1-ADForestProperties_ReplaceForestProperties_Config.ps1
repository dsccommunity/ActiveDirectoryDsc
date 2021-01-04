<#PSScriptInfo
.VERSION 1.0.1
.GUID 4ac2de06-ee10-4f15-9ed8-a87d21b48766
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
        This configuration will manage the Service and User Principal name suffixes
        in the forest by replacing any existing suffixes with the ones specified
        in the configuration.
#>
Configuration ADForestProperties_ReplaceForestProperties_Config
{
    Import-DscResource -ModuleName ActiveDirectoryDsc

    node 'localhost'
    {
        ADForestProperties 'contoso.com'
        {
            ForestName                 = 'contoso.com'
            UserPrincipalNameSuffix    = 'fabrikam.com', 'industry.com'
            ServicePrincipalNameSuffix = 'corporate.com'
        }
    }
}
