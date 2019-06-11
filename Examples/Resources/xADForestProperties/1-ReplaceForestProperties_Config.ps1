<#PSScriptInfo
.VERSION 1.0
.GUID 4ac2de06-ee10-4f15-9ed8-a87d21b48766
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT (c) Microsoft Corporation. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xActiveDirectory/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xActiveDirectory
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.PRIVATEDATA
#>

#Requires -module xActiveDirectory

<#
    .DESCRIPTION
        This configuation manages the Service and User Principal name suffixes
        in the forest by replacing any existing suffixes with the ones specified
        in the configuration.
#>

Configuration ReplaceForestProperties_Config
{
    Param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $TargetName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ForestName,

        [parameter(Mandatory = $true)]
        [String[]]
        $UserPrincipalNameSuffix,

        [parameter(Mandatory = $true)]
        [String[]]
        $ServicePrincipalNameSuffix
    )

    Import-DscResource -ModuleName xActiveDirectory

    node $TargetName
    {
        xADForestProperties $ForestName
        {
            ForestName                 = $ForestName
            UserPrincipalNameSuffix    = $UserPrincipalNameSuffix
            ServicePrincipalNameSuffix = $ServicePrincipalNameSuffix
        }
    }
}

$parameters = @{
    TargetName                 = 'dc.contoso.com'
    ForestName                 = 'contoso.com'
    UserPrincipalNameSuffix    = 'fabrikam.com', 'industry.com'
    ServicePrincipalNameSuffix = 'corporate.com'
}
