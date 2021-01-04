<#PSScriptInfo
.VERSION 1.0.1
.GUID 2caf2b93-d87e-426d-8c44-9f1d0452be10
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
        This configuration will create a new one way inbound trust between two
        domains.
#>
Configuration ADDomainTrust_ExternalInboundTrust_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $SourceDomain,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TargetDomain,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $TargetDomainAdminCred
    )

    Import-DscResource -module ActiveDirectoryDsc

    node localhost
    {
        ADDomainTrust 'Trust'
        {
            Ensure           = 'Present'
            SourceDomainName = $SourceDomain
            TargetDomainName = $TargetDomain
            TargetCredential = $TargetDomainAdminCred
            TrustDirection   = 'Inbound'
            TrustType        = 'External'
        }
    }
}
