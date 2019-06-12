<#PSScriptInfo
.VERSION 1.0
.GUID 2caf2b93-d87e-426d-8c44-9f1d0452be10
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
        This configuration will create a new one way inbound trust between two
        domains.
#>

Configuration NewOneWayTrust_Config
{
    param
    (
        [Parameter(Mandatory)]
        [String]$SourceDomain,
        [Parameter(Mandatory)]
        [String]$TargetDomain,
        [Parameter(Mandatory)]
        [PSCredential]$TargetDomainAdminCred
    )

    Import-DscResource -module xActiveDirectory
    Node $AllNodes.NodeName
    {
        xADDomainTrust trust
        {
            Ensure                              = 'Present'
            SourceDomainName                    = $SourceDomain
            TargetDomainName                    = $TargetDomain
            TargetDomainAdministratorCredential = $TargetDomainAdminCred
            TrustDirection                      = 'Inbound'
            TrustType                           = 'External'
        }
    }
}
