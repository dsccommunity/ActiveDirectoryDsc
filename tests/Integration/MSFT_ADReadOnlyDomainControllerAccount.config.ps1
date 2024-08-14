#region HEADER
# Integration Test Config Template Version: 1.2.0
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    <#
        Allows reading the configuration data from a JSON file, for real testing
        scenarios outside of the CI.
    #>
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $currentDomain = Get-ADDomain
    $dnsRoot = $currentDomain.DNSRoot
    $currentSite = Get-ADReplicationSite
    $siteName = $currentSite.Name

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName                    = 'localhost'
                DomainControllerAccountName = 'DSCINTTESTRODC1'
                DomainName                  = $dnsRoot
                SiteName                    = $siteName
            }
        )
    }
}

<#
    .SYNOPSIS
        Pre-create a read only domain controller account.
#>
Configuration MSFT_ADKDSKey_CreateReadOnlyDomainControllerAccount
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADReadOnlyDomainControllerAccount 'Integration_Test'
        {
            DomainControllerAccountName = $Node.DomainControllerAccountName
            DomainName                  = $Node.DomainName
            SiteName                    = $Node.SiteName
        }
    }
}
