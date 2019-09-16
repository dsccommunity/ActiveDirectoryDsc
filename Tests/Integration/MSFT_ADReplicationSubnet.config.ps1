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
    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
            }
        )
    }
}

<#
    .SYNOPSIS
        Creates a site subnet.
#>
Configuration MSFT_ADReplicationSubnet_CreateSubnet_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADReplicationSubnet 'LondonSubnet'
        {
            Ensure   = 'Present'
            Name     = '10.0.0.0/24'
            Site     = 'London'
            Location = 'Datacenter 3'
        }
    }
}

<#
    .SYNOPSIS
        Changes a site subnet Site to Default.
#>
Configuration MSFT_ADReplicationSubnet_ChangeSubnetSite_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADReplicationSubnet 'LondonSubnet'
        {
            Ensure   = 'Present'
            Name     = '10.0.0.0/24'
            Site     = 'Default-First-Site-Name'
            Location = 'Datacenter 3'
        }
    }
}

<#
    .SYNOPSIS
        Changes a Replication Subnet Location.
#>
Configuration MSFT_ADReplicationSubnet_ChangeSubnetLocation_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADReplicationSubnet 'LondonSubnet'
        {
            Ensure   = 'Present'
            Name     = '10.0.0.0/24'
            Site     = 'Default-First-Site-Name'
            Location = 'Office 12'
        }
    }
}

<#
    .SYNOPSIS
        Removes a site subnet.
#>
Configuration MSFT_ADReplicationSubnet_RemoveSubnet_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADReplicationSubnet 'LondonSubnet'
        {
            Ensure   = 'Absent'
            Name     = '10.0.0.0/24'
            Site     = 'Default-First-Site-Name'
            Location = 'Datacenter 3'
        }
    }
}
