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
                EffectiveTime   = (Get-Date -year 1999 -month 1 -day 1 -hour 0 -Minute 0 -Second 0).ToString()
            }
        )
    }
}

<#
    .SYNOPSIS
        Create a KDS root key in the past. This will allow the key to be used right away
#>
Configuration MSFT_ADKDSKey_CreateKDSRootKeyInPast_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADKDSKey 'Integration_Test'
        {
            Ensure                   = 'Present'
            EffectiveTime            = $ConfigurationData.AllNodes.EffectiveTime
            AllowUnsafeEffectiveTime = $true
        }
    }
}
