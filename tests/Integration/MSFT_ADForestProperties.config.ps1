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
    $currentDomainController = Get-ADDomainController
    $forestName = $currentDomainController.Forest

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
                ForestName      = $forestName
                Tests           = [Ordered]@{
                    SetPropertyValues = @{
                        TombstoneLifetime          = 200
                        ServicePrincipalNameSuffix = 'fabrikam.com'
                        UserPrincipalNameSuffix    = 'fabrikam.com'
                    }
                    SetAddProperties = @{
                        ServicePrincipalNameSuffixToAdd = 'test.com'
                        UserPrincipalNameSuffixToAdd    = 'test.com'
                    }
                    SetRemoveProperties = @{
                        ServicePrincipalNameSuffixToRemove = 'test.com'
                        UserPrincipalNameSuffixToRemove    = 'test.com'
                    }
                }
                Default         = @{
                    TombstoneLifetime          = 180
                    ServicePrincipalNameSuffix = ''
                    UserPrincipalNameSuffix    = ''
                }
            }
        )
    }
}

<#
    .SYNOPSIS
        Sets the supported property values.
#>
Configuration MSFT_ADForestProperties_SetPropertyValues_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'SetPropertyValues'

    node $AllNodes.NodeName
    {
        ADForestProperties 'Integration_Test'
        {
            ForestName                 = $Node.ForestName
            TombstoneLifetime          = $Node.Tests.$testName.TombstoneLifetime
            ServicePrincipalNameSuffix = $Node.Tests.$testName.ServicePrincipalNameSuffix
            UserPrincipalNameSuffix    = $Node.Tests.$testName.UserPrincipalNameSuffix
        }
    }
}

<#
    .SYNOPSIS
        Sets the SPN/UPN suffix properties using the 'add' parameters.
#>
Configuration MSFT_ADForestProperties_SetAddProperties_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'SetAddProperties'

    node $AllNodes.NodeName
    {
        ADForestProperties 'Integration_Test'
        {
            ForestName                      = $Node.ForestName
            ServicePrincipalNameSuffixToAdd = $Node.Tests.$testName.ServicePrincipalNameSuffixToAdd
            UserPrincipalNameSuffixToAdd    = $Node.Tests.$testName.UserPrincipalNameSuffixToAdd
        }
    }
}

<#
    .SYNOPSIS
        Sets the SPN/UPN suffix properties using the 'remove' parameters.
#>
Configuration MSFT_ADForestProperties_SetRemoveProperties_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'SetRemoveProperties'

    node $AllNodes.NodeName
    {
        ADForestProperties 'Integration_Test'
        {
            ForestName                         = $Node.ForestName
            ServicePrincipalNameSuffixToRemove = $Node.Tests.$testName.ServicePrincipalNameSuffixToRemove
            UserPrincipalNameSuffixToRemove    = $Node.Tests.$testName.UserPrincipalNameSuffixToRemove
        }
    }
}

<#
    .SYNOPSIS
        Restore domain controller properties to the default values.
#>
Configuration MSFT_ADForestProperties_RestoreDefaultValues_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADForestProperties 'Integration_Test'
        {
            ForestName                 = $Node.ForestName
            TombstoneLifetime          = $Node.Default.TombstoneLifetime
            ServicePrincipalNameSuffix = $Node.Default.ServicePrincipalNameSuffix
            UserPrincipalNameSuffix    = $Node.Default.UserPrincipalNameSuffix
        }
    }
}
