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
                NodeName                        = 'localhost'
                Name                            = 'Administrators'
                DisplayName                     = 'Administrators'
                Description                     = 'Administrators Password Policy'
                ComplexityEnabled               = $true
                LockoutDuration                 = '00:30:00'
                LockoutObservationWindow        = '00:30:00'
                LockoutThreshold                = 3
                MinPasswordAge                  = '1.00:00:00'
                MaxPasswordAge                  = '42.00:00:00'
                MinPasswordLength               = 7
                PasswordHistoryCount            = 12
                ReversibleEncryptionEnabled     = $false
                ProtectedFromAccidentalDeletion = $true
                Precedence                      = 10
            }
        )
    }
}

<#
    .SYNOPSIS
        Create a fine grained password policy for the Administrators group, but don't assign subjects
#>
Configuration MSFT_ADFineGrainedPasswordPolicy_CreateADFineGrainedPasswordPolicy_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADFineGrainedPasswordPolicy 'Integration_Test'
        {
            Name                            = $ConfigurationData.AllNodes.Name
            DisplayName                     = $ConfigurationData.AllNodes.DisplayName
            Description                     = $ConfigurationData.AllNodes.Description
            Ensure                          = 'Present'
            ComplexityEnabled               = $ConfigurationData.AllNodes.ComplexityEnabled
            LockoutDuration                 = $ConfigurationData.AllNodes.LockoutDuration
            LockoutObservationWindow        = $ConfigurationData.AllNodes.LockoutObservationWindow
            LockoutThreshold                = $ConfigurationData.AllNodes.LockoutThreshold
            MinPasswordAge                  = $ConfigurationData.AllNodes.MinPasswordAge
            MaxPasswordAge                  = $ConfigurationData.AllNodes.MaxPasswordAge
            MinPasswordLength               = $ConfigurationData.AllNodes.MinPasswordLength
            PasswordHistoryCount            = $ConfigurationData.AllNodes.PasswordHistoryCount
            ReversibleEncryptionEnabled     = $ConfigurationData.AllNodes.ReversibleEncryptionEnabled
            ProtectedFromAccidentalDeletion = $ConfigurationData.AllNodes.ProtectedFromAccidentalDeletion
            Precedence                      = $ConfigurationData.AllNodes.Precedence
        }
    }
}

<#
    .SYNOPSIS
        Remove a fine grained password policy for the Administrators group
#>
Configuration MSFT_ADFineGrainedPasswordPolicy_RemoveADFineGrainedPasswordPolicy_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADFineGrainedPasswordPolicy 'Integration_Test'
        {
            Name                            = $ConfigurationData.AllNodes.Name
            Ensure                          = 'Absent'
            Precedence                      = $ConfigurationData.AllNodes.Precedence
            ProtectedFromAccidentalDeletion = $false
        }
    }
}
