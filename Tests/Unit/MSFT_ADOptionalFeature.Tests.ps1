$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADOptionalFeature'

#region HEADER

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit

#endregion HEADER

function Invoke-TestSetup
{
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope $script:dscResourceName {
        # If one type does not exist, it's assumed the other ones does not exist either.
        if (-not ('Microsoft.ActiveDirectory.Management.ADComputer' -as [Type]))
        {
            $adModuleStub = (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\Microsoft.ActiveDirectory.Management.cs')
            Add-Type -Path $adModuleStub
        }

        $forestName = 'contoso.com'
        $testCredential = [System.Management.Automation.PSCredential]::Empty

        $featureParameters = @{
            FeatureName                       = 'Recycle Bin Feature'
            ForestFqdn                        = $forestName
            EnterpriseAdministratorCredential = $testCredential
        }

        $mockADForestDesiredState = @{
            Name               = $forestName
            ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest
            RootDomain         = $forestName
            DomainNamingMaster = "DC01"
        }

        $mockADForestNonDesiredState = @{
            Name               = $forestName
            ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2000Forest
            RootDomain         = $forestName
            DomainNamingMaster = "DC01"
        }

        $mockADDomainDesiredState = @{
            Name        = $forestName
            DomainMode  = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain
        }

        $mockADDomainNonDesiredState = @{
            Name        = $forestName
            DomainMode  = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2000Domain -as [int]
        }

        $mockADRecycleBinEnabled = @{
            EnabledScopes      = @(
                "CN=Partitions,CN=Configuration,DC=contoso,DC=com",
                "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com"
            )
            Name               = "Recycle Bin Feature"
            RequiredDomainMode = $null
            RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2008R2Forest
        }

        $mockADRecycleBinDisabled = @{
            EnabledScopes      = @()
            Name               = "Recycle Bin Feature"
            RequiredDomainMode = $null
            RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2008R2Forest
        }

        Describe 'MSFT_ADOptionalFeature\Get-TargetResource' {
            Context 'When feature is enabled' {
                mock Get-ADOptionalFeature { $mockADRecycleBinEnabled }

                It 'Should return expected properties' {
                    $targetResource = Get-TargetResource @featureParameters

                    $targetResource.FeatureName                       | Should -Be $featureParameters.FeatureName
                    $targetResource.ForestFqdn                        | Should -Be $featureParameters.ForestFqdn
                    $targetResource.Enabled                           | Should -BeTrue
                    $targetResource.EnterpriseAdministratorCredential | Should -BeNullOrEmpty
                }
            }

            Context 'When feature isnt enabled' {
                mock Get-ADOptionalFeature { $mockADRecycleBinDisabled }

                It 'Should return expected properties' {
                    $targetResource = Get-TargetResource @featureParameters

                    $targetResource.FeatureName                       | Should -Be $featureParameters.FeatureName
                    $targetResource.ForestFqdn                        | Should -Be $featureParameters.ForestFqdn
                    $targetResource.Enabled                           | Should -BeFalse
                    $targetResource.EnterpriseAdministratorCredential | Should -BeNullOrEmpty
                }
            }
        }

        Describe 'MSFT_ADOptionalFeature\Test-TargetResource' {
            Context 'When target resource in desired state' {
                mock Get-ADOptionalFeature { $mockADRecycleBinEnabled }

                It 'Should return $true' {
                    Test-TargetResource @featureParameters | Should -Be $true
                }
            }

            Context 'When target not in desired state' {
                mock Get-ADOptionalFeature { $mockADRecycleBinDisabled }

                It 'Should return $false' {
                    Test-TargetResource @featureParameters | Should -Be $false
                }
            }
        }

        Describe 'MSFT_ADOptionalFeature\Set-TargetResource' {
            Mock -CommandName Get-ADForest -MockWith { $mockADForestDesiredState }
            Mock -CommandName Get-ADDomain -MockWith { $mockADDomainDesiredState }
            Mock Get-ADOptionalFeature { $mockADRecycleBinDisabled }

            Context 'When domain and forest requirements are met' {
                Mock -CommandName Enable-ADOptionalFeature

                It 'Should call Enable-ADOptionalFeature with correct properties' {
                    Set-TargetResource @featureParameters

                    Assert-MockCalled Enable-ADOptionalFeature -Scope It -Times 1 -Exactly -ParameterFilter {
                        $Identity.ToString() -eq $featureParameters.FeatureName -and
                        $Scope.ToString() -eq "ForestOrConfigurationSet" -and
                        $Server -eq $mockADForestDesiredState.DomainNamingMaster
                    }
                }
            }

            Context 'When forest requirements are met' {
                Mock -CommandName Get-ADForest -MockWith { $mockADForestNonDesiredState }
                Mock -CommandName Enable-ADOptionalFeature

                It 'Should throw exception that forest functional level is too low' {
                    { Set-TargetResource @featureParameters } | Should -Throw
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
