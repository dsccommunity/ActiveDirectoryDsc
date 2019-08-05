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
        $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'DummyUser',
            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
        )

        $featureParameters = @{
            FeatureName                       = 'Recycle Bin Feature'
            ForestFqdn                        = $forestName
            EnterpriseAdministratorCredential = $testCredential
        }

        $testFeatureProperties = $featureParameters.Clone()
        $testFeatureProperties.FeatureName = "Test Feature"

        $badCredentialsProperties = $featureParameters.Clone()
        $badCredentialsProperties.EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'Invalid',
            (ConvertTo-SecureString -String 'Invalid' -AsPlainText -Force)
        )

        $mockADForestDesiredState = @{
            Name               = $forestName
            ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
            RootDomain         = $forestName
            DomainNamingMaster = "DC01"
        }

        $mockADForestNonDesiredState = $mockADForestDesiredState.Clone()
        $mockADForestNonDesiredState.ForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]0 # Windows2000Forest

        $mockADDomainDesiredState = @{
            Name        = $forestName
            DomainMode  = [Microsoft.ActiveDirectory.Management.ADDomainMode]7  # Windows2016Domain
        }

        $mockADDomainNonDesiredState = $mockADDomainDesiredState.Clone()
        $mockADDomainNonDesiredState.DomainMode  = [Microsoft.ActiveDirectory.Management.ADDomainMode]0  # Windows2000Domain

        $mockADRecycleBinDisabled = @{
            EnabledScopes      = @()
            Name               = "Recycle Bin Feature"
            RequiredDomainMode = $null
            RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]4 # Windows2008R2
        }

        $mockADRecycleBinEnabled= $mockADRecycleBinDisabled.Clone()
        $mockADRecycleBinEnabled.EnabledScopes = @(
                "CN=Partitions,CN=Configuration,DC=contoso,DC=com",
                "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com"
            )

        $mockTestFeatureDisabled = @{
            EnabledScopes      = @()
            Name               = "Test Feature"
            RequiredDomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]7 # Windows2016Domain
            RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
        }

        Describe 'MSFT_ADOptionalFeature\Get-TargetResource' {
            Context 'When feature is enabled' {
                Mock -CommandName Get-ADOptionalFeature -MockWith { $mockADRecycleBinEnabled }

                It 'Should return expected properties' {
                    $targetResource = Get-TargetResource @featureParameters

                    $targetResource.FeatureName                                | Should -Be $featureParameters.FeatureName
                    $targetResource.ForestFqdn                                 | Should -Be $featureParameters.ForestFqdn
                    $targetResource.Enabled                                    | Should -BeTrue
                    $targetResource.EnterpriseAdministratorCredential.Username | Should -Be $featureParameters.EnterpriseAdministratorCredential.Username
                    $targetResource.EnterpriseAdministratorCredential.Password | Should -BeNullOrEmpty
                }
            }

            Context 'When feature isnt enabled' {
                Mock -CommandName Get-ADOptionalFeature -MockWith { $mockADRecycleBinDisabled }

                It 'Should return expected properties' {
                    $targetResource = Get-TargetResource @featureParameters

                    $targetResource.FeatureName                                | Should -Be $featureParameters.FeatureName
                    $targetResource.ForestFqdn                                 | Should -Be $featureParameters.ForestFqdn
                    $targetResource.Enabled                                    | Should -BeFalse
                    $targetResource.EnterpriseAdministratorCredential.Username | Should -Be $featureParameters.EnterpriseAdministratorCredential.Username
                    $targetResource.EnterpriseAdministratorCredential.Password | Should -BeNullOrEmpty
                }
            }

            context 'When domain is not available' {
                It 'Should throw "Credential Error" when domain is available but authentication fails' {
                    Mock -CommandName Get-ADOptionalFeature -ParameterFilter { $Credential.Username -eq $badCredentialsProperties.EnterpriseAdministratorCredential.Username } -MockWith {
                        throw New-Object System.Security.Authentication.AuthenticationException
                    }

                    { Get-TargetResource @badCredentialsProperties } | Should -Throw $script:localizedData.CredentialError
                }

                It 'Should throw "Cannot contact forest" when forest cannot be located' {
                    Mock -CommandName Get-ADOptionalFeature -MockWith {
                        throw New-Object Microsoft.ActiveDirectory.Management.ADServerDownException
                    }

                    { Get-TargetResource @featureParameters } | Should -Throw ($script:localizedData.ForestNotFound -f $featureParameters.ForestFQDN)
                }
            }
        }

        Describe 'MSFT_ADOptionalFeature\Test-TargetResource' {
            Context 'When target resource in desired state' {
                Mock -CommandName Get-ADOptionalFeature -MockWith { $mockADRecycleBinEnabled }

                It 'Should return $true' {
                    Test-TargetResource @featureParameters | Should -Be $true
                }
            }

            Context 'When target not in desired state' {
                Mock -CommandName Get-ADOptionalFeature -MockWith { $mockADRecycleBinDisabled }

                It 'Should return $false' {
                    Test-TargetResource @featureParameters | Should -Be $false
                }
            }
        }

        Describe 'MSFT_ADOptionalFeature\Set-TargetResource' {
            Mock -CommandName Get-ADForest -MockWith { $mockADForestDesiredState }
            Mock -CommandName Get-ADDomain -MockWith { $mockADDomainDesiredState }
            Mock -CommandName Get-ADOptionalFeature -MockWith { $mockADRecycleBinDisabled }

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

            Context 'When forest requirements are not met' {
                Mock -CommandName Get-ADForest -MockWith { $mockADForestNonDesiredState }
                Mock -CommandName Enable-ADOptionalFeature

                It 'Should throw exception that forest functional level is too low' {
                    { Set-TargetResource @featureParameters } | Should -Throw
                }
            }

            Context 'When domain requirements are not met' {
                Mock -CommandName Get-ADOptionalFeature -MockWith { $mockTestFeatureDisabled }
                Mock -CommandName Get-ADForest -MockWith { $mockADForesDesiredState }
                Mock -CommandName Get-ADDomain -MockWith { $mockADDomainNonDesiredState }
                Mock -CommandName Enable-ADOptionalFeature

                It 'Should throw exception that domain functional level is too low' {
                    { Set-TargetResource @testFeatureProperties } | Should -Throw
                }
            }

            context 'When domain is not available' {
                It 'Should throw "Credential Error" when forest is available but authentication fails' {
                    Mock -CommandName Get-ADForest -ParameterFilter { $Credential.Username -eq $badCredentialsProperties.EnterpriseAdministratorCredential.Username } -MockWith {
                        throw New-Object System.Security.Authentication.AuthenticationException
                    }

                    { Set-TargetResource @badCredentialsProperties } | Should -Throw $script:localizedData.CredentialError
                }

                It 'Should throw "Cannot contact forest" when forest cannot be located' {
                    Mock -CommandName Get-ADForest -MockWith {
                        throw New-Object Microsoft.ActiveDirectory.Management.ADServerDownException
                    }

                    { Set-TargetResource @featureParameters } | Should -Throw ($script:localizedData.ForestNotFound -f $featureParameters.ForestFQDN)
                }

                It 'Should throw "Credential Error" when domain is available but authentication fails' {
                    Mock -CommandName Get-ADDomain -ParameterFilter { $Credential.Username -eq $badCredentialsProperties.EnterpriseAdministratorCredential.Username } -MockWith {
                        throw New-Object System.Security.Authentication.AuthenticationException
                    }

                    { Set-TargetResource @badCredentialsProperties } | Should -Throw $script:localizedData.CredentialError
                }

                It 'Should throw "Cannot contact forest" when domain cannot be located' {
                    Mock -CommandName Get-ADDomain -MockWith {
                        throw New-Object Microsoft.ActiveDirectory.Management.ADServerDownException
                    }

                    { Set-TargetResource @featureParameters } | Should -Throw ($script:localizedData.ForestNotFound -f $featureParameters.ForestFQDN)
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
