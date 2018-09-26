$script:DSCModuleName = 'xActiveDirectory'
$script:DSCResourceName = 'MSFT_xADForestProperties'

$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Unit

try
{
    InModuleScope $script:DSCResourceName {

        $forestName = 'contoso.com'
        $testCredential = [System.Management.Automation.PSCredential]::Empty

        $replaceParameters = @{
            ForestName                 = $forestName
            ServicePrincipalNameSuffix = 'test.net'
            UserPrincipalNameSuffix    = 'cloudapp.net', 'fabrikam.com'
            Credential                 = $testCredential
        }

        $includeRemoveParameters = @{
            ForestName                          = $forestName
            ServicePrincipalNameSuffixToRemove  = 'test.com'
            ServicePrincipalNameSuffixToInclude = 'test.net'
            UserPrincipalNameSuffixToRemove     = 'pester.net'
            UserPrincipalNameSuffixToInclude    = 'cloudapp.net', 'fabrikam.com'
            Credential                          = $testCredential
        }

        $removeParameters = $includeRemoveParameters.clone()
        $removeParameters['ServicePrincipalNameSuffixToInclude'] = $null
        $removeParameters['UserPrincipalNameSuffixToInclude'] = $null

        $invalidParameters = $includeRemoveParameters.clone()
        $invalidParameters['UserPrincipalNameSuffix'] = 'test.com'

        $mockADForestDesiredState = @{
            Name        = $forestName
            SpnSuffixes = @('test.net')
            UpnSuffixes = @('cloudapp.net', 'fabrikam.com')
        }

        $mockADForestNonDesiredState = @{
            Name        = $forestName
            SpnSuffixes = @('test3.value')
            UpnSuffixes = @('test1.value', 'test2.value')
        }

        Mock -CommandName Assert-Module
        Mock -CommandName Import-Module

        Describe 'MSFT_xADForestProperties\Get-TargetResource' {
            Mock -CommandName Get-ADForest -MockWith { $mockADForestDesiredState }

            Context 'When used with include/remove parameters' {

                It 'Should return expected properties' {
                    $targetResource = Get-TargetResource @includeRemoveParameters

                    $targetResource.ServicePrincipalNameSuffix          | Should -Be $mockADForestDesiredState.SpnSuffixes
                    $targetResource.ServicePrincipalNameSuffixToInclude | Should -Be $includeRemoveParameters.ServicePrincipalNameSuffixToInclude
                    $targetResource.ServicePrincipalNameSuffixToRemove  | Should -Be $includeRemoveParameters.ServicePrincipalNameSuffixToRemove
                    $targetResource.UserPrincipalNameSuffix             | Should -Be $mockADForestDesiredState.UpnSuffixes
                    $targetResource.UserPrincipalNameSuffixToInclude    | Should -Be $includeRemoveParameters.UserPrincipalNameSuffixToInclude
                    $targetResource.UserPrincipalNameSuffixToRemove     | Should -Be $includeRemoveParameters.UserPrincipalNameSuffixToRemove
                    $targetResource.Credential                          | Should -BeNullOrEmpty
                    $targetResource.ForestName                          | Should -Be $mockADForestDesiredState.Name
                }
            }

            Context 'When used with replace parameters' {

                It 'Should return expected properties' {
                    $targetResource = Get-TargetResource @replaceParameters

                    $targetResource.ServicePrincipalNameSuffix          | Should -Be $mockADForestDesiredState.SpnSuffixes
                    $targetResource.ServicePrincipalNameSuffixToInclude | Should -BeNullOrEmpty
                    $targetResource.ServicePrincipalNameSuffixToRemove  | Should -BeNullOrEmpty
                    $targetResource.UserPrincipalNameSuffix             | Should -Be $mockADForestDesiredState.UpnSuffixes
                    $targetResource.UserPrincipalNameSuffixToInclude    | Should -BeNullOrEmpty
                    $targetResource.UserPrincipalNameSuffixToRemove     | Should -BeNullOrEmpty
                    $targetResource.Credential                          | Should -BeNullOrEmpty
                    $targetResource.ForestName                          | Should -Be $mockADForestDesiredState.Name
                }
            }
        }

        Describe 'MSFT_xADForestProperties\Test-TargetResource' {
            Context 'When target resource in desired state' {
                Mock -CommandName Get-ADForest -MockWith { $mockADForestDesiredState }

                It 'Should return $true when using include/remove parameters' {
                    Test-TargetResource @includeRemoveParameters | Should -Be $true
                }

                It 'Should return $true when using replace parameters' {
                    Test-TargetResource @replaceParameters | Should -Be $true
                }
            }

            Context 'When using Include and Remove parameters and target not in desired state' {
                Mock -CommandName Get-ADForest -MockWith { $mockADForestNonDesiredState }

                It 'Should return $false when using include/remove parameters' {
                    Test-TargetResource @includeRemoveParameters | Should -Be $false
                }

                It 'Should return $false when using replace parameters' {
                    Test-TargetResource @replaceParameters | Should -Be $false
                }
            }

            Context 'When using invalid parameter combination' {
                Mock -CommandName Get-ADForest

                It 'Should throw when invalid parameter set is used' {
                    { Test-TargetResource @invalidParameters } | Should -Throw
                }
            }
        }

        Describe 'MSFT_xADForestProperties\Set-TargetResource' {
            Context 'When using replace parameters' {
                Mock -CommandName Set-ADForest -ParameterFilter {
                    ($SpnSuffixes.Replace -join ',') -eq ($replaceParameters.ServicePrincipalNameSuffix -join ',') -and
                    ($UpnSuffixes.Replace -join ',') -eq ($replaceParameters.UserPrincipalNameSuffix -join ',')
                }

                It 'Should call Set-ADForest with the replace action'  {
                    Set-TargetResource @replaceParameters

                    Assert-MockCalled Set-ADForest -Scope It -Times 1 -Exactly
                }
            }

            Context 'When using include/remove parameters' {
                Mock -CommandName Set-ADForest -ParameterFilter {
                    ($SpnSuffixes.Add -join ',') -eq ($includeRemoveParameters.ServicePrincipalNameSuffixToInclude -join ',') -and
                    ($SpnSuffixes.Remove -join ',') -eq ($includeRemoveParameters.ServicePrincipalNameSuffixToRemove -join ',') -and
                    ($UpnSuffixes.Add -join ',') -eq ($includeRemoveParameters.UserPrincipalNameSuffixToInclude -join ',') -and
                    ($UpnSuffixes.Remove -join ',') -eq ($includeRemoveParameters.UserPrincipalNameSuffixToRemove -join ',')
                }

                It 'Should call Set-ADForest with the add and remove actions' {
                    Set-TargetResource @includeRemoveParameters

                    Assert-MockCalled Set-ADForest -Scope It -Times 1 -Exactly
                }
            }

            Context 'When using only remove parameters' {
                Mock -CommandName Set-ADForest -ParameterFilter {
                    ($SpnSuffixes.Remove -join ',') -eq ($removeParameters.ServicePrincipalNameSuffixToRemove -join ',') -and
                    ($UpnSuffixes.Remove -join ',') -eq ($removeParameters.UserPrincipalNameSuffixToRemove -join ',')
                }

                It 'Should call Set-ADForest with the remove action' {
                    Set-TargetResource @removeParameters

                    Assert-MockCalled Set-ADForest -Scope It -Times 1 -Exactly
                }
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
