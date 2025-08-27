# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies have been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies have not been resolved, this will throw an error.
            Import-Module -Name 'DscResource.Test' -Force -ErrorAction 'Stop'
        }
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -ResolveDependency -Tasks build" first.'
    }
}

BeforeAll {
    $script:dscModuleName = 'ActiveDirectoryDsc'
    $script:dscResourceName = 'MSFT_ADForestFunctionalLevel'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    # Load stub cmdlets and classes.
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1')

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscResourceName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    Restore-TestEnvironment -TestEnvironment $script:testEnvironment

    # Unload stub module
    Remove-Module -Name ActiveDirectory_2019 -Force

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_ADForestFunctionalLevel\Get-TargetResource' -Tag 'Get' {
    Context 'When the current property values are returned' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                return @{
                    ForestMode = 'Windows2012R2Forest'
                }
            }
        }

        It 'Should return the the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2016Forest'
                }

                $result = Get-TargetResource @mockParameters

                $result.ForestIdentity | Should -Be $mockParameters.ForestIdentity
                $result.ForestMode | Should -Be 'Windows2012R2Forest'
            }

            Should -Invoke -CommandName Get-ADForest -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADForestFunctionalLevel\Test-TargetResource' -Tag 'Test' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    @{
                        ParameterName  = 'ForestMode'
                        InDesiredState = $true
                    }
                )
            }
        }

        It 'Should return $true' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2016Forest'
                }

                Test-TargetResource @mockParameters | Should -BeTrue
            }

            Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    @{
                        ParameterName  = 'ForestMode'
                        InDesiredState = $false
                    }
                )
            }
        }

        It 'Should return $false' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2012R2Forest'
                }

                Test-TargetResource @mockParameters | Should -BeFalse
            }

            Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADForestFunctionalLevel\Compare-TargetResourceState' -Tag 'Compare' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2016Forest'
                }
            }
        }

        It 'Should return $true' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2016Forest'
                }

                $compareResult = Compare-TargetResourceState @mockParameters
                $compareResult | Should -HaveCount 1

                $comparedReturnValue = $compareResult.Where( { $_.ParameterName -eq 'ForestMode' })
                $comparedReturnValue | Should -Not -BeNullOrEmpty
                $comparedReturnValue.Expected | Should -Be $mockParameters.ForestMode
                $comparedReturnValue.Actual | Should -Be $mockParameters.ForestMode
                $comparedReturnValue.InDesiredState | Should -BeTrue
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property ForestMode is not in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        ForestIdentity = 'contoso.com'
                        ForestMode     = 'Windows2016Forest'
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ForestIdentity = 'contoso.com'
                        ForestMode     = 'Windows2012R2Forest'
                    }

                    $compareResult = Compare-TargetResourceState @mockParameters
                    $compareResult | Should -HaveCount 1

                    $comparedReturnValue = $compareResult.Where( { $_.ParameterName -eq 'ForestMode' })
                    $comparedReturnValue | Should -Not -BeNullOrEmpty
                    $comparedReturnValue.Expected | Should -Be $mockParameters.ForestMode
                    $comparedReturnValue.Actual | Should -Be 'Windows2016Forest'
                    $comparedReturnValue.InDesiredState | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADForestFunctionalLevel\Set-TargetResource' -Tag 'Set' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Set-ADForestMode
            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    @{
                        ParameterName  = 'ForestMode'
                        Actual         = 'Windows2016Forest'
                        Expected       = 'Windows2016Forest'
                        InDesiredState = $true
                    }
                )
            }
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2016Forest'
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADForestMode -Exactly -Times 0 -Scope It
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Set-ADForestMode
            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    @{
                        ParameterName  = 'ForestMode'
                        Actual         = 'Windows2016Forest'
                        Expected       = 'Windows2012R2Forest'
                        InDesiredState = $false
                    }
                )
            }
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestIdentity = 'contoso.com'
                    ForestMode     = 'Windows2012R2Forest'
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADForestMode -Exactly -Times 1 -Scope It
        }
    }
}
