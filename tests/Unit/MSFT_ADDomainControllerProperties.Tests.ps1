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
    $script:dscResourceName = 'MSFT_ADDomainControllerProperties'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscResourceName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    Restore-TestEnvironment -TestEnvironment $script:testEnvironment

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_ADDomainControllerProperties\Get-TargetResource' -Tag 'Get' {
    Context 'When the current property values are returned' {
        BeforeAll {
            Mock -CommandName Get-CimInstance -MockWith {
                return @{
                    MaxOfflineTimeInDays = 60
                }
            }
        }

        It 'Should return the correct values' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockGetParameters = @{
                    IsSingleInstance = 'Yes'
                }

                $result = Get-TargetResource @mockGetParameters
                $result.IsSingleInstance | Should -Be $mockGetParameters.IsSingleInstance
                $result.ContentFreshness | Should -Be 60
            }

            Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADDomainControllerProperties\Test-TargetResource' -Tag 'Test' {
    Context 'When the system is in the desired state' {
        Context 'When the property ContentFreshness is in desired state' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'ContentFreshness'
                            InDesiredState = $true
                        }
                    )
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockTestParameters = @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }

                    Test-TargetResource @mockTestParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property ContentFreshness is not in desired state' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'ContentFreshness'
                            InDesiredState = $false
                        }
                    )
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockTestParameters = @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }

                    Test-TargetResource @mockTestParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADDomainControllerProperties\Compare-TargetResourceState' -Tag 'Compare' {
    Context 'When the system is in the desired state' {
        Context 'When the property ContentFreshness is in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }
                }

                Mock -CommandName Compare-ResourcePropertyState -MockWith {
                    @{
                        ParameterName  = 'ContentFreshness'
                        Expected       = 60
                        Actual         = 60
                        InDesiredState = $true
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $compareParameters = @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }

                    $result = Compare-TargetResourceState @compareParameters
                    $result | Should -HaveCount 1

                    $comparedReturnValue = $result.Where( { $_.ParameterName -eq 'ContentFreshness' })
                    $comparedReturnValue | Should -Not -BeNullOrEmpty
                    $comparedReturnValue.Expected | Should -Be 60
                    $comparedReturnValue.Actual | Should -Be 60
                    $comparedReturnValue.InDesiredState | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Compare-ResourcePropertyState -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property ContentFreshness is not in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }
                }

                Mock -CommandName Compare-ResourcePropertyState -MockWith {
                    @{
                        ParameterName  = 'ContentFreshness'
                        Expected       = 100
                        Actual         = 60
                        InDesiredState = $false
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $compareParameters = @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 100
                    }

                    $compareParameters = Compare-TargetResourceState @compareParameters
                    $compareParameters | Should -HaveCount 1

                    $comparedReturnValue = $compareParameters.Where( { $_.ParameterName -eq 'ContentFreshness' })
                    $comparedReturnValue | Should -Not -BeNullOrEmpty
                    $comparedReturnValue.Expected | Should -Be 100
                    $comparedReturnValue.Actual | Should -Be 60
                    $comparedReturnValue.InDesiredState | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Compare-ResourcePropertyState -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADDomainControllerProperties\Set-TargetResource' -Tag 'Set' {
    Context 'When the system is in the desired state' {
        Context 'When the property ContentFreshness is in desired state' {
            BeforeAll {
                Mock -CommandName Set-CimInstance
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'ContentFreshness'
                            InDesiredState = $true
                        }
                    )
                }
            }

            It 'Should not throw and do not call Set-CimInstance' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockSetParameters = @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }

                    { Set-TargetResource @mockSetParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-CimInstance -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property ContentFreshness is not in desired state' {
            BeforeAll {
                Mock -CommandName Set-CimInstance
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'ContentFreshness'
                            InDesiredState = $false
                        }
                    )
                }
            }

            It 'Should not throw and call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockSetParameters = @{
                        IsSingleInstance = 'Yes'
                        ContentFreshness = 60
                    }

                    { Set-TargetResource @mockSetParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-CimInstance -Exactly -Times 1 -Scope It
            }
        }
    }
}
