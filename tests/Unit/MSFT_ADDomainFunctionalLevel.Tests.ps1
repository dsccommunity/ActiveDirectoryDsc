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
    $script:dscResourceName = 'MSFT_ADDomainFunctionalLevel'

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

Describe 'MSFT_ADDomainFunctionalLevel\Get-TargetResource' -Tag 'Get' {
    Context 'When the current property values are returned' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                return @{
                    DomainMode = 'Windows2012R2Domain'
                }
            }
        }

        It 'Should return the the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainIdentity = 'contoso.com'
                    DomainMode     = 'Windows2016Domain'
                }

                $result = Get-TargetResource @mockParameters
                $result.DomainIdentity | Should -Be $mockParameters.DomainIdentity
                $result.DomainMode | Should -Be 'Windows2012R2Domain'
            }

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADDomainFunctionalLevel\Test-TargetResource' -Tag 'Test' {
    Context 'When the system is in the desired state' {
        Context 'When the property DomainMode is in desired state' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'DomainMode'
                            InDesiredState = $true
                        }
                    )
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2016Domain'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property DomainMode is not in desired state' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'DomainMode'
                            InDesiredState = $false
                        }
                    )
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2012R2Domain'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADDomainFunctionalLevel\Compare-TargetResourceState' -Tag 'Compare' {
    Context 'When the system is in the desired state' {
        Context 'When the property DomainMode is in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2016Domain'
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2016Domain'
                    }

                    $compareResult = Compare-TargetResourceState @mockParameters
                    $compareResult | Should -HaveCount 1

                    $result = $compareResult.Where( { $_.ParameterName -eq 'DomainMode' })
                    $result | Should -Not -BeNullOrEmpty
                    $result.Expected | Should -Be $mockParameters.DomainMode
                    $result.Actual | Should -Be $mockParameters.DomainMode
                    $result.InDesiredState | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property DomainMode is not in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2016Domain'
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0
                    $mockParameters = @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2012R2Domain'
                    }

                    $compareResult = Compare-TargetResourceState @mockParameters
                    $compareResult | Should -HaveCount 1

                    $comparedReturnValue = $compareResult.Where( { $_.ParameterName -eq 'DomainMode' })
                    $comparedReturnValue | Should -Not -BeNullOrEmpty
                    $comparedReturnValue.Expected | Should -Be $mockParameters.DomainMode
                    $comparedReturnValue.Actual | Should -Be 'Windows2016Domain'
                    $comparedReturnValue.InDesiredState | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADDomainFunctionalLevel\Set-TargetResource' -Tag 'Set' {
    Context 'When the system is in the desired state' {
        Context 'When the property DomainMode is in desired state' {
            BeforeAll {
                Mock -CommandName Set-ADDomainMode
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'DomainMode'
                            Actual         = 'Windows2016Domain'
                            Expected       = 'Windows2016Domain'
                            InDesiredState = $true
                        }
                    )
                }
            }

            It 'Should not throw and do not call Set-ADDomainMode' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainIdentity = 'contoso.com'
                        DomainMode     = 'Windows2016Domain'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADDomainMode -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the property DomainMode is not in desired state' {
            Context 'When desired domain mode should be ''Windows2012R2Domain''' {
                BeforeAll {
                    Mock -CommandName Set-ADDomainMode
                    Mock -CommandName Compare-TargetResourceState -MockWith {
                        return @(
                            @{
                                ParameterName  = 'DomainMode'
                                Actual         = 'Windows2016Domain'
                                Expected       = 'Windows2012R2Domain'
                                InDesiredState = $false
                            }
                        )
                    }
                }

                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainIdentity = 'contoso.com'
                            DomainMode     = 'Windows2012R2Domain'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADDomainMode -Exactly -Times 1 -Scope It
                }
            }

            Context 'When desired domain mode should be ''Windows2016Domain''' {
                BeforeAll {
                    Mock -CommandName Set-ADDomainMode
                    Mock -CommandName Compare-TargetResourceState -MockWith {
                        return @(
                            @{
                                ParameterName  = 'DomainMode'
                                Actual         = 'Windows2012R2Domain'
                                Expected       = 'Windows2016Domain'
                                InDesiredState = $false
                            }
                        )
                    }
                }

                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainIdentity = 'contoso.com'
                            DomainMode     = 'Windows2016Domain'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADDomainMode -Exactly -Times 1 -Scope It
                }
            }
        }
    }
}
