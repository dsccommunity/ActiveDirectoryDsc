# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies has not been resolved, this will throw an error.
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
    $script:dscResourceName = 'MSFT_ADServicePrincipalName'

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

Describe 'MSFT_ADServicePrincipalName\Get-TargetResource' -Tag 'Get' {
    Context 'When no SPN is set' {
        BeforeAll {
            Mock -CommandName Get-ADObject
        }

        It 'Should return absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                }

                $result = Get-TargetResource @testDefaultParameters

                $result.Ensure | Should -Be 'Absent'
                $result.ServicePrincipalName | Should -Be 'HOST/demo'
                $result.Account | Should -Be ''
            }
        }
    }

    Context 'When one SPN is set' {
        BeforeAll {
            Mock -CommandName Get-ADObject -MockWith {
                return [PSCustomObject] @{
                    SamAccountName = 'User'
                }
            }
        }

        It 'Should return present with the correct account' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                }

                $result = Get-TargetResource @testDefaultParameters

                $result.Ensure | Should -Be 'Present'
                $result.ServicePrincipalName | Should -Be 'HOST/demo'
                $result.Account | Should -Be 'User'
            }
        }
    }

    Context 'When multiple SPN are set' {
        BeforeAll {
            Mock -CommandName Get-ADObject -MockWith {
                return @(
                    [PSCustomObject] @{
                        SamAccountName = 'User'
                    },
                    [PSCustomObject] @{
                        SamAccountName = 'Computer'
                    }
                )
            }
        }

        It 'Should return present with the multiple accounts' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                }

                $result = Get-TargetResource @testDefaultParameters

                $result.Ensure | Should -Be 'Present'
                $result.ServicePrincipalName | Should -Be 'HOST/demo'
                $result.Account | Should -Be 'User;Computer'
            }
        }
    }
}

Describe 'MSFT_ADServicePrincipalName\Test-TargetResource' -Tag 'Test' {
    Context 'When no SPN set' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    Ensure               = 'Absent'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = ''
                }
            }
        }

        It 'Should return false for present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Present' @testDefaultParameters
                $result | Should -BeFalse
            }
        }

        It 'Should return true for absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Absent' @testDefaultParameters
                $result | Should -BeTrue
            }
        }
    }

    Context 'When correct SPN set' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    Ensure               = 'Present'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }
            }
        }

        It 'Should return true for present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Present' @testDefaultParameters
                $result | Should -BeTrue
            }
        }

        It 'Should return false for absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Absent' @testDefaultParameters
                $result | Should -BeFalse
            }
        }
    }

    Context 'When wrong SPN set' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    Ensure               = 'Present'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'Computer'
                }
            }
        }

        It 'Should return false for present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Present' @testDefaultParameters
                $result | Should -BeFalse
            }
        }

        It 'Should return false for absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Absent' @testDefaultParameters
                $result | Should -BeFalse
            }
        }
    }

    Context 'When multiple SPN set' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    Ensure               = 'Present'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User;Computer'
                }
            }
        }

        It 'Should return false for present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Present' @testDefaultParameters
                $result | Should -BeFalse
            }
        }

        It 'Should return false for absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                $result = Test-TargetResource -Ensure 'Absent' @testDefaultParameters
                $result | Should -BeFalse
            }
        }
    }
}

Describe 'MSFT_ADServicePrincipalName\Set-TargetResource' -Tag 'Set' {
    Context 'When AD Object does not exist' {
        BeforeAll {
            Mock -CommandName Test-TargetResource -MockWith { $false }
            Mock -CommandName Get-ADObject
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParams = @{
                    Ensure               = 'Present'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                { Set-TargetResource @testPresentParams } | Should -Throw ($script:localizedData.AccountNotFound -f $testPresentParams.Account)
            }

            Should -Invoke -CommandName Test-TargetResource -Exactly -Times 1 -Scope It
        }
    }

    Context 'When No SPN set' {
        BeforeAll {
            Mock -CommandName Test-TargetResource -MockWith { $false }
            Mock -CommandName Get-ADObject -ParameterFilter {
                $Filter -eq ([ScriptBlock]::Create(' ServicePrincipalName -eq $ServicePrincipalName '))
            }

            Mock -CommandName Get-ADObject -MockWith {
                return 'User'
            }

            Mock -CommandName Set-ADObject
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParams = @{
                    Ensure               = 'Present'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                { Set-TargetResource @testPresentParams } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADObject -ParameterFilter {
                $Identity -eq 'User'
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When wrong SPN set' {
        BeforeAll {
            Mock -CommandName Test-TargetResource -MockWith { $false }
            Mock -CommandName Get-ADObject -ParameterFilter { $Filter -eq ([ScriptBlock]::Create(' ServicePrincipalName -eq $ServicePrincipalName ')) } -MockWith {
                return [PSCustomObject] @{
                    SamAccountName    = 'Computer'
                    DistinguishedName = 'CN=Computer,OU=Corp,DC=contoso,DC=com'
                }
            }

            Mock -CommandName Get-ADObject -MockWith {
                return [PSCustomObject] @{
                    SamAccountName = 'User'
                }
            }

            Mock -CommandName Set-ADObject -ParameterFilter { $null -ne $Add }
            Mock -CommandName Set-ADObject -ParameterFilter { $null -ne $Remove }
        }

        It 'Should call the Set-ADObject twice' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParams = @{
                    Ensure               = 'Present'
                    ServicePrincipalName = 'HOST/demo'
                    Account              = 'User'
                }

                { Set-TargetResource @testPresentParams } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADObject -Exactly -Times 1 -Scope It -ParameterFilter { $null -ne $Add }
            Should -Invoke -CommandName Set-ADObject -Exactly -Times 1 -Scope It -ParameterFilter { $null -ne $Remove }
        }
    }

    Context 'When all SPNs are to be removed' {
        BeforeAll {
            Mock -CommandName Test-TargetResource -MockWith { $false }
            Mock -CommandName Set-ADObject
            Mock -CommandName Get-ADObject -ParameterFilter {
                $Filter -eq ([ScriptBlock]::Create(' ServicePrincipalName -eq $ServicePrincipalName '))
            } -MockWith {
                [PSCustomObject] @{
                    SamAccountName    = 'User'
                    DistinguishedName = 'CN=User,OU=Corp,DC=contoso,DC=com'
                }
            }
        }

        It 'Should call the Set-ADObject' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testAbsentParams = @{
                    Ensure               = 'Absent'
                    ServicePrincipalName = 'HOST/demo'
                }

                { Set-TargetResource @testAbsentParams } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADObject -Exactly -Times 1 -Scope It
        }
    }
}
