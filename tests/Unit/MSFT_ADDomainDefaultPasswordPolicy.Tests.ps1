# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
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
    $script:dscResourceName = 'MSFT_ADDomainDefaultPasswordPolicy'

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

Describe 'MSFT_ADDomainDefaultPasswordPolicy\Get-TargetResource' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-ADCommonParameters -MockWith {
                @{
                    Identity = 'contoso.com'
                }
            }

            Mock -CommandName Get-ADDefaultDomainPasswordPolicy -MockWith {
                @{
                    ComplexityEnabled           = $true
                    LockoutDuration             = New-TimeSpan -Minutes 30
                    LockoutObservationWindow    = New-TimeSpan -Minutes 30
                    LockoutThreshold            = 3
                    MinPasswordAge              = New-TimeSpan -Days 1
                    MaxPasswordAge              = New-TimeSpan -Days 42
                    MinPasswordLength           = 7
                    PasswordHistoryCount        = 12
                    ReversibleEncryptionEnabled = $false
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockGetParams = @{
                    DomainName = 'contoso.com'
                }

                $result = Get-TargetResource @mockGetParams

                $result.DomainName | Should -Be 'contoso.com'
                $result.ComplexityEnabled | Should -BeTrue
                $result.LockoutDuration | Should -Be 30
                $result.LockoutObservationWindow | Should -Be 30
                $result.LockoutThreshold | Should -Be 3
                $result.MinPasswordAge | Should -Be 1440
                $result.MaxPasswordAge | Should -Be 60480
                $result.MinPasswordLength | Should -Be 7
                $result.PasswordHistoryCount | Should -Be 12
                $result.ReversibleEncryptionEnabled | Should -BeFalse
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADCommonParameters -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADDefaultDomainPasswordPolicy -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-ADCommonParameters -MockWith {
                @{
                    Identity = 'contoso.com'
                }
            }

            Mock -CommandName Get-ADDefaultDomainPasswordPolicy -MockWith {
                @{
                    LockoutDuration          = New-TimeSpan
                    LockoutObservationWindow = New-TimeSpan
                    MinPasswordAge           = New-TimeSpan
                    MaxPasswordAge           = New-TimeSpan
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockGetParams = @{
                    DomainName = 'contoso.com'
                }

                $result = Get-TargetResource @mockGetParams

                $result.DomainName | Should -Be 'contoso.com'
                $result.ComplexityEnabled | Should -BeNullOrEmpty
                $result.LockoutDuration | Should -Be 0
                $result.LockoutObservationWindow | Should -Be 0
                $result.LockoutThreshold | Should -BeNullOrEmpty
                $result.MinPasswordAge | Should -Be 0
                $result.MaxPasswordAge | Should -Be 0
                $result.MinPasswordLength | Should -BeNullOrEmpty
                $result.PasswordHistoryCount | Should -BeNullOrEmpty
                $result.ReversibleEncryptionEnabled | Should -BeNullOrEmpty
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADCommonParameters -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADDefaultDomainPasswordPolicy -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADDomainDefaultPasswordPolicy\Test-TargetResource' -Tag 'Test' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                  = 'contoso.com'
                    ComplexityEnabled           = $true
                    LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutThreshold            = 3
                    MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                    MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                    MinPasswordLength           = 7
                    PasswordHistoryCount        = 12
                    ReversibleEncryptionEnabled = $true
                }
            }
        }

        It 'Should return true' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockTestParams = @{
                    DomainName                  = 'contoso.com'
                    Credential                  = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'SafeMode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainController            = 'testserver.contoso.com'
                    ComplexityEnabled           = $true
                    LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutThreshold            = 3
                    MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                    MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                    MinPasswordLength           = 7
                    PasswordHistoryCount        = 12
                    ReversibleEncryptionEnabled = $true
                }

                Test-TargetResource @mockTestParams | Should -BeTrue
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeDiscovery {
            $testCases = @(
                @{
                    Name  = 'ComplexityEnabled'
                    Value = $false
                }
                @{
                    Name  = 'LockoutDuration'
                    Value = (New-TimeSpan -Minutes 60).TotalMinutes
                }
                @{
                    Name  = 'LockoutObservationWindow'
                    Value = (New-TimeSpan -Minutes 60).TotalMinutes
                }
                @{
                    Name  = 'LockoutThreshold'
                    Value = 5
                }
                @{
                    Name  = 'MinPasswordAge'
                    Value = (New-TimeSpan -Days 5).TotalMinutes
                }
                @{
                    Name  = 'MaxPasswordAge'
                    Value = (New-TimeSpan -Days 60).TotalMinutes
                }
                @{
                    Name  = 'MinPasswordLength'
                    Value = 10
                }
                @{
                    Name  = 'PasswordHistoryCount'
                    Value = 10
                }
                @{
                    Name  = 'ReversibleEncryptionEnabled'
                    Value = $false
                }
            )
        }

        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                  = 'contoso.com'
                    ComplexityEnabled           = $true
                    LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutThreshold            = 3
                    MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                    MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                    MinPasswordLength           = 7
                    PasswordHistoryCount        = 12
                    ReversibleEncryptionEnabled = $true
                }
            }
        }

        It 'Should return false when parameter <Name> does not match' -ForEach $testCases {
            InModuleScope -Parameters $_ -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockTestParams = @{
                    DomainName                  = 'contoso.com'
                    ComplexityEnabled           = $true
                    LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutThreshold            = 3
                    MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                    MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                    MinPasswordLength           = 7
                    PasswordHistoryCount        = 12
                    ReversibleEncryptionEnabled = $true
                }

                $mockTestParams.$Name = $Value

                Test-TargetResource @mockTestParams | Should -BeFalse
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADDomainDefaultPasswordPolicy\Set-TargetResource' -Tag 'Set' {
    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-ADCommonParameters -MockWith {
                @{
                    Identity = 'contoso.com'
                }
            }

            Mock -CommandName Set-ADDefaultDomainPasswordPolicy
        }

        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockSetParams = @{
                    DomainName                  = 'contoso.com'
                    ComplexityEnabled           = $true
                    LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                    LockoutThreshold            = 3
                    MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                    MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                    MinPasswordLength           = 7
                    PasswordHistoryCount        = 12
                    ReversibleEncryptionEnabled = $true
                }

                { Set-TargetResource @mockSetParams } | Should -Not -Throw
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADCommonParameters -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADDefaultDomainPasswordPolicy -Exactly -Times 1 -Scope It
        }
    }
}
