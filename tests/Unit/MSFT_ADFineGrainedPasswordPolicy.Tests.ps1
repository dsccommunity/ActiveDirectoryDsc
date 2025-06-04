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
    $script:dscResourceName = 'MSFT_ADFineGrainedPasswordPolicy'

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

Describe 'MSFT_ADFineGrainedPasswordPolicy\Get-TargetResource' -Tag 'Get' {
    Context 'When the resource is Present' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-ADFineGrainedPasswordPolicy -MockWith {
                @{
                    Name                            = 'PasswordPolicy1'
                    DisplayName                     = 'Domain Users Password Policy'
                    Description                     = 'Unit Test Policy'
                    ComplexityEnabled               = $true
                    LockoutDuration                 = [TimeSpan]::Parse('00:30:00')
                    LockoutObservationWindow        = [TimeSpan]::Parse('00:30:00')
                    LockoutThreshold                = 3
                    MinPasswordAge                  = [TimeSpan]::Parse('1.00:00:00')
                    MaxPasswordAge                  = [TimeSpan]::Parse('42.00:00:00')
                    MinPasswordLength               = 7
                    PasswordHistoryCount            = 12
                    Precedence                      = 100
                    ProtectedFromAccidentalDeletion = $false
                    ReversibleEncryptionEnabled     = $false
                }
            }

            Mock -CommandName Get-ADFineGrainedPasswordPolicySubject -MockWith {
                @{
                    Name           = 'Group1'
                    ObjectClass    = 'group'
                    SamAccountName = 'Group1'
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name       = 'PasswordPolicy1'
                    Precedence = 100
                }

                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Present'
                $result.Name | Should -Be 'PasswordPolicy1'
                $result.DisplayName | Should -Be 'Domain Users Password Policy'
                $result.Description | Should -Be 'Unit Test Policy'
                $result.ComplexityEnabled | Should -BeTrue
                $result.LockoutDuration | Should -Be '00:30:00'
                $result.LockoutObservationWindow | Should -Be '00:30:00'
                $result.LockoutThreshold | Should -Be 3
                $result.MinPasswordAge | Should -Be '1.00:00:00'
                $result.MaxPasswordAge | Should -Be '42.00:00:00'
                $result.MinPasswordLength | Should -Be 7
                $result.PasswordHistoryCount | Should -Be 12
                $result.ReversibleEncryptionEnabled | Should -BeFalse
                $result.Precedence | Should -Be 100
                $result.ProtectedFromAccidentalDeletion | Should -BeFalse
                $result.Ensure | Should -Be 'Present'
                $result.Subjects | Should -Be @('Group1')
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicy -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicySubject -Exactly -Times 1 -Scope It
        }

        Context 'When the ''Credential'' parameter is specified' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name       = 'PasswordPolicy1'
                        Precedence = 100
                        Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'SafeMode',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    Get-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter {
                    $null -ne $Credential
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicySubject -ParameterFilter {
                    $null -ne $Credential
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the ''DomainController'' parameter is specified' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name             = 'PasswordPolicy1'
                        Precedence       = 100
                        DomainController = 'testserver.contoso.com'
                    }

                    Get-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter {
                    $Server -eq 'testserver.contoso.com'
                } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicySubject -ParameterFilter {
                    $Server -eq 'testserver.contoso.com'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When Get-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
            BeforeAll {
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject -MockWith {
                    throw 'UnexpectedError'
                }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name       = 'PasswordPolicy1'
                        Precedence = 100
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RetrievePasswordPolicySubjectError -f $mockParameters.Name)

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-ADFineGrainedPasswordPolicy -MockWith {
                @{
                    Name                            = 'PasswordPolicy1'
                    DisplayName                     = 'Domain Users Password Policy'
                    Description                     = 'Unit Test Policy'
                    ComplexityEnabled               = $true
                    LockoutDuration                 = [TimeSpan]::Parse('00:30:00')
                    LockoutObservationWindow        = [TimeSpan]::Parse('00:30:00')
                    LockoutThreshold                = 3
                    MinPasswordAge                  = [TimeSpan]::Parse('1.00:00:00')
                    MaxPasswordAge                  = [TimeSpan]::Parse('42.00:00:00')
                    MinPasswordLength               = 7
                    PasswordHistoryCount            = 12
                    Precedence                      = 100
                    ProtectedFromAccidentalDeletion = $false
                    ReversibleEncryptionEnabled     = $false
                }
            }

            Mock -CommandName Get-ADFineGrainedPasswordPolicySubject -MockWith {
                @{
                    Name           = 'Group1'
                    ObjectClass    = 'group'
                    SamAccountName = 'Group1'
                }
            }

            Mock -CommandName Get-ADFineGrainedPasswordPolicySubject
            Mock -CommandName Get-ADFineGrainedPasswordPolicy -MockWith {
                throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name       = 'PasswordPolicy1'
                    Precedence = 100
                }

                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Absent'
                $result.Name | Should -Be 'PasswordPolicy1'
                $result.DisplayName | Should -BeNullOrEmpty
                $result.Description | Should -BeNullOrEmpty
                $result.ComplexityEnabled | Should -BeNullOrEmpty
                $result.LockoutDuration | Should -BeNullOrEmpty
                $result.LockoutObservationWindow | Should -BeNullOrEmpty
                $result.LockoutThreshold | Should -BeNullOrEmpty
                $result.MinPasswordAge | Should -BeNullOrEmpty
                $result.MaxPasswordAge | Should -BeNullOrEmpty
                $result.MinPasswordLength | Should -BeNullOrEmpty
                $result.PasswordHistoryCount | Should -BeNullOrEmpty
                $result.ReversibleEncryptionEnabled | Should -BeNullOrEmpty
                $result.Precedence | Should -BeNullOrEmpty
                $result.ProtectedFromAccidentalDeletion | Should -BeNullOrEmpty
                $result.Ensure | Should -Be 'Absent'
                $result.Subjects | Should -BeNullOrEmpty
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter {
                $Identity -eq 'PasswordPolicy1'
            } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADFineGrainedPasswordPolicySubject -ParameterFilter {
                $Identity -eq 'PasswordPolicy1'
            } -Exactly -Times 0 -Scope It
        }

        Context 'When Get-ADFineGrainedPasswordPolicy throws an unexpected error' {
            BeforeAll {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name       = 'PasswordPolicy1'
                        Precedence = 100
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RetrievePasswordPolicyError -f $mockParameters.Name)

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }
            }
        }
    }
}

Describe 'MSFT_ADFineGrainedPasswordPolicy\Test-TargetResource' -Tag 'Test' {
    Context 'When the Resource is Present' {
        Context 'When the resource should be Present' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ReversibleEncryptionEnabled     = $false
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Present'
                        Subjects                        = [string[]] 'Group1'
                    }
                }
            }

            Context 'When the ''Credential'' parameter is specified' {
                It 'Should return the correct result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            Precedence                      = 100
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Ensure                          = 'Present'
                            Subjects                        = 'Group1'
                            Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'SafeMode',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''DomainController'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            Precedence                      = 100
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Ensure                          = 'Present'
                            Subjects                        = 'Group1'
                            DomainController                = 'testserver.contoso.com'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'testserver.contoso.com' } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return the correct result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            Precedence                      = 100
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Ensure                          = 'Present'
                            Subjects                        = 'Group1'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            Context 'When the resource is not in the desired state' {
                It 'Should return the correct result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            DisplayName                     = 'Password Policy 2'
                            Description                     = 'Fine Grained Password Policy 2'
                            ComplexityEnabled               = $false
                            LockoutDuration                 = '00:31:00'
                            LockoutObservationWindow        = '00:31:00'
                            LockoutThreshold                = 4
                            MinPasswordAge                  = '2.00:00:00'
                            MaxPasswordAge                  = '43.00:00:00'
                            MinPasswordLength               = 8
                            PasswordHistoryCount            = 13
                            Precedence                      = 110
                            ReversibleEncryptionEnabled     = $true
                            ProtectedFromAccidentalDeletion = $true
                            Ensure                          = 'Present'
                            Subjects                        = 'Group1'
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }
                }
            }
        }

        Context 'When the resource should be Absent' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ReversibleEncryptionEnabled     = $false
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Present'
                        Subjects                        = [string[]] 'Group1'
                    }
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        ReversibleEncryptionEnabled     = $false
                        Ensure                          = 'Absent'
                        Subjects                        = 'Group1'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                            = 'PasswordPolicy1'
                    DisplayName                     = $null
                    Description                     = $null
                    ComplexityEnabled               = $null
                    LockoutDuration                 = $null
                    LockoutObservationWindow        = $null
                    LockoutThreshold                = $null
                    MinPasswordAge                  = $null
                    MaxPasswordAge                  = $null
                    MinPasswordLength               = $null
                    PasswordHistoryCount            = $null
                    ReversibleEncryptionEnabled     = $null
                    Precedence                      = $null
                    ProtectedFromAccidentalDeletion = $null
                    Ensure                          = 'Absent'
                    Subjects                        = @()
                }
            }
        }

        Context 'When the resource should be Present' {
            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        ReversibleEncryptionEnabled     = $false
                        Ensure                          = 'Present'
                        Subjects                        = 'Group1'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        ReversibleEncryptionEnabled     = $false
                        Ensure                          = 'Absent'
                        Subjects                        = 'Group1'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADFineGrainedPasswordPolicy\Set-TargetResource' -Tag 'Set' {
    Context 'When the Resource should be Present' {
        BeforeAll {
            Mock -CommandName New-ADFineGrainedPasswordPolicy
            Mock -CommandName Set-ADFineGrainedPasswordPolicy
            Mock -CommandName Remove-ADFineGrainedPasswordPolicy
            Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
            Mock -CommandName Add-ADFineGrainedPasswordPolicySubject
        }

        Context 'When the Resource is Present' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ReversibleEncryptionEnabled     = $false
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Present'
                        Subjects                        = [string[]] 'Group1'
                    }
                }
            }

            Context 'When properties have changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 110
                            DisplayName                     = 'Password Policy 2'
                            Description                     = 'Fine Grained Password Policy 2'
                            ComplexityEnabled               = $false
                            LockoutDuration                 = '00:31:00'
                            LockoutObservationWindow        = '00:31:00'
                            LockoutThreshold                = 4
                            MinPasswordAge                  = '2.00:00:00'
                            MaxPasswordAge                  = '43.00:00:00'
                            MinPasswordLength               = 8
                            PasswordHistoryCount            = 13
                            ReversibleEncryptionEnabled     = $true
                            ProtectedFromAccidentalDeletion = $true
                        }

                        Set-TargetResource @mockParameters
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''Subjects'' property has changed' {
                Context 'When the ''Subjects'' property is initially populated' {
                    Context 'When the ''Subjects'' property has a subject to be added' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    Name                            = 'PasswordPolicy1'
                                    Precedence                      = 100
                                    DisplayName                     = 'Domain Users Password Policy'
                                    Description                     = 'Unit Test Policy'
                                    ComplexityEnabled               = $true
                                    LockoutDuration                 = '00:30:00'
                                    LockoutObservationWindow        = '00:30:00'
                                    LockoutThreshold                = 3
                                    MinPasswordAge                  = '1.00:00:00'
                                    MaxPasswordAge                  = '42.00:00:00'
                                    MinPasswordLength               = 7
                                    PasswordHistoryCount            = 12
                                    ProtectedFromAccidentalDeletion = $false
                                    ReversibleEncryptionEnabled     = $false
                                    Subjects                        = @('Group1', 'Group2')
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -ParameterFilter { $Subjects -eq 'Group2' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                        }

                        Context 'When the ''Add-ADFineGrainedPasswordPolicySubject'' throws an unexpected exception' {
                            BeforeAll {
                                Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                            }

                            It 'Should throw the correct exception' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        Name                            = 'PasswordPolicy1'
                                        Precedence                      = 100
                                        DisplayName                     = 'Domain Users Password Policy'
                                        Description                     = 'Unit Test Policy'
                                        ComplexityEnabled               = $true
                                        LockoutDuration                 = '00:30:00'
                                        LockoutObservationWindow        = '00:30:00'
                                        LockoutThreshold                = 3
                                        MinPasswordAge                  = '1.00:00:00'
                                        MaxPasswordAge                  = '42.00:00:00'
                                        MinPasswordLength               = 7
                                        PasswordHistoryCount            = 12
                                        ProtectedFromAccidentalDeletion = $false
                                        ReversibleEncryptionEnabled     = $false
                                        Subjects                        = @('Group1', 'Group2')
                                    }

                                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.AddingPasswordPolicySubjectsError -f $mockParameters.Name)

                                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                                }
                            }
                        }
                    }

                    Context 'When the ''Subjects'' property has a subject to be removed' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                @{
                                    Name                            = 'PasswordPolicy1'
                                    DisplayName                     = 'Domain Users Password Policy'
                                    Description                     = 'Unit Test Policy'
                                    ComplexityEnabled               = $true
                                    LockoutDuration                 = '00:30:00'
                                    LockoutObservationWindow        = '00:30:00'
                                    LockoutThreshold                = 3
                                    MinPasswordAge                  = '1.00:00:00'
                                    MaxPasswordAge                  = '42.00:00:00'
                                    MinPasswordLength               = 7
                                    PasswordHistoryCount            = 12
                                    ReversibleEncryptionEnabled     = $false
                                    Precedence                      = 100
                                    ProtectedFromAccidentalDeletion = $false
                                    Ensure                          = 'Present'
                                    Subjects                        = @('Group1', 'Group2')
                                }
                            }
                        }

                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    Name                            = 'PasswordPolicy1'
                                    Precedence                      = 100
                                    DisplayName                     = 'Domain Users Password Policy'
                                    Description                     = 'Unit Test Policy'
                                    ComplexityEnabled               = $true
                                    LockoutDuration                 = '00:30:00'
                                    LockoutObservationWindow        = '00:30:00'
                                    LockoutThreshold                = 3
                                    MinPasswordAge                  = '1.00:00:00'
                                    MaxPasswordAge                  = '42.00:00:00'
                                    MinPasswordLength               = 7
                                    PasswordHistoryCount            = 12
                                    ProtectedFromAccidentalDeletion = $false
                                    ReversibleEncryptionEnabled     = $false
                                    Subjects                        = @('Group2')
                                }

                                Set-TargetResource @mockParameters
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'PasswordPolicy1' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -ParameterFilter { $Subjects -eq 'Group1' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                        }

                        Context 'When ''Remove-ADFineGrainedPasswordPolicySubject'' throws an unexpected exception' {
                            BeforeAll {
                                Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                            }

                            It 'Should throw the correct exception' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        Name                            = 'PasswordPolicy1'
                                        Precedence                      = 100
                                        DisplayName                     = 'Domain Users Password Policy'
                                        Description                     = 'Unit Test Policy'
                                        ComplexityEnabled               = $true
                                        LockoutDuration                 = '00:30:00'
                                        LockoutObservationWindow        = '00:30:00'
                                        LockoutThreshold                = 3
                                        MinPasswordAge                  = '1.00:00:00'
                                        MaxPasswordAge                  = '42.00:00:00'
                                        MinPasswordLength               = 7
                                        PasswordHistoryCount            = 12
                                        ProtectedFromAccidentalDeletion = $false
                                        ReversibleEncryptionEnabled     = $false
                                        Subjects                        = @('Group2')
                                    }

                                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RemovingPasswordPolicySubjectsError -f $mockParameters.Name)

                                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                                }
                            }
                        }
                    }
                }

                Context 'When the ''Subjects'' property is initially empty' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            @{
                                Name                            = 'PasswordPolicy1'
                                DisplayName                     = 'Domain Users Password Policy'
                                Description                     = 'Unit Test Policy'
                                ComplexityEnabled               = $true
                                LockoutDuration                 = '00:30:00'
                                LockoutObservationWindow        = '00:30:00'
                                LockoutThreshold                = 3
                                MinPasswordAge                  = '1.00:00:00'
                                MaxPasswordAge                  = '42.00:00:00'
                                MinPasswordLength               = 7
                                PasswordHistoryCount            = 12
                                ReversibleEncryptionEnabled     = $false
                                Precedence                      = 100
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Present'
                                Subjects                        = @()
                            }
                        }
                    }

                    Context 'When the ''Subjects'' property has a subject to be added' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    Name                            = 'PasswordPolicy1'
                                    Precedence                      = 100
                                    DisplayName                     = 'Domain Users Password Policy'
                                    Description                     = 'Unit Test Policy'
                                    ComplexityEnabled               = $true
                                    LockoutDuration                 = '00:30:00'
                                    LockoutObservationWindow        = '00:30:00'
                                    LockoutThreshold                = 3
                                    MinPasswordAge                  = '1.00:00:00'
                                    MaxPasswordAge                  = '42.00:00:00'
                                    MinPasswordLength               = 7
                                    PasswordHistoryCount            = 12
                                    ProtectedFromAccidentalDeletion = $false
                                    ReversibleEncryptionEnabled     = $false
                                    Subjects                        = @('Group2')
                                }

                                Set-TargetResource @mockParameters
                            }

                            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -ParameterFilter { $Subjects -eq @('Group2') } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                        }
                    }
                }
            }

            Context 'When the ''Credential'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Fine Grained Password Policy 2'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'SafeMode',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the 'DomainController' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Fine Grained Password Policy 2'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            DomainController                = 'testserver.contoso.com'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'testserver.contoso.com' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq 'testserver.contoso.com' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When ''Set-ADFineGrainedPasswordPolicy'' throws an unexpected error' {
                BeforeAll {
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Fine Grained Password Policy 2'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.SettingPasswordPolicyError -f $mockParameters.Name)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }
                }
            }

            Context 'When the Resource is in the desired state' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                        }

                        Set-TargetResource @mockParameters
                    }

                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the Resource is Absent' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = $null
                        Description                     = $null
                        ComplexityEnabled               = $null
                        LockoutDuration                 = $null
                        LockoutObservationWindow        = $null
                        LockoutThreshold                = $null
                        MinPasswordAge                  = $null
                        MaxPasswordAge                  = $null
                        MinPasswordLength               = $null
                        PasswordHistoryCount            = $null
                        ReversibleEncryptionEnabled     = $null
                        Precedence                      = $null
                        ProtectedFromAccidentalDeletion = $null
                        Ensure                          = 'Absent'
                        Subjects                        = @()
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'PasswordPolicy1'
                        Precedence                      = 100
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ProtectedFromAccidentalDeletion = $false
                        ReversibleEncryptionEnabled     = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
            }

            Context 'When the 'Subjects' Property is specified' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            Name                            = 'PasswordPolicy1'
                            DisplayName                     = $null
                            Description                     = $null
                            ComplexityEnabled               = $null
                            LockoutDuration                 = $null
                            LockoutObservationWindow        = $null
                            LockoutThreshold                = $null
                            MinPasswordAge                  = $null
                            MaxPasswordAge                  = $null
                            MinPasswordLength               = $null
                            PasswordHistoryCount            = $null
                            ReversibleEncryptionEnabled     = $null
                            Precedence                      = $null
                            ProtectedFromAccidentalDeletion = $null
                            Ensure                          = 'Absent'
                            Subjects                        = @()
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Subjects                        = @('Group1')
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                }

                Context 'When ''Add-ADFineGrainedPasswordPolicySubject'' throws an unexpected error' {
                    BeforeAll {
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'PasswordPolicy1'
                                Precedence                      = 100
                                DisplayName                     = 'Domain Users Password Policy'
                                Description                     = 'Unit Test Policy'
                                ComplexityEnabled               = $true
                                LockoutDuration                 = '00:30:00'
                                LockoutObservationWindow        = '00:30:00'
                                LockoutThreshold                = 3
                                MinPasswordAge                  = '1.00:00:00'
                                MaxPasswordAge                  = '42.00:00:00'
                                MinPasswordLength               = 7
                                PasswordHistoryCount            = 12
                                ProtectedFromAccidentalDeletion = $false
                                ReversibleEncryptionEnabled     = $false
                                Subjects                        = @('Group1')
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.AddingPasswordPolicySubjectsError -f $mockParameters.Name)

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }

            Context 'When ''New-ADFineGrainedPasswordPolicy'' throws an unexpected error' {
                BeforeAll {
                    Mock -CommandName New-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.AddingPasswordPolicyError -f $mockParameters.Name)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }
                }
            }
        }
    }

    Context 'When the Resource should be Absent' {
        BeforeAll {
            Mock -CommandName New-ADFineGrainedPasswordPolicy
            Mock -CommandName Set-ADFineGrainedPasswordPolicy
            Mock -CommandName Remove-ADFineGrainedPasswordPolicy
            Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
            Mock -CommandName Add-ADFineGrainedPasswordPolicySubject
        }

        Context 'When the Resource is Present' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ReversibleEncryptionEnabled     = $false
                        Precedence                      = 100
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Present'
                        Subjects                        = [string[]] 'Group1'
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'PasswordPolicy1'
                        Precedence                      = 100
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ProtectedFromAccidentalDeletion = $false
                        ReversibleEncryptionEnabled     = $false
                        Ensure                          = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
            }

            Context 'When ''ProtectedFromAccidentalDeletion'' is 'true'' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            Name                            = 'PasswordPolicy1'
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ReversibleEncryptionEnabled     = $false
                            Precedence                      = 100
                            ProtectedFromAccidentalDeletion = $true
                            Ensure                          = 'Present'
                            Subjects                        = [string[]] 'Group1'
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Ensure                          = 'Absent'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter {
                        $ProtectedFromAccidentalDeletion -eq $false
                    } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                }

                Context 'When ''Set-ADFineGrainedPasswordPolicy'' throws an unexpected exception' {
                    BeforeAll {
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'PasswordPolicy1'
                                Precedence                      = 100
                                DisplayName                     = 'Domain Users Password Policy'
                                Description                     = 'Unit Test Policy'
                                ComplexityEnabled               = $true
                                LockoutDuration                 = '00:30:00'
                                LockoutObservationWindow        = '00:30:00'
                                LockoutThreshold                = 3
                                MinPasswordAge                  = '1.00:00:00'
                                MaxPasswordAge                  = '42.00:00:00'
                                MinPasswordLength               = 7
                                PasswordHistoryCount            = 12
                                ProtectedFromAccidentalDeletion = $false
                                ReversibleEncryptionEnabled     = $false
                                Ensure                          = 'Absent'
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RemovingDeletionProtectionError -f $mockParameters.Name)

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }

            Context 'When ''Remove-ADFineGrainedPasswordPolicy'' throws an unexpected exception' {
                BeforeAll {
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'PasswordPolicy1'
                            Precedence                      = 100
                            DisplayName                     = 'Domain Users Password Policy'
                            Description                     = 'Unit Test Policy'
                            ComplexityEnabled               = $true
                            LockoutDuration                 = '00:30:00'
                            LockoutObservationWindow        = '00:30:00'
                            LockoutThreshold                = 3
                            MinPasswordAge                  = '1.00:00:00'
                            MaxPasswordAge                  = '42.00:00:00'
                            MinPasswordLength               = 7
                            PasswordHistoryCount            = 12
                            ProtectedFromAccidentalDeletion = $false
                            ReversibleEncryptionEnabled     = $false
                            Ensure                          = 'Absent'
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RemovePasswordPolicyError -f $mockParameters.Name)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }
                }
            }
        }

        Context 'When the Resource is Absent' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                            = 'PasswordPolicy1'
                        DisplayName                     = $null
                        Description                     = $null
                        ComplexityEnabled               = $null
                        LockoutDuration                 = $null
                        LockoutObservationWindow        = $null
                        LockoutThreshold                = $null
                        MinPasswordAge                  = $null
                        MaxPasswordAge                  = $null
                        MinPasswordLength               = $null
                        PasswordHistoryCount            = $null
                        ReversibleEncryptionEnabled     = $null
                        Precedence                      = $null
                        ProtectedFromAccidentalDeletion = $null
                        Ensure                          = 'Absent'
                        Subjects                        = @()
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'PasswordPolicy1'
                        Precedence                      = 100
                        DisplayName                     = 'Domain Users Password Policy'
                        Description                     = 'Unit Test Policy'
                        ComplexityEnabled               = $true
                        LockoutDuration                 = '00:30:00'
                        LockoutObservationWindow        = '00:30:00'
                        LockoutThreshold                = 3
                        MinPasswordAge                  = '1.00:00:00'
                        MaxPasswordAge                  = '42.00:00:00'
                        MinPasswordLength               = 7
                        PasswordHistoryCount            = 12
                        ProtectedFromAccidentalDeletion = $false
                        ReversibleEncryptionEnabled     = $false
                        Ensure                          = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'PasswordPolicy1' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 0 -Scope It
            }
        }
    }
}
