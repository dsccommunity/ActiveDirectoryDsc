$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADFineGrainedPasswordPolicy'

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

# Begin Testing

Invoke-TestSetup

try
{
    InModuleScope $script:dscResourceName {
        Set-StrictMode -Version 1.0

        # Load stub cmdlets and classes.
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1') -Force

        $testPasswordPolicyName = 'PasswordPolicy1'
        $testPasswordPolicySubjectsName = 'Group1'
        $testDomainController = 'testserver.contoso.com'

        $testPassword = ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force
        $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'Safemode',
            $testPassword
        )

        $mockAdPasswordPolicy = @{
            Name                            = $testPasswordPolicyName
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
            ReversibleEncryptionEnabled     = $false
            ProtectedFromAccidentalDeletion = $false
            Subjects                        = $testPasswordPolicySubjectsName
        }

        $mockGetAdFineGrainedPasswordPolicy = @{
            Name                            = $mockAdPasswordPolicy.Name
            DisplayName                     = $mockAdPasswordPolicy.DisplayName
            Description                     = $mockAdPasswordPolicy.Description
            ComplexityEnabled               = $mockAdPasswordPolicy.ComplexityEnabled
            LockoutDuration                 = [TimeSpan]::Parse($mockAdPasswordPolicy.LockoutDuration)
            LockoutObservationWindow        = [TimeSpan]::Parse($mockAdPasswordPolicy.LockoutObservationWindow)
            LockoutThreshold                = $mockAdPasswordPolicy.LockoutThreshold
            MinPasswordAge                  = [TimeSpan]::Parse($mockAdPasswordPolicy.MinPasswordAge)
            MaxPasswordAge                  = [TimeSpan]::Parse($mockAdPasswordPolicy.MaxPasswordAge)
            MinPasswordLength               = $mockAdPasswordPolicy.MinPasswordLength
            PasswordHistoryCount            = $mockAdPasswordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled     = $mockAdPasswordPolicy.ReversibleEncryptionEnabled
            Precedence                      = $mockAdPasswordPolicy.Precedence
            ProtectedFromAccidentalDeletion = $mockAdPasswordPolicy.ProtectedFromAccidentalDeletion
        }

        $mockGetFineGrainedPasswordPolicySubjectResults = @{
            Name           = $testPasswordPolicySubjectsName
            ObjectClass    = 'group'
            SamAccountName = $testPasswordPolicySubjectsName
        }

        $mockAdPasswordPolicyChanged = @{
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
        }

        $mockGetTargetResourceResults = @{
            Name                            = $mockAdPasswordPolicy.Name
            DisplayName                     = $mockAdPasswordPolicy.DisplayName
            Description                     = $mockAdPasswordPolicy.Description
            ComplexityEnabled               = $mockAdPasswordPolicy.ComplexityEnabled
            LockoutDuration                 = $mockAdPasswordPolicy.LockoutDuration
            LockoutObservationWindow        = $mockAdPasswordPolicy.LockoutObservationWindow
            LockoutThreshold                = $mockAdPasswordPolicy.LockoutThreshold
            MinPasswordAge                  = $mockAdPasswordPolicy.MinPasswordAge
            MaxPasswordAge                  = $mockAdPasswordPolicy.MaxPasswordAge
            MinPasswordLength               = $mockAdPasswordPolicy.MinPasswordLength
            PasswordHistoryCount            = $mockAdPasswordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled     = $mockAdPasswordPolicy.ReversibleEncryptionEnabled
            Precedence                      = $mockAdPasswordPolicy.Precedence
            ProtectedFromAccidentalDeletion = $mockAdPasswordPolicy.ProtectedFromAccidentalDeletion
            Ensure                          = 'Present'
            Subjects                        = [string[]] $mockAdPasswordPolicy.Subjects
        }

        $mockGetTargetResourceResultsAbsent = @{
            Name                            = $testPasswordPolicyName
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

        #region Function Get-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Get-TargetResource' -Tag Get {
            BeforeAll {
                $getTargetResourceParameters = @{
                    Name       = $testPasswordPolicyName
                    Precedence = 100
                }

                Mock -CommandName Assert-Module
                Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                    -MockWith { $mockGetAdFineGrainedPasswordPolicy }
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                    -MockWith { $mockGetFineGrainedPasswordPolicySubjectResults }
            }

            Context 'When the resource is Present' {
                BeforeAll {
                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGetTargetResourceResults.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockGetTargetResourceResults.$property
                    }
                }

                It 'Should return the correct Ensure property' {
                    $result.Ensure | Should -Be 'Present'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy `
                        -ParameterFilter { $Identity -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -ParameterFilter { $Identity -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }

                Context 'When the "Credential" parameter is specified' {
                    BeforeAll {
                        $result = Get-TargetResource @getTargetResourceParameters -Credential $testCredential
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy `
                            -ParameterFilter { $Credential -eq $testCredential } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            -ParameterFilter { $Credential -eq $testCredential } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the "DomainController" parameter is specified' {
                    BeforeAll {
                        $result = Get-TargetResource @getTargetResourceParameters `
                            -DomainController $testDomainController
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy `
                            -ParameterFilter { $Server -eq $testDomainController } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            -ParameterFilter { $Server -eq $testDomainController } `
                            -Exactly -Times 1
                    }
                }

                Context 'When Get-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } |
                            Should -Throw ($script:localizedData.RetrievePasswordPolicySubjectError -f
                                $getTargetResourceParameters.Name)
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGetTargetResourceResults.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockGetTargetResourceResultsAbsent.$property
                    }
                }

                It 'Should return the correct Ensure property' {
                    $result.Ensure | Should -Be 'Absent'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy `
                        -ParameterFilter { $Identity -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -ParameterFilter { $Identity -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 0
                }

                Context 'When Get-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } |
                            Should -Throw ($script:localizedData.RetrievePasswordPolicyError -f
                                $getTargetResourceParameters.Name)
                    }
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    Name                            = $mockAdPasswordPolicy.Name
                    DisplayName                     = $mockAdPasswordPolicy.DisplayName
                    Description                     = $mockAdPasswordPolicy.Description
                    ComplexityEnabled               = $mockAdPasswordPolicy.ComplexityEnabled
                    LockoutDuration                 = $mockAdPasswordPolicy.LockoutDuration
                    LockoutObservationWindow        = $mockAdPasswordPolicy.LockoutObservationWindow
                    LockoutThreshold                = $mockAdPasswordPolicy.LockoutThreshold
                    MinPasswordAge                  = $mockAdPasswordPolicy.MinPasswordAge
                    MaxPasswordAge                  = $mockAdPasswordPolicy.MaxPasswordAge
                    MinPasswordLength               = $mockAdPasswordPolicy.MinPasswordLength
                    PasswordHistoryCount            = $mockAdPasswordPolicy.PasswordHistoryCount
                    ReversibleEncryptionEnabled     = $mockAdPasswordPolicy.ReversibleEncryptionEnabled
                    Precedence                      = $mockAdPasswordPolicy.Precedence
                    ProtectedFromAccidentalDeletion = $mockAdPasswordPolicy.ProtectedFromAccidentalDeletion
                    Ensure                          = 'Present'
                    Subjects                        = $mockAdPasswordPolicy.Subjects
                }

                $testTargetResourceParametersAbsent = $testTargetResourceParameters.Clone()
                $testTargetResourceParametersAbsent.Ensure = 'Absent'
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResults }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParameters }  | Should -Not -Throw
                    }

                    Context 'When the "Credential" parameter is specified' {
                        Test-TargetResource @testTargetResourceParameters -Credential $testCredential

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $testTargetResourceParameters.Name -and `
                                    $Precedence -eq $testTargetResourceParameters.Precedence -and `
                                    $Credential -eq $testCredential } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "DomainController" parameter is specified' {
                        Test-TargetResource @testTargetResourceParameters -DomainController $testDomainController

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $testTargetResourceParameters.Name -and `
                                    $Precedence -eq $testTargetResourceParameters.Precedence -and `
                                    $DomainController -eq $testDomainController } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return $true' {
                            Test-TargetResource @testTargetResourceParameters | Should -Be $true
                        }
                    }

                    foreach ($property in $mockAdPasswordPolicyChanged.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            It 'Should return $false' {
                                $testTargetResourceParametersChanged = $testTargetResourceParameters.Clone()
                                $testTargetResourceParametersChanged.$property = $mockAdPasswordPolicyChanged.$property

                                Test-TargetResource @testTargetResourceParametersChanged | Should -Be $false
                            }
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParametersAbsent } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceParametersAbsent.Name -and `
                                $Precedence -eq $testTargetResourceParametersAbsent.Precedence } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceParametersAbsent | Should -Be $false
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResultsAbsent }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceParameters.Name -and `
                                $Precedence -eq $testTargetResourceParameters.Precedence } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceParameters | Should -Be $false
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParametersAbsent } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceParametersAbsent.Name -and `
                                $Precedence -eq $testTargetResourceParametersAbsent.Precedence } `
                            -Exactly -Times 1
                    }

                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceParametersAbsent | Should -Be $true
                    }
                }
            }
        }
        #endregion

        #region Function Set-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Set-TargetResource' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name                            = $mockAdPasswordPolicy.Name
                    Precedence                      = $mockAdPasswordPolicy.Precedence
                    DisplayName                     = $mockAdPasswordPolicy.DisplayName
                    Description                     = $mockAdPasswordPolicy.Description
                    ComplexityEnabled               = $mockAdPasswordPolicy.ComplexityEnabled
                    LockoutDuration                 = $mockAdPasswordPolicy.LockoutDuration
                    LockoutObservationWindow        = $mockAdPasswordPolicy.LockoutObservationWindow
                    LockoutThreshold                = $mockAdPasswordPolicy.LockoutThreshold
                    MinPasswordAge                  = $mockAdPasswordPolicy.MinPasswordAge
                    MaxPasswordAge                  = $mockAdPasswordPolicy.MaxPasswordAge
                    MinPasswordLength               = $mockAdPasswordPolicy.MinPasswordLength
                    PasswordHistoryCount            = $mockAdPasswordPolicy.PasswordHistoryCount
                    ReversibleEncryptionEnabled     = $mockAdPasswordPolicy.ReversibleEncryptionEnabled
                    ProtectedFromAccidentalDeletion = $mockAdPasswordPolicy.ProtectedFromAccidentalDeletion
                }

                $setTargetResourceParametersAbsent = $setTargetResourceParameters.Clone()
                $setTargetResourceParametersAbsent.Ensure = 'Absent'

                Mock -CommandName New-ADFineGrainedPasswordPolicy
                Mock -CommandName Set-ADFineGrainedPasswordPolicy
                Mock -CommandName Remove-ADFineGrainedPasswordPolicy
                Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                Mock -CommandName Add-ADFineGrainedPasswordPolicySubject
            }

            Context 'When the Resource should be Present' {

                Context 'When the Resource is Present' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResults }
                    }

                    foreach ($propertyName in $mockAdPasswordPolicyChanged.Keys)
                    {
                        Context "When the '$propertyName' property has changed" {
                            BeforeAll {
                                $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                                $setTargetResourceParametersChangedProperty.$propertyName = `
                                    $mockAdPasswordPolicyChanged.$propertyName

                                Set-TargetResource @setTargetResourceParametersChangedProperty
                            }

                            It "Should call the expected mocks" {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                    -ParameterFilter { (Get-Variable -Name $propertyName -ValueOnly) -eq `
                                        $setTargetResourceParametersChangedProperty.$propertyName } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                    -Exactly -Times 0
                                Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                    -Exactly -Times 0
                                Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                    -Exactly -Times 0
                                Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                    -Exactly -Times 0
                            }
                        }
                    }

                    Context "When the 'Subjects' property has changed" {
                        Context "When the 'Subjects' property is initially populated" {
                            Context "When the 'Subjects' property has a subject to be added" {
                                BeforeAll {
                                    $addSubjectName = 'Group2'
                                    $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                                    $setTargetResourceParametersChangedProperty.Subjects = [System.Collections.ArrayList]@($mockAdPasswordPolicy.Subjects)
                                    $setTargetResourceParametersChangedProperty.Subjects.Add($addSubjectName) | Out-Null

                                    Set-TargetResource @setTargetResourceParametersChangedProperty -Verbose
                                }

                                It 'Should call the expected mocks' {
                                    Assert-MockCalled -CommandName Get-TargetResource `
                                        -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                        -ParameterFilter { $Subjects -eq $addSubjectName } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                }

                                Context "When the 'Add-ADFineGrainedPasswordPolicySubject' throws an unexpected exception" {
                                    BeforeAll {
                                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                                    }

                                    It 'Should throw the correct exception' {
                                        { Set-TargetResource @setTargetResourceParametersChangedProperty } |
                                            Should -Throw ($script:localizedData.AddingPasswordPolicySubjectsError -f
                                                $setTargetResourceParametersChangedProperty.Name)
                                    }
                                }
                            }

                            Context "When the 'Subjects' property has a subject to be removed" {
                                BeforeAll {
                                    $removeSubjectName = $testPasswordPolicySubjectsName
                                    $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                                    $setTargetResourceParametersChangedProperty.Subjects = [System.Collections.ArrayList]@($mockAdPasswordPolicy.Subjects)
                                    $setTargetResourceParametersChangedProperty.Subjects.Remove($removeSubjectName) | Out-Null

                                    Set-TargetResource @setTargetResourceParametersChangedProperty -Verbose
                                }

                                It "Should call the expected mocks" {
                                    Assert-MockCalled -CommandName Get-TargetResource `
                                        -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                        -ParameterFilter { $Subjects -eq $removeSubjectName } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                }

                                Context "When 'Remove-ADFineGrainedPasswordPolicySubject' throws an unexpected exception" {
                                    BeforeAll {
                                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                                    }

                                    It 'Should throw the correct exception' {
                                        { Set-TargetResource @setTargetResourceParametersChangedProperty } |
                                            Should -Throw ($script:localizedData.RemovingPasswordPolicySubjectsError -f
                                                $setTargetResourceParametersChangedProperty.Name)
                                    }
                                }
                            }
                        }

                        Context "When the 'Subjects' property is initially empty" {
                            BeforeAll {
                                $mockGetTargetResourceResultsEmptySubject = $mockGetTargetResourceResults.Clone()
                                $mockGetTargetResourceResultsEmptySubject.Subjects = @()

                                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResultsEmptySubject }
                            }

                            Context "When the 'Subjects' property has a subject to be added" {
                                BeforeAll {
                                    $newSubject = 'Group2'
                                    $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                                    $setTargetResourceParametersChangedProperty.Subjects = $newSubject

                                    Set-TargetResource @setTargetResourceParametersChangedProperty -Verbose
                                }

                                It "Should call the expected mocks" {
                                    Assert-MockCalled -CommandName Get-TargetResource `
                                        -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                        -ParameterFilter { $Subjects -eq $newSubject } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                        -Exactly -Times 0
                                }
                            }
                        }
                    }

                    Context "When the 'Credential' parameter is specified" {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                            $setTargetResourceParametersChangedProperty.Description = $mockAdPasswordPolicyChanged.Description

                            $result = Set-TargetResource @setTargetResourceParametersChangedProperty -Credential $testCredential
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Credential -eq $testCredential } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                -ParameterFilter { $Credential -eq $testCredential } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                        }
                    }

                    Context "When the 'DomainController' parameter is specified" {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                            $setTargetResourceParametersChangedProperty.Description = $mockAdPasswordPolicyChanged.Description

                            $result = Set-TargetResource @setTargetResourceParametersChangedProperty -DomainController $testDomainController
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $DomainController -eq $testDomainController } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                -ParameterFilter { $Server -eq $testDomainController } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                        }
                    }

                    Context "When 'Set-ADFineGrainedPasswordPolicy' throws an unexpected error" {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                            $setTargetResourceParametersChangedProperty.Description = $mockAdPasswordPolicyChanged.Description

                            Mock -CommandName Set-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceParametersChangedProperty } |
                                Should -Throw ($script:localizedData.SettingPasswordPolicyError -f
                                    $setTargetResourceParametersChangedProperty.Name)
                        }
                    }

                    Context 'When the Resource is in the desired state' {
                        BeforeAll {
                            $result = Set-TargetResource @setTargetResourceParameters
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                        }
                    }
                }

                Context 'When the Resource is Absent' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResultsAbsent }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $mockGetTargetResourceResultsAbsent.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                            -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                            -Exactly -Times 0
                    }

                    Context "When the 'Subjects' Property is specified" {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResultsAbsent }

                            $setTargetResourceParametersWithSubject = $setTargetResourceParameters.Clone()
                            $setTargetResourceParametersWithSubject.Subjects = $mockAdPasswordPolicy.Subjects
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceParametersWithSubject } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $mockGetTargetResourceResultsAbsent.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                -ParameterFilter { $Name -eq $setTargetResourceParametersWithSubject.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                -ParameterFilter { $Identity -eq $setTargetResourceParametersWithSubject.Name -and `
                                    $Subjects -eq $setTargetResourceParametersWithSubject.Subjects } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                        }

                        Context "When 'Add-ADFineGrainedPasswordPolicySubject' throws an unexpected error" {
                            BeforeAll {
                                Mock -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                    -MockWith { throw 'UnexpectedError' }
                            }

                            It 'Should throw the correct exception' {
                                { Set-TargetResource @setTargetResourceParametersWithSubject } |
                                    Should -Throw ($script:localizedData.AddingPasswordPolicySubjectsError -f
                                        $setTargetResourceParametersWithSubject.Name)
                            }
                        }
                    }

                    Context "When 'New-ADFineGrainedPasswordPolicy' throws an unexpected error" {
                        BeforeAll {
                            Mock -CommandName New-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceParameters } |
                                Should -Throw ($script:localizedData.AddingPasswordPolicyError -f
                                    $setTargetResourceParameters.Name)
                        }
                    }
                }
            }

            Context 'When the Resource should be Absent' {
                Context 'When the Resource is Present' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResults }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParametersAbsent } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceParametersAbsent.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                            -ParameterFilter { $Identity -eq $setTargetResourceParametersAbsent.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                            -Exactly -Times 0
                    }

                    Context "When 'ProtectedFromAccidentalDeletion' is 'true'" {
                        BeforeAll {
                            $mockGetTargetResourceResultsDeletionProtected = $mockGetTargetResourceResults.Clone()
                            $mockGetTargetResourceResultsDeletionProtected.ProtectedFromAccidentalDeletion = $true

                            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResultsDeletionProtected }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceParametersAbsent } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourceParametersAbsent.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                                -ParameterFilter { $Identity -eq $setTargetResourceParametersAbsent.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                                -ParameterFilter { $Identity -eq $setTargetResourceParametersAbsent.Name -and `
                                    $ProtectedFromAccidentalDeletion -eq $false } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                                -Exactly -Times 0
                        }

                        Context "When 'Set-ADFineGrainedPasswordPolicy' throws an unexpected exception" {
                            BeforeAll {
                                Mock -CommandName Set-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                            }

                            It 'Should throw the correct exception' {
                                { Set-TargetResource @setTargetResourceParametersAbsent } |
                                    Should -Throw ($script:localizedData.RemovingDeletionProtectionError -f
                                        $setTargetResourceParametersAbsent.Name)
                            }
                        }
                    }

                    Context "When 'Remove-ADFineGrainedPasswordPolicy' throws an unexpected exception" {
                        BeforeAll {
                            Mock -CommandName Remove-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceParametersAbsent } |
                                Should -Throw ($script:localizedData.RemovePasswordPolicyError -f
                                    $setTargetResourceParametersAbsent.Name)
                        }
                    }
                }

                Context 'When the Resource is Absent' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResultsAbsent }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParametersAbsent } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceParametersAbsent.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject `
                            -Exactly -Times 0
                    }
                }
            }
        }
        #endregion
    }
    #endregion
}
finally
{
    Invoke-TestCleanup
}
