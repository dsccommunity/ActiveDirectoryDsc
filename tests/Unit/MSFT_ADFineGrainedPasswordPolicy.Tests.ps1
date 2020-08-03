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

        $testPasswordPolicyName = 'Domain Users'
        $testDomainController = 'testserver.contoso.com'

        $testPassword = ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force
        $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'Safemode',
            $testPassword
        )

        $getTargetResourceParametersPolicy = @{
            Name       = $testPasswordPolicyName
            Precedence = 100
        }

        $mockGetPasswordPolicy = @{
            Name                            = $testPasswordPolicyName
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
            ReversibleEncryptionEnabled     = $false
            ProtectedFromAccidentalDeletion = $false
        }

        $mockGetPasswordPolicySubject = @{
            Name           = $testPasswordPolicyName
            ObjectClass    = 'group'
            SamAccountName = $testPasswordPolicyName
        }

        $mockGetPasswordPolicySubjectAbsent = $null
        $mockGetPasswordPolicyAbsent = $null

        $mockAdPasswordPolicyChanged = @{
            Name                      = $testPasswordPolicyName
            ComplexityEnabled         = $false
            MinPasswordLength         = 1
            PasswordHistoryCount      = 0
        }

        $mockGetResourcePasswordPolicy = @{
            Name                            = $mockGetPasswordPolicy.Name
            DisplayName                     = $mockGetPasswordPolicy.DisplayName
            Description                     = $mockGetPasswordPolicy.Description
            ComplexityEnabled               = $mockGetPasswordPolicy.ComplexityEnabled
            LockoutDuration                 = $mockGetPasswordPolicy.LockoutDuration
            LockoutObservationWindow        = $mockGetPasswordPolicy.LockoutObservationWindow.ToString()
            LockoutThreshold                = $mockGetPasswordPolicy.LockoutThreshold.ToString()
            MinPasswordAge                  = $mockGetPasswordPolicy.MinPasswordAge.ToString()
            MaxPasswordAge                  = $mockGetPasswordPolicy.MaxPasswordAge.ToString()
            MinPasswordLength               = $mockGetPasswordPolicy.MinPasswordLength
            PasswordHistoryCount            = $mockGetPasswordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled     = $mockGetPasswordPolicy.ReversibleEncryptionEnabled
            Precedence                      = $mockGetPasswordPolicy.Precedence
            ProtectedFromAccidentalDeletion = $mockGetPasswordPolicy.ProtectedFromAccidentalDeletion
            Ensure                          = 'Present'
            Subjects                        = [string[]] $mockGetPasswordPolicy.Name
        }

        $mockGetResourcePasswordPolicyAbsent = @{
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
                Mock -CommandName Assert-Module
                Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                    -MockWith { $mockGetPasswordPolicy }
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                    -MockWith { $mockGetPasswordPolicySubject }
            }

            Context 'When the resource is Present' {
                Context 'When the "Credential" parameter is specified' {
                    BeforeAll {
                        $result = Get-TargetResource @getTargetResourceParametersPolicy -Credential $testCredential
                    }

                    It 'Should call the expected mocks' {
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
                        $result = Get-TargetResource @getTargetResourceParametersPolicy `
                            -DomainController $testDomainController
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy `
                            -ParameterFilter { $Server -eq $testDomainController } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            -ParameterFilter { $Server -eq $testDomainController } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resouce has all same input values' {
                    BeforeAll {
                        $result = Get-TargetResource @getTargetResourceParametersPolicy
                    }

                    foreach ($property in $mockGetResourcePasswordPolicy.Keys)
                    {
                        It "Should return the correct $property property" {
                            $result.$property | Should -Be $mockGetResourcePasswordPolicy.$property
                        }
                    }

                    It 'Should return the correct Ensure property' {
                        $result.Ensure | Should -Be 'Present'
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            -ParameterFilter { $Identity -eq $getTargetResourceParametersPolicy.Name } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { $mockGetPasswordPolicyAbsent }

                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -MockWith { $mockGetPasswordPolicySubjectAbsent }

                    $result = Get-TargetResource @getTargetResourceParametersPolicy
                }

                foreach ($property in $mockGetResourcePasswordPolicy.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockGetResourcePasswordPolicyAbsent.$property
                    }
                }

                It 'Should return the correct Ensure property' {
                    $result.Ensure | Should -Be 'Absent'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -ParameterFilter { $Identity -eq $getTargetResourceParametersPolicy.Name } `
                        -Exactly -Times 0
                }
            }

            Context 'When Get-ADFineGrainedPasswordPolicy throws an unexpected error' {
                BeforeAll {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParametersPolicy } |
                        Should -Throw ($script:localizedData.RetrieveFineGrainedPasswordPolicyError -f
                            $getTargetResourceParametersPolicy.Name)
                }
            }

            Context 'When Get-ADFineGrainedPasswordPolicy cannot find the policy' {
                BeforeAll {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                }

                It 'Should not throw' {
                    { Get-TargetResource @getTargetResourceParametersPolicy } | Should -Not -Throw
                }
            }

            Context 'When Get-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                BeforeAll {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParametersPolicy } |
                        Should -Throw ($script:localizedData.RetrieveFineGrainedPasswordPolicySubjectError -f
                            $getTargetResourceParametersPolicy.Name)
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParametersPolicy = @{
                    Name                            = $mockGetPasswordPolicy.Name
                    DisplayName                     = $mockGetPasswordPolicy.DisplayName
                    Description                     = $mockGetPasswordPolicy.Description
                    ComplexityEnabled               = $mockGetPasswordPolicy.ComplexityEnabled
                    LockoutDuration                 = [TimeSpan]::Parse('00:30:00')
                    LockoutObservationWindow        = [TimeSpan]::Parse('00:30:00')
                    LockoutThreshold                = $mockGetPasswordPolicy.LockoutThreshold
                    MinPasswordAge                  = [TimeSpan]::Parse('1.00:00:00')
                    MaxPasswordAge                  = [TimeSpan]::Parse('42.00:00:00')
                    MinPasswordLength               = $mockGetPasswordPolicy.MinPasswordLength
                    PasswordHistoryCount            = $mockGetPasswordPolicy.PasswordHistoryCount
                    Precedence                      = $null
                    ProtectedFromAccidentalDeletion = $mockGetPasswordPolicy.ProtectedFromAccidentalDeletion
                    Ensure                          = 'Present'
                }

                $testTargetResourceParametersPolicyAbsent = $testTargetResourceParametersPolicy.Clone()
                $testTargetResourceParametersPolicyAbsent.Ensure = 'Absent'

                $testTargetResourceParametersDesired = $testTargetResourceParametersPolicy.Clone()
                $testTargetResourceParametersDesired['Precedence'] = 100
                $testTargetResourceParametersDesired['ReversibleEncryptionEnabled'] = $false

                $testTargetResourceParametersNotDesired = $testTargetResourceParametersPolicy.Clone()
                $testTargetResourceParametersNotDesired['Precedence'] = 100
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicy }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParametersPolicy -Credential $testCredential `
                            -DomainController $testDomainController }  | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceParametersPolicy.Name
                                $Precedence -eq $testTargetResourceParametersPolicy.Precedence
                                $Subjects -eq $testTargetResourceParametersPolicy.Name
                                $Credential -eq $testCredential
                                $DomainController -eq $testDomainController } `
                            -Exactly -Times 1
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return $true' {
                            Test-TargetResource @testTargetResourceParametersDesired -Credential $testCredential `
                                -DomainController $testDomainController | Should -Be $true
                        }
                    }

                    foreach ($property in $mockAdPasswordPolicyChanged.Keys)
                    {
                        if ($property -notin ('Name'))
                        {
                            Context "When the $property resource property is not in the desired state" {

                                It 'Should return $false' {
                                    $testTargetResourceParametersChanged = $testTargetResourceParametersNotDesired.Clone()
                                    $testTargetResourceParametersChanged.$property = $mockAdPasswordPolicyChanged.$property

                                    Test-TargetResource @testTargetResourceParametersChanged | Should -Be $false
                                }
                            }
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParametersPolicyAbsent } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter {
                                $Name -eq $testTargetResourceParametersPolicy.Name
                                $Precedence -eq $testTargetResourceParametersPolicy.Precedence
                                $Subjects -eq $testTargetResourceParametersPolicy.Subjects
                                $Credential -eq $testCredential
                                $DomainController -eq $testDomainController } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceParametersPolicyAbsent | Should -Be $false
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicyAbsent }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParametersPolicy } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter {
                                $Name -eq $testTargetResourceParametersPolicy.Name
                                $Precedence -eq $testTargetResourceParametersPolicy.Precedence
                                $Subjects -eq $testTargetResourceParametersPolicy.Subjects
                                $Credential -eq $testCredential
                                $DomainController -eq $testDomainController } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceParametersPolicy | Should -Be $false
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParametersPolicyAbsent } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceParametersPolicyAbsent.Name
                                $Precedence -eq $testTargetResourceParametersPolicyAbsent.Precedence
                                $Subjects -eq $testTargetResourceParametersPolicyAbsent.Subjects
                                $Credential -eq $testCredential
                                $DomainController -eq $testDomainController } `
                            -Exactly -Times 1
                    }

                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceParametersPolicyAbsent | Should -Be $true
                    }
                }
            }
        }
        #endregion

        #region Function Set-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Set-TargetResource' {
            BeforeAll {
                $testPasswordPolicyName = 'Domain Users'

                $testGetDefaultParams = @{
                    Name                            = $testPasswordPolicyName
                    Precedence                      = 10
                }

                $testSetDefaultParams = @{
                    Name                            = $testPasswordPolicyName
                    Precedence                      = 10
                    Ensure                          = 'Present'
                    ProtectedFromAccidentalDeletion = $true
                }

                $stubPasswordPolicy = @{
                    Name                            = $testPasswordPolicyName
                    DisplayName                     = 'Domain Users Password Policy'
                    Description                     = 'Unit Test Policy'
                    ComplexityEnabled               = $true
                    LockoutDuration                 = '00:30:00'
                    LockoutObservationWindow        = '00:30:00'
                    LockoutThreshold                = 3
                    MinPasswordAge                  = [TimeSpan]::Parse('1.00:00:00').TotalDays
                    MaxPasswordAge                  = [TimeSpan]::Parse('42.00:00:00').TotalDays
                    MinPasswordLength               = 7
                    PasswordHistoryCount            = 12
                    ReversibleEncryptionEnabled     = $true
                    Precedence                      = $null
                    ProtectedFromAccidentalDeletion = $false
                    Ensure                          = 'Present'
                }

                $fakeGetSetPasswordPolicy = @{
                    Name                            = $testPasswordPolicyName
                    DisplayName                     = 'Display Name'
                    Description                     = 'Unit Test Policy Diff'
                    ComplexityEnabled               = $false
                    LockoutDuration                 = [TimeSpan]::Parse('00:20:00')
                    LockoutObservationWindow        = [TimeSpan]::Parse('00:20:00')
                    LockoutThreshold                = 5
                    MinPasswordAge                  = [TimeSpan]::Parse('2.00:00:00')
                    MaxPasswordAge                  = [TimeSpan]::Parse('40.00:00:00')
                    MinPasswordLength               = 8
                    PasswordHistoryCount            = 10
                    ReversibleEncryptionEnabled     = $true
                    Precedence                      = 100
                    ProtectedFromAccidentalDeletion = $false

                }

                Mock -CommandName Assert-Module
                Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicy }
                Mock -CommandName Set-ADFineGrainedPasswordPolicy
            }

            Context 'When the Resource is present and needs to be updated' {
                BeforeAll {
                    $result = Set-TargetResource @testGetDefaultParams
                }

                It 'Should call "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' }
                }

                Context 'When the "Credential" parameter is not specified' {
                    BeforeAll {
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy

                        $result = Set-TargetResource @testSetDefaultParams
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -Exactly -Times 1
                    }
                }

                Context 'When the "Credential" parameter is specified' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicy }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy

                        $result = Set-TargetResource @testSetDefaultParams -Credential $testCredential
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -ParameterFilter `
                             { $Credential -eq $testCredential } -Exactly -Times 1
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Credential -eq $testCredential } -Exactly -Times 1
                    }
                }

                Context 'When the "DomainController" parameter is specified' {
                    BeforeAll {
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy

                        $result = Set-TargetResource @testSetDefaultParams -DomainController $testDomainController
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Server -eq $testDomainController } -Exactly -Times 1
                    }
                }

                Context 'When each configuration is to be changed individually' {
                    BeforeAll {
                        $result = Set-TargetResource @testSetDefaultParams
                    }

                    foreach ($propertyName in $stubPasswordPolicy.Keys)
                    {
                        if ($propertyName -notin ('Name','Ensure'))
                        {
                            $propertyDefaultParams = $testSetDefaultParams.Clone()
                            $propertyDefaultParams[$propertyName] = $fakeGetSetPasswordPolicy[$propertyName]

                            Mock -CommandName Set-ADFineGrainedPasswordPolicy `
                                { $PSBoundParameters.ContainsKey($propertyName) }

                            $result = Set-TargetResource @propertyDefaultParams

                            It "Should call expected mocks with '$propertyName' parameter when specified" {
                                Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy
                            }
                        }
                    }
                }

                Context 'When Set-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        $testSetDefaultParamsDiff = $testSetDefaultParams.Clone()
                        $testSetDefaultParamsDiff['MinPasswordLength'] = 20

                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @testSetDefaultParamsDiff } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f `
                                $testSetDefaultParamsDiff.Name)
                    }
                }

                Context 'When the Resource exists and does not need to be updated' {
                    BeforeAll {
                        $testSetDefaultParamsNoDiff = $testSetDefaultParams.Clone()
                        $testSetDefaultParamsNoDiff['Precedence'] = 100
                        $testSetDefaultParamsNoDiff['ProtectedFromAccidentalDeletion'] = $false

                        Mock -CommandName Set-ADFineGrainedPasswordPolicy

                        $result = Set-TargetResource @testSetDefaultParamsNoDiff
                    }

                    It "Should not call 'Set-ADFineGrainedPasswordPolicy' when resource set as desired" {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -Times 0
                    }
                }
            }

            Context 'When the Resource does not exist and needs to be created' {
                BeforeAll {
                    Mock -CommandName Assert-Module
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicyAbsent }
                    $result = Get-TargetResource @testGetDefaultParams
                }

                Context 'When policy does not exist' {
                    BeforeAll {
                        $newParametersPolicy = $stubPasswordPolicy.Clone()
                        $newParametersPolicy['DisplayName'] = 'Display Name'
                        $newParametersPolicy['ProtectedFromAccidentalDeletion'] = $true
                        $newParametersPolicy['Precedence'] = 10
                        $newParametersPolicy['MinPasswordAge'] = '1.00:00:00'
                        $newParametersPolicy['MaxPasswordAge'] = '42.00:00:00'
                        $newParametersPolicy['Subjects'] = $testPasswordPolicyName

                        Mock -CommandName New-ADFineGrainedPasswordPolicy
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                        $result = Set-TargetResource @newParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $newParametersPolicy } -Exactly -Times 1
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1
                    }
                }

                Context 'When New-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        Mock -CommandName New-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @stubPasswordPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $stubPasswordPolicy.Name)
                    }
                }

                Context 'When Add-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        $newParametersPolicy = $stubPasswordPolicy.Clone()
                        $newParametersPolicy['Precedence'] = 10
                        $newParametersPolicy['Subjects'] = $testPasswordPolicyName

                        Mock -CommandName New-ADFineGrainedPasswordPolicy
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @newParametersPolicy } |
                            Should -Throw ($script:localizedData.AddingPasswordPolicySubjectsError -f
                                $newParametersPolicy.Name)
                    }
                }
            }

            Context 'When the Resource exists and needs to be deleted' {
                BeforeAll {
                    $result = Get-TargetResource @testGetDefaultParams
                }

                Context 'When "ProtectedFromAccidentalDeletion" is set true and the policy is deleted' {
                    BeforeAll {
                        $removeParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeParametersPolicy['Ensure'] = 'Absent'
                        $mockPasswordPolicyProtected = $mockGetResourcePasswordPolicy.Clone()
                        $mockPasswordPolicyProtected['ProtectedFromAccidentalDeletion'] = $true

                        Mock -CommandName Get-TargetResource -MockWith { $mockPasswordPolicyProtected }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicy

                        $result = Set-TargetResource @removeParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $removeParametersPolicy } -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Identity -eq $removeParametersPolicy['Name'] } -Exactly -Times 1
                    }
                }

                Context 'When Set-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        $removeParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeParametersPolicy['Ensure'] = 'Absent'
                        $mockPasswordPolicyProtected = $mockGetResourcePasswordPolicy.Clone()
                        $mockPasswordPolicyProtected['ProtectedFromAccidentalDeletion'] = $true

                        Mock -CommandName Get-TargetResource -MockWith { $mockPasswordPolicyProtected }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicy
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @removeParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $removeParametersPolicy.Name)
                    }
                }

                Context 'When Remove-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        $removeParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                        $removeParametersPolicy['Ensure'] = 'Absent'

                        Mock -CommandName Set-ADFineGrainedPasswordPolicy
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicy -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @removeParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceRemovalError -f
                                $removeParametersPolicy.Name)
                    }
                }
            }

            Context 'When the Resource does not exist and specified to be deleted' {
                    BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicyAbsent }
                    $removeParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                    $removeParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Set-ADFineGrainedPasswordPolicy
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy

                    $result = Set-TargetResource @removeParametersPolicy
                }

                It 'Should not call the expected mocks' {
                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeParametersPolicy } -Times 0
                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeParametersPolicy['Name'] } -Times 0
                }
            }

            Context 'When the Resource exists and subjects to be explicitly set' {
                BeforeAll {
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy
                    $result = Set-TargetResource @testGetDefaultParams
                }

                It 'Should call "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' }
                }

                Context 'When adding a new subject to policy' {
                    BeforeAll {
                        $setSubjectsParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsParametersPolicy['Subjects'] = 'Domain Admins'
                        $setSubjectsParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                        $result = Set-TargetResource @setSubjectsParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1
                    }
                }

                Context 'When adding a new subject to policy that does not have subjects' {
                    BeforeAll {
                        $setSubjectsParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsParametersPolicy['Subjects'] = 'Domain Users'
                        $setSubjectsParametersPolicy['Ensure'] = 'Present'
                        $mockGetPasswordPolicy = $mockGetResourcePasswordPolicy.Clone()
                        $mockGetPasswordPolicy['Subjects'] = $null

                        Mock -CommandName Get-TargetResource -MockWith { $mockGetPasswordPolicy }
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                        $result = Set-TargetResource @setSubjectsParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1
                    }
                }

                Context 'When expected Subjects is set to null value to remove existing' {
                    BeforeAll {
                        $removeSubjectsParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeSubjectsParametersPolicy['Subjects'] = $null
                        $removeSubjectsParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject

                        Set-TargetResource @removeSubjectsParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject
                    }
                }

                Context 'When Remove-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        $mockGetResourcePasswordPolicySubs = $mockGetResourcePasswordPolicy.Clone()
                        $mockGetResourcePasswordPolicySubs['Subjects'] = 'Domain Admins', 'Domain Users'
                        $setSubjectsParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsParametersPolicy['Subjects'] = 'Domain Users'
                        $setSubjectsParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicySubs }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setSubjectsParametersPolicy } |
                            Should -Throw ($script:localizedData.RemovingPasswordPolicySubjectsError -f
                                $setSubjectsParametersPolicy.Name)
                    }
                }

                Context 'When Add-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        $setSubjectsParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsParametersPolicy['Subjects'] = 'Domain Admins'
                        $setSubjectsParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setSubjectsParametersPolicy } |
                            Should -Throw ($script:localizedData.AddingPasswordPolicySubjectsError -f
                                $setSubjectsParametersPolicy.Name)
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
