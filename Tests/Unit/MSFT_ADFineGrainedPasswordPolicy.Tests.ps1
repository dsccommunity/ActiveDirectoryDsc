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

        $testFineGrainedPasswordPolicyName = 'Domain Users'
        $testDomainController = 'testserver.contoso.com'

        $testPassword = ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force
        $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'Safemode',
            $testPassword
        )

        $getTargetResourceParametersPolicy = @{
            Name       = $testFineGrainedPasswordPolicyName
            Precedence = 100
        }

        $fakeGetFineGrainedPasswordPolicy = @{
            Name                            = $testFineGrainedPasswordPolicyName
            DisplayName                     = $testFineGrainedPasswordPolicyName
            Description                     = "Unit Test Policy"
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

        $fakeGetFineGrainedPasswordPolicySubject = @{
            Name           = $testFineGrainedPasswordPolicyName
            ObjectClass    = 'group'
            SamAccountName = $testFineGrainedPasswordPolicyName
        }

        $fakeGetFineGrainedPasswordPolicySubjectAbsent = $null
        $fakeGetFineGrainedPasswordPolicyAbsent = $null

        $mockAdFineGrainedPasswordPolicyChanged = @{
            Name                      = $testFineGrainedPasswordPolicyName
            ComplexityEnabled         = $false
            MinPasswordLength         = 1
            PasswordHistoryCount      = 0
        }

        $mockGetResourceFineGrainedPasswordPolicy = @{
            Name                            = $fakeGetFineGrainedPasswordPolicy.Name
            DisplayName                     = $fakeGetFineGrainedPasswordPolicy.DisplayName
            Description                     = $fakeGetFineGrainedPasswordPolicy.Description
            ComplexityEnabled               = $fakeGetFineGrainedPasswordPolicy.ComplexityEnabled
            LockoutDuration                 = $fakeGetFineGrainedPasswordPolicy.LockoutDuration
            LockoutObservationWindow        = $fakeGetFineGrainedPasswordPolicy.LockoutObservationWindow
            LockoutThreshold                = $fakeGetFineGrainedPasswordPolicy.LockoutThreshold
            MinPasswordAge                  = $fakeGetFineGrainedPasswordPolicy.MinPasswordAge
            MaxPasswordAge                  = $fakeGetFineGrainedPasswordPolicy.MaxPasswordAge
            MinPasswordLength               = $fakeGetFineGrainedPasswordPolicy.MinPasswordLength
            PasswordHistoryCount            = $fakeGetFineGrainedPasswordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled     = $fakeGetFineGrainedPasswordPolicy.ReversibleEncryptionEnabled
            Precedence                      = $fakeGetFineGrainedPasswordPolicy.Precedence
            ProtectedFromAccidentalDeletion = $fakeGetFineGrainedPasswordPolicy.ProtectedFromAccidentalDeletion
            Ensure                          = 'Present'
            Subjects                        = [string[]] $fakeGetFineGrainedPasswordPolicy.Name
        }

        $mockGetResourceFineGrainedPasswordPolicyAbsent = @{
            Name                            = $testFineGrainedPasswordPolicyName
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
                    -MockWith { $fakeGetFineGrainedPasswordPolicy }
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                    -MockWith { $fakeGetFineGrainedPasswordPolicySubject }
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

                    foreach ($property in $mockGetResourceFineGrainedPasswordPolicy.Keys)
                    {
                        It "Should return the correct $property property" {
                            $result.$property | Should -Be $mockGetResourceFineGrainedPasswordPolicy.$property
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
                        -MockWith { $fakeGetFineGrainedPasswordPolicyAbsent }

                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -MockWith { $fakeGetFineGrainedPasswordPolicySubjectAbsent }

                    $result = Get-TargetResource @getTargetResourceParametersPolicy
                }

                foreach ($property in $mockGetResourceFineGrainedPasswordPolicy.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockGetResourceFineGrainedPasswordPolicyAbsent.$property
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
                    Name                            = $fakeGetFineGrainedPasswordPolicy.Name
                    DisplayName                     = $fakeGetFineGrainedPasswordPolicy.DisplayName
                    Description                     = $fakeGetFineGrainedPasswordPolicy.Description
                    ComplexityEnabled               = $fakeGetFineGrainedPasswordPolicy.ComplexityEnabled
                    LockoutDuration                 = [TimeSpan]::Parse('00:30:00')
                    LockoutObservationWindow        = [TimeSpan]::Parse('00:30:00')
                    LockoutThreshold                = $fakeGetFineGrainedPasswordPolicy.LockoutThreshold
                    MinPasswordAge                  = [TimeSpan]::Parse('1.00:00:00')
                    MaxPasswordAge                  = [TimeSpan]::Parse('42.00:00:00')
                    MinPasswordLength               = $fakeGetFineGrainedPasswordPolicy.MinPasswordLength
                    PasswordHistoryCount            = $fakeGetFineGrainedPasswordPolicy.PasswordHistoryCount
                    Precedence                      = $null
                    ProtectedFromAccidentalDeletion = $fakeGetFineGrainedPasswordPolicy.ProtectedFromAccidentalDeletion
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
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicy }
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

                    foreach ($property in $mockAdFineGrainedPasswordPolicyChanged.Keys)
                    {
                        if ($property -notin ('Name'))
                        {
                            Context "When the $property resource property is not in the desired state" {

                                It 'Should return $false' {
                                    $testTargetResourceParametersChanged = $testTargetResourceParametersNotDesired.Clone()
                                    $testTargetResourceParametersChanged.$property = $mockAdFineGrainedPasswordPolicyChanged.$property

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
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicyAbsent }
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
                $testFineGrainedPasswordPolicyName = 'Domain Users'

                $testGetDefaultParams = @{
                    Name                            = $testFineGrainedPasswordPolicyName
                    Precedence                      = 10
                }

                $testSetDefaultParams = @{
                    Name                            = $testFineGrainedPasswordPolicyName
                    Precedence                      = 10
                    Ensure                          = 'Present'
                    ProtectedFromAccidentalDeletion = $true
                }

                $stubFineGrainedPasswordPolicy = @{
                    Name                            = $testFineGrainedPasswordPolicyName
                    DisplayName                     = $testFineGrainedPasswordPolicyName
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

                $fakeGetSetFineGrainedPasswordPolicy = @{
                    Name                            = $testFineGrainedPasswordPolicyName
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
                Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicy }
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
                        Mock -CommandName Get-TargetResource -ParameterFilter { $Credential -eq $testCredential } `
                            -MockWith { $mockGetResourceFineGrainedPasswordPolicy }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Credential -eq $testCredential }

                        $result = Set-TargetResource @testSetDefaultParams -Credential $testCredential
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -ParameterFilter `
                             { $Credential -eq $testCredential } -Exactly -Times 1
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Credential -eq $testCredential } -Exactly -Times 1
                    }
                }

                Context 'When the "DomainController" parameter is not specified' {
                    BeforeAll {
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Server -eq $null }

                        $result = Set-TargetResource @testSetDefaultParams
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Server -eq $null } -Exactly -Times 1
                    }
                }

                Context 'When the "DomainController" parameter is specified' {
                    BeforeAll {
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Server -eq $testDomainController }

                        $result = Set-TargetResource @testSetDefaultParams -DomainController $testDomainController
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Server -eq $testDomainController } -Exactly -Times 1
                    }
                }

                Context 'When each configuration is to be changed individually' {
                    BeforeAll {
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Server -eq $testDomainController }

                        $result = Set-TargetResource @testSetDefaultParams
                    }

                    foreach ($propertyName in $stubFineGrainedPasswordPolicy.Keys)
                    {
                        if ($propertyName -notin ('Name','Ensure'))
                        {
                            $propertyDefaultParams = $testSetDefaultParams.Clone()
                            $propertyDefaultParams[$propertyName] = $fakeGetSetFineGrainedPasswordPolicy[$propertyName]

                            Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
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
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $testSetDefaultParamsDiff } `
                            -MockWith { throw 'UnexpectedError' }
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
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicyAbsent }
                    $result = Get-TargetResource @testGetDefaultParams
                }

                Context 'When policy does not exist' {
                    BeforeAll {
                        $newFineGrainedParametersPolicy = $stubFineGrainedPasswordPolicy.Clone()
                        $newFineGrainedParametersPolicy['DisplayName'] = 'Display Name'
                        $newFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $true
                        $newFineGrainedParametersPolicy['Precedence'] = 10
                        $newFineGrainedParametersPolicy['MinPasswordAge'] = '1.00:00:00'
                        $newFineGrainedParametersPolicy['MaxPasswordAge'] = '42.00:00:00'
                        $newFineGrainedParametersPolicy['Subjects'] = $testFineGrainedPasswordPolicyName

                        Mock -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $newFineGrainedParametersPolicy }
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                        $result = Set-TargetResource @newFineGrainedParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $newFineGrainedParametersPolicy } -Exactly -Times 1
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1
                    }
                }

                Context 'When New-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        Mock -CommandName New-ADFineGrainedPasswordPolicy `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @stubFineGrainedPasswordPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $stubFineGrainedPasswordPolicy.Name)
                    }
                }

                Context 'When Add-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        $newFineGrainedParametersPolicy = $stubFineGrainedPasswordPolicy.Clone()
                        $newFineGrainedParametersPolicy['Precedence'] = 10
                        $newFineGrainedParametersPolicy['Subjects'] = $testFineGrainedPasswordPolicyName

                        Mock -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $newFineGrainedParametersPolicy }
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -ParameterFilter `
                            { $Identity -eq $newFineGrainedParametersPolicy['Name'] -and `
                                $Subjects -eq $newFineGrainedParametersPolicy['Subjects'] } `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @newFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.AddingPasswordPolicySubjectsError -f
                                $newFineGrainedParametersPolicy.Name)
                    }
                }
            }

            Context 'When the Resource exists and needs to be deleted' {
                BeforeAll {
                    $result = Get-TargetResource @testGetDefaultParams
                }

                Context 'When "ProtectedFromAccidentalDeletion" is set true and the policy is deleted' {
                    BeforeAll {
                        $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'
                        $mockPasswordPolicyProtected = $mockGetResourceFineGrainedPasswordPolicy.Clone()
                        $mockPasswordPolicyProtected['ProtectedFromAccidentalDeletion'] = $true

                        Mock -CommandName Get-TargetResource -MockWith { $mockPasswordPolicyProtected }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $removeFineGrainedParametersPolicy }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }

                        $result = Set-TargetResource @removeFineGrainedParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $removeFineGrainedParametersPolicy } -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } -Exactly -Times 1
                    }
                }

                Context 'When Set-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'
                        $mockPasswordPolicyProtected = $mockGetResourceFineGrainedPasswordPolicy.Clone()
                        $mockPasswordPolicyProtected['ProtectedFromAccidentalDeletion'] = $true

                        Mock -CommandName Get-TargetResource -MockWith { $mockPasswordPolicyProtected }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $removeFineGrainedParametersPolicy } `
                            -MockWith { throw 'UnexpectedError' }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @removeFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $removeFineGrainedParametersPolicy.Name)
                    }
                }

                Context 'When Remove-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    BeforeAll {
                        $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                        $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                        Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $removeFineGrainedParametersPolicy }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                            { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @removeFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceRemovalError -f
                                $removeFineGrainedParametersPolicy.Name)
                    }
                }
            }

            Context 'When the Resource does not exist and specified to be deleted' {
                    BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicyAbsent }
                    $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                    $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }

                    $result = Set-TargetResource @removeFineGrainedParametersPolicy
                }

                It 'Should not call the expected mocks' {
                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy } -Times 0
                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } -Times 0
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
                        $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Admins'
                        $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                        $result = Set-TargetResource @setSubjectsFineGrainedParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1
                    }
                }

                Context 'When adding a new subject to policy that does not have subjects' {
                    BeforeAll {
                        $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Users'
                        $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'
                        $fakeGetFineGrainedPasswordPolicy = $mockGetResourceFineGrainedPasswordPolicy.Clone()
                        $fakeGetFineGrainedPasswordPolicy['Subjects'] = $null

                        Mock -CommandName Get-TargetResource -MockWith { $fakeGetFineGrainedPasswordPolicy }
                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                        $result = Set-TargetResource @setSubjectsFineGrainedParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -Exactly -Times 1
                    }
                }

                Context 'When expected Subjects is set to null value to remove existing' {
                    BeforeAll {
                        # $mockGetResourcePasswordPolicySubs = $mockGetResourceFineGrainedPasswordPolicy.Clone()
                        # $mockGetResourcePasswordPolicySubs['Subjects'] = 'Domain Admins', 'Domain Users'
                        $removeSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $removeSubjectsFineGrainedParametersPolicy['Subjects'] = $null
                        $removeSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'

                        # Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicySubs }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject

                        Set-TargetResource @removeSubjectsFineGrainedParametersPolicy
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicySubject
                    }
                }

                Context 'When Remove-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        $mockGetResourcePasswordPolicySubs = $mockGetResourceFineGrainedPasswordPolicy.Clone()
                        $mockGetResourcePasswordPolicySubs['Subjects'] = 'Domain Admins', 'Domain Users'
                        $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Users'
                        $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Get-TargetResource -MockWith { $mockGetResourcePasswordPolicySubs }
                        Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setSubjectsFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.RemovingPasswordPolicySubjectsError -f
                                $setSubjectsFineGrainedParametersPolicy.Name)
                    }
                }

                Context 'When Add-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    BeforeAll {
                        $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                        $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Admins'
                        $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'

                        Mock -CommandName Add-ADFineGrainedPasswordPolicySubject `
                            -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setSubjectsFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.AddingPasswordPolicySubjectsError -f
                                $setSubjectsFineGrainedParametersPolicy.Name)
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
