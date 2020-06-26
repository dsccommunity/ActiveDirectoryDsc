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
            Name                        = $testFineGrainedPasswordPolicyName
            ComplexityEnabled           = $true
            LockoutDuration             = [TimeSpan]::Parse('00:30:00')
            LockoutObservationWindow    = [TimeSpan]::Parse('00:30:00')
            LockoutThreshold            = 3
            MinPasswordAge              = [TimeSpan]::Parse('1.00:00:00')
            MaxPasswordAge              = [TimeSpan]::Parse('42.00:00:00')
            MinPasswordLength           = 7
            PasswordHistoryCount        = 12
            Precedence                  = 100
            ReversibleEncryptionEnabled = $false
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
            Name                        = $fakeGetFineGrainedPasswordPolicy.Name
            ComplexityEnabled           = $fakeGetFineGrainedPasswordPolicy.ComplexityEnabled
            LockoutDuration             = $fakeGetFineGrainedPasswordPolicy.LockoutDuration
            LockoutObservationWindow    = $fakeGetFineGrainedPasswordPolicy.LockoutObservationWindow
            LockoutThreshold            = $fakeGetFineGrainedPasswordPolicy.LockoutThreshold
            MinPasswordAge              = $fakeGetFineGrainedPasswordPolicy.MinPasswordAge
            MaxPasswordAge              = $fakeGetFineGrainedPasswordPolicy.MaxPasswordAge
            MinPasswordLength           = $fakeGetFineGrainedPasswordPolicy.MinPasswordLength
            PasswordHistoryCount        = $fakeGetFineGrainedPasswordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled = $fakeGetFineGrainedPasswordPolicy.ReversibleEncryptionEnabled
            Precedence                  = $getTargetResourceParametersPolicy['Precedence']
            Ensure                      = 'Present'
            Subjects                    = @($fakeGetFineGrainedPasswordPolicy.Name)
        }

        $mockGetResourceFineGrainedPasswordPolicyAbsent = @{
            Name                        = $testFineGrainedPasswordPolicyName
            ComplexityEnabled           = $null
            LockoutDuration             = $null
            LockoutObservationWindow    = $null
            LockoutThreshold            = $null
            MinPasswordAge              = $null
            MaxPasswordAge              = $null
            MinPasswordLength           = $null
            PasswordHistoryCount        = $null
            ReversibleEncryptionEnabled = $null
            Precedence                  = $null
            Ensure                      = 'Absent'
            Subjects                    = @()
        }

        #region Function Get-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Get-TargetResource' -Tag Get {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject
            }

            Context 'When the resource is Present' {


                It 'Calls "Get-ADFineGrainedPasswordPolicy" and "Get-ADFineGrainedPasswordPolicySubject" with `
                    "Credential" parameter when specified' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { $fakeGetFineGrainedPasswordPolicy }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -MockWith { $fakeGetFineGrainedPasswordPolicySubject }

                    $result = Get-TargetResource @getTargetResourceParametersPolicy -Credential $testCredential

                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -Scope It

                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject -Scope It
                }

                It 'Calls "Get-ADFineGrainedPasswordPolicy" and "Get-ADFineGrainedPasswordPolicySubject" with `
                    "DomainController" parameter when specified' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { $fakeGetFineGrainedPasswordPolicy }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -MockWith { $fakeGetFineGrainedPasswordPolicySubject }

                    $result = Get-TargetResource @getTargetResourceParametersPolicy -DomainController $testDomainController

                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -Scope It

                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject -Scope It
                }



                Context 'When the Resouce has all same input values' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        -MockWith { $fakeGetFineGrainedPasswordPolicy }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -MockWith { $fakeGetFineGrainedPasswordPolicySubject }

                    $result = Get-TargetResource @getTargetResourceParametersPolicy

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
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -Times 1
                        Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            -ParameterFilter { $Identity -eq $getTargetResourceParametersPolicy.Name } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the resource is Absent' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                    -MockWith { $fakeGetFineGrainedPasswordPolicyAbsent }

                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                    -MockWith { $fakeGetFineGrainedPasswordPolicySubjectAbsent }

                $result = Get-TargetResource @getTargetResourceParametersPolicy

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
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -Times 1
                    Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        -ParameterFilter { $Identity -eq $getTargetResourceParametersPolicy.Name } `
                        -Exactly -Times 1
                }
            }

            Context 'When Get-ADFineGrainedPasswordPolicy throws an unexpected error' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                    -MockWith { throw 'UnexpectedError' }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParametersPolicy } |
                        Should -Throw ($script:localizedData.RetrieveFineGrainedPasswordPolicyError -f
                            $getTargetResourceParametersPolicy.Name)
                }
            }

            Context 'When Get-ADFineGrainedPasswordPolicySubject throws an expected identity not found error' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                    -MockWith { $fakeGetFineGrainedPasswordPolicyAbsent }
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                    -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }

                It 'Should not throw and continue on' {
                    { Get-TargetResource @getTargetResourceParametersPolicy } |
                        Should -Not -Throw
                }
            }

            Context 'When Get-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                    -MockWith { $fakeGetFineGrainedPasswordPolicyAbsent }
                Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                    -MockWith { throw 'UnexpectedError' }

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

            $testTargetResourceParametersPolicy = @{
                Name                            = $fakeGetFineGrainedPasswordPolicy.Name
                ComplexityEnabled               = $fakeGetFineGrainedPasswordPolicy.ComplexityEnabled
                LockoutDuration                 = [TimeSpan]::Parse('00:30:00')
                LockoutObservationWindow        = [TimeSpan]::Parse('00:30:00')
                LockoutThreshold                = $fakeGetFineGrainedPasswordPolicy.LockoutThreshold
                MinPasswordAge                  = [TimeSpan]::Parse('1.00:00:00')
                MaxPasswordAge                  = [TimeSpan]::Parse('42.00:00:00')
                MinPasswordLength               = $fakeGetFineGrainedPasswordPolicy.MinPasswordLength
                PasswordHistoryCount            = $fakeGetFineGrainedPasswordPolicy.PasswordHistoryCount
                Precedence                      = $null
                Ensure                          = 'Present'
            }

            $testTargetResourceParametersPolicyAbsent = $testTargetResourceParametersPolicy.Clone()
            $testTargetResourceParametersPolicyAbsent.Ensure = 'Absent'

            $testTargetResourceParametersDesired = $testTargetResourceParametersPolicy.Clone()
            $testTargetResourceParametersDesired['Precedence'] = 100
            $testTargetResourceParametersDesired['ReversibleEncryptionEnabled'] = $false

            $testTargetResourceParametersNotDesired = $testTargetResourceParametersPolicy.Clone()
            $testTargetResourceParametersNotDesired['Precedence'] = 100

            Context 'When the Resource is Present' {

                Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicy }

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
                            -Exactly -times 1
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
                            -Exactly -times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceParametersPolicyAbsent | Should -Be $false
                    }
                }
            }

            Context 'When the Resource is Absent' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicyAbsent }

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
                            -Exactly -times 1
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
                            -Exactly -times 1
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
                Ensure                          = 'Present'
            }

            Context 'When the Resource is present and needs to be updated' {
                Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

                It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy

                    $result = Set-TargetResource @testGetDefaultParams

                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' } -Scope It
                }

                It 'Calls "Set-ADFineGrainedPasswordPolicy" without "Credential" parameter by default' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Credential -eq $null }

                    $result = Set-TargetResource @testSetDefaultParams

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Credential -eq $null } -Scope It
                }

                It 'Calls "Set-ADFineGrainedPasswordPolicy" with "Credential" parameter when specified' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Credential -eq $testCredential } { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject -ParameterFilter `
                        { $Credential -eq $testCredential } { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Credential -eq $testCredential }

                    $result = Set-TargetResource @testSetDefaultParams -Credential $testCredential

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Credential -eq $testCredential } -Scope It
                }

                It 'Calls "Set-ADFineGrainedPasswordPolicy" without "DomainController" parameter by default' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Server -eq $null }

                    $result = Set-TargetResource @testSetDefaultParams

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Server -eq $null } -Scope It
                }

                It 'Calls "Set-ADFineGrainedPasswordPolicy" with "DomainController" parameter when specified' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Server -eq $testDomainController }

                    $result = Set-TargetResource @testSetDefaultParams -DomainController $testDomainController

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Server -eq $testDomainController } -Scope It
                }

                foreach ($propertyName in $stubFineGrainedPasswordPolicy.Keys)
                {
                    if ($propertyName -notin ('Name','Ensure'))
                    {
                        It "Calls 'Set-ADFineGrainedPasswordPolicy' with '$propertyName' parameter when specified" {
                            $propertyDefaultParams = $testSetDefaultParams.Clone()
                            $propertyDefaultParams[$propertyName] = $stubFineGrainedPasswordPolicy[$propertyName]
                            Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                                { return $fakeGetFineGrainedPasswordPolicy; }
                            Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                                { return $fakeGetFineGrainedPasswordPolicySubject; }
                            Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                                { $PSBoundParameters.ContainsKey($propertyName) }

                            $result = Set-TargetResource @propertyDefaultParams

                            Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                                { $PSBoundParameters.ContainsKey($propertyName) } -Scope It
                        }
                    }
                }

                Context 'When Set-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    $testSetDefaultParamsDiff = $testSetDefaultParams.Clone()
                    $testSetDefaultParamsDiff['MinPasswordLength'] = 20

                    Mock -CommandName Get-TargetResource -MockWith { $mockGetResourceFineGrainedPasswordPolicy }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject -ParameterFilter `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                    Mock -CommandName Add-ADFineGrainedPasswordPolicySubject
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $testSetDefaultParamsDiff } `
                        -MockWith { throw 'UnexpectedError' }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @testSetDefaultParamsDiff } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f `
                                $testSetDefaultParamsDiff.Name)
                    }
                }

                Context 'When the Resource exists and does not need to be updated' {
                    $stubFineGrainedPasswordPolicyNoDiff = $stubFineGrainedPasswordPolicy.Clone()
                    $stubFineGrainedPasswordPolicyNoDiff['Precedence'] = 10
                    $stubFineGrainedPasswordPolicyNoDiff['ReversibleEncryptionEnabled'] = $false
                    $testSetDefaultParamsNoDiff = $testSetDefaultParams.Clone()
                    $testSetDefaultParamsNoDiff['Precedence'] = 10
                    $fakeGetFineGrainedPasswordPolicyNoDiff = $fakeGetFineGrainedPasswordPolicy.Clone()
                    $fakeGetFineGrainedPasswordPolicyNoDiff['Precedence'] = 10

                    It "Does not call 'Set-ADFineGrainedPasswordPolicy' when resource set as desired" {
                        Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                            { return $fakeGetFineGrainedPasswordPolicyNoDiff; }
                        Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                            { return $fakeGetFineGrainedPasswordPolicySubject; }
                        Mock -CommandName Set-ADFineGrainedPasswordPolicy

                        $result = Set-TargetResource @testSetDefaultParamsNoDiff

                        Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -Scope It -Times 0
                    }
                }
            }

            Context 'When the Resource does not exist and needs to be created' {
                Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

                It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }

                    $result = Get-TargetResource @testGetDefaultParams

                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' } -Scope It
                }

                It "Calls 'New-ADFineGrainedPasswordPolicy' and 'Add-ADFineGrainedPasswordPolicySubject' cmdlets" {
                    $newFineGrainedParametersPolicy = $stubFineGrainedPasswordPolicy.Clone()
                    $newFineGrainedParametersPolicy['Precedence'] = 10
                    $newFineGrainedParametersPolicy['MinPasswordAge'] = '1.00:00:00'
                    $newFineGrainedParametersPolicy['MaxPasswordAge'] = '42.00:00:00'
                    $newFineGrainedParametersPolicy['Subjects'] = $testFineGrainedPasswordPolicyName

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicyAbsent; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubjectAbsent; }
                    Mock -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $newFineGrainedParametersPolicy }
                    Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -ParameterFilter `
                        { $Identity -eq $newFineGrainedParametersPolicy['Name'] -and `
                            $Subjects -eq $newFineGrainedParametersPolicy['Subjects'] }

                    $result = Set-TargetResource @newFineGrainedParametersPolicy

                    Assert-MockCalled -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $newFineGrainedParametersPolicy } -Scope It
                    Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject -ParameterFilter `
                        { $Identity -eq $newFineGrainedParametersPolicy['Name'] -and `
                            $Subjects -eq $newFineGrainedParametersPolicy['Subjects'] } -Scope It
                }

                Context 'When New-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    Mock -CommandName New-ADFineGrainedPasswordPolicy `
                        -MockWith { throw 'UnexpectedError' }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @stubFineGrainedPasswordPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $stubFineGrainedPasswordPolicy.Name)
                    }
                }

                Context 'When Add-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    $newFineGrainedParametersPolicy = $stubFineGrainedPasswordPolicy.Clone()
                    $newFineGrainedParametersPolicy['Precedence'] = 10
                    $newFineGrainedParametersPolicy['Subjects'] = $testFineGrainedPasswordPolicyName

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicyAbsent; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubjectAbsent; }
                    Mock -CommandName New-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $newFineGrainedParametersPolicy }
                    Mock -CommandName Add-ADFineGrainedPasswordPolicySubject -ParameterFilter `
                        { $Identity -eq $newFineGrainedParametersPolicy['Name'] -and `
                            $Subjects -eq $newFineGrainedParametersPolicy['Subjects'] } `
                        -MockWith { throw 'UnexpectedError' }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @newFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $newFineGrainedParametersPolicy.Name)
                    }
                }
            }

            Context 'When the Resource exists and needs to be deleted' {
                Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

                It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }

                    $result = Get-TargetResource @testGetDefaultParams

                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' } -Scope It
                }

                It "Calls 'Remove-ADFineGrainedPasswordPolicy' and 'Set-ADFineGrainedPasswordPolicy' cmdlets" {
                    $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                    $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }

                    $result = Set-TargetResource @removeFineGrainedParametersPolicy

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy } -Scope It
                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } -Scope It
                }

                It "Calls 'Remove-ADFineGrainedPasswordPolicy' but does not specify to remove delete protection" {
                    $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }

                    $result = Set-TargetResource @removeFineGrainedParametersPolicy

                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } -Scope It
                }

                Context 'When Set-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                    $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy } `
                        -MockWith { throw 'UnexpectedError' }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @removeFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $removeFineGrainedParametersPolicy.Name)
                    }
                }

                Context 'When Remove-ADFineGrainedPasswordPolicy throws an unexpected error' {
                    $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                    $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } `
                        -MockWith { throw 'UnexpectedError' }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @removeFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $removeFineGrainedParametersPolicy.Name)
                    }
                }
            }

            Context 'When the Resource does not exist and specified to be deleted' {
                Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

                It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicyAbsent; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubjectAbsent; }

                    $result = Get-TargetResource @testGetDefaultParams

                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' } -Scope It
                }

                It "Does not call 'Remove-ADFineGrainedPasswordPolicy' and 'Set-ADFineGrainedPasswordPolicy' cmdlets" {
                    $removeFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $removeFineGrainedParametersPolicy['ProtectedFromAccidentalDeletion'] = $false
                    $removeFineGrainedParametersPolicy['Ensure'] = 'Absent'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicyAbsent; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubjectAbsent; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy }
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] }

                    $result = Set-TargetResource @removeFineGrainedParametersPolicy

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $removeFineGrainedParametersPolicy } -Scope It -Times 0
                    Assert-MockCalled -CommandName Remove-ADFineGrainedPasswordPolicy -ParameterFilter `
                        { $Identity -eq $removeFineGrainedParametersPolicy['Name'] } -Scope It -Times 0
                }
            }

            Context 'When the Resource exists and subjects to be explicitly set' {
                Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

                It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy

                    $result = Set-TargetResource @testGetDefaultParams

                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter `
                        { $ModuleName -eq 'ActiveDirectory' } -Scope It
                }

                It "Calls 'Add-ADFineGrainedPasswordPolicySubject' with subjects to set" {
                    $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Users'
                    $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'
                    $fakeGetFineGrainedPasswordPolicySubjectDiff = $fakeGetFineGrainedPasswordPolicySubject.Clone()
                    $fakeGetFineGrainedPasswordPolicySubjectDiff['Name'] = 'Domain Admins'
                    $fakeGetFineGrainedPasswordPolicySubjectDiff['SamAccountName'] = 'Domain Admins'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubjectDiff; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                    Mock -CommandName Add-ADFineGrainedPasswordPolicySubject

                    $result = Set-TargetResource @setSubjectsFineGrainedParametersPolicy

                    Assert-MockCalled -CommandName Add-ADFineGrainedPasswordPolicySubject
                }

                Context 'When Remove-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Admins'
                    $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy
                    Mock -CommandName Add-ADFineGrainedPasswordPolicySubject
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject `
                        -MockWith { throw 'UnexpectedError' }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setSubjectsFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
                                $setSubjectsFineGrainedParametersPolicy.Name)
                    }
                }

                Context 'When Add-ADFineGrainedPasswordPolicySubject throws an unexpected error' {
                    $setSubjectsFineGrainedParametersPolicy = $getTargetResourceParametersPolicy.Clone()
                    $setSubjectsFineGrainedParametersPolicy['Subjects'] = 'Domain Admins'
                    $setSubjectsFineGrainedParametersPolicy['Ensure'] = 'Present'

                    Mock -CommandName Get-ADFineGrainedPasswordPolicy `
                        { return $fakeGetFineGrainedPasswordPolicy; }
                    Mock -CommandName Get-ADFineGrainedPasswordPolicySubject `
                        { return $fakeGetFineGrainedPasswordPolicySubject; }
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy
                    Mock -CommandName Remove-ADFineGrainedPasswordPolicySubject
                    Mock -CommandName Add-ADFineGrainedPasswordPolicySubject `
                        -MockWith { throw 'UnexpectedError' }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setSubjectsFineGrainedParametersPolicy } |
                            Should -Throw ($script:localizedData.ResourceConfigurationError -f
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
