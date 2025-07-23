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
    $script:dscResourceName = 'MSFT_ADOrganizationalUnit'

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

Describe 'MSFT_ADOrganizationalUnit\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the resource is Present' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $false
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'TestOU'
                    Path = 'OU=Fake,DC=contoso,DC=com'
                }

                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Present'
                $result.Name | Should -Be $mockParameters.Name
                $result.Path | Should -Be $mockParameters.Path
                $result.Description | Should -Be 'Test AD OU description'
                $result.ProtectedFromAccidentalDeletion | Should -BeFalse
                $result.DistinguishedName | Should -Be 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOrganizationalUnit -ParameterFilter {
                $SearchBase -eq 'OU=Fake,DC=contoso,DC=com'
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the OU has apostrophe' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                return @{
                    Name                            = "Jones's OU"
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $false
                    DistinguishedName               = "Jones's OU" + ',OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        It 'Should return the desired result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = "Jones's OU"
                    Path = 'OU=Fake,DC=contoso,DC=com'
                }

                $targetResource = Get-TargetResource @mockParameters

                $targetResource.Name | Should -Be "Jones's OU"
            }

            # Regression tests for issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/674.
            Should -Invoke -CommandName Get-ADOrganizationalUnit -ParameterFilter {
                $Filter -eq ('Name -eq "{0}"' -f "Jones's OU")
            }
        }
    }

    Context 'When the OU is protected' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $true
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        It 'Should return the desired result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'TestOU'
                    Path = 'OU=Fake,DC=contoso,DC=com'
                }

                $result = Get-TargetResource @mockParameters

                $result.ProtectedFromAccidentalDeletion | Should -BeTrue
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOrganizationalUnit -ParameterFilter {
                $SearchBase -eq 'OU=Fake,DC=contoso,DC=com'
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the "Credential" parameter is specified' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $false
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name       = 'TestOU'
                    Path       = 'OU=Fake,DC=contoso,DC=com'
                    Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                { Get-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOrganizationalUnit -ParameterFilter {
                $SearchBase -eq 'OU=Fake,DC=contoso,DC=com' -and
                $null -ne $Credential
            }  -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the "DomainController" parameter is specified' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $false
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name             = 'TestOU'
                    Path             = 'OU=Fake,DC=contoso,DC=com'
                    DomainController = 'TESTDC'
                }

                { Get-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOrganizationalUnit `
                -ParameterFilter { $SearchBase -eq 'OU=Fake,DC=contoso,DC=com' -and
                $Server -eq 'TESTDC'
            }  -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'TestOU'
                    Path = 'OU=Fake,DC=contoso,DC=com'
                }

                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Absent'
                $result.Name | Should -Be $mockParameters.Name
                $result.Path | Should -Be $mockParameters.Path
                $result.Description | Should -BeNullOrEmpty
                $result.ProtectedFromAccidentalDeletion | Should -BeNullOrEmpty
                $result.DistinguishedName | Should -BeNullOrEmpty
            }

            Should -Invoke -CommandName Assert-Module  -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOrganizationalUnit -ParameterFilter {
                $SearchBase -eq 'OU=Fake,DC=contoso,DC=com'
            }  -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the OU parent path does not exist' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new()
            }
        }

        It 'Returns the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'TestOU'
                    Path = 'OU=Fake,DC=contoso,DC=com'
                }

                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Absent'
                $result.ProtectedFromAccidentalDeletion | Should -BeNullOrEmpty
                $result.Description | Should -BeNullOrEmpty
                $result.DistinguishedName | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When "Get-ADOrganizationUnit" throws an unexpected error' {
        BeforeAll {
            Mock -CommandName Get-ADOrganizationalUnit -MockWith { throw 'error' }
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'TestOU'
                    Path = 'OU=Fake,DC=contoso,DC=com'
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.GetResourceError -f $mockParameters.Name)

                { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
            }
        }
    }
}

Describe 'MSFT_ADOrganizationalUnit\Test-TargetResource' -Tag 'Test' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $false
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    Ensure                          = 'Present'
                }
            }
        }

        Context 'When the Resource should be Present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'Description'
                        Value    = 'Changed Test AD OU description'
                    }
                    @{
                        Property = 'ProtectedFromAccidentalDeletion'
                        Value    = $true
                    }
                )
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        Ensure                          = 'Present'
                        ProtectedFromAccidentalDeletion = $false
                    }

                    { Test-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $Name -eq 'TestOU' -and
                    $Path -eq 'OU=Fake,DC=contoso,DC=com'
                }  -Exactly -Times 1 -Scope It
            }

            Context 'When the <Property> resource property is not in the desired state' -ForEach $testCases {
                It 'Should return $false' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            Ensure                          = 'Present'
                            ProtectedFromAccidentalDeletion = $false
                        }

                        $mockParameters.$Property = $Value

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }
                }
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            Ensure                          = 'Present'
                            ProtectedFromAccidentalDeletion = $false
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            # Regression test for issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/624.
            Context 'When parameter RestoreFromRecycleBin is specified' {
                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            RestoreFromRecycleBin           = $true
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        Ensure                          = 'Absent'
                        ProtectedFromAccidentalDeletion = $false
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $Name -eq 'TestOU' -and
                    $Path -eq 'OU=Fake,DC=contoso,DC=com'
                }  -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $true
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    Ensure                          = 'Absent'
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        Ensure                          = 'Present'
                        ProtectedFromAccidentalDeletion = $false
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $Name -eq 'TestOU' -and
                    $Path -eq 'OU=Fake,DC=contoso,DC=com'
                }  -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        Ensure                          = 'Absent'
                        ProtectedFromAccidentalDeletion = $false
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $Name -eq 'TestOU' -and
                    $Path -eq 'OU=Fake,DC=contoso,DC=com'
                }  -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADOrganizationalUnit\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName New-ADOrganizationalUnit
        Mock -CommandName Set-ADOrganizationalUnit
        Mock -CommandName Remove-ADOrganizationalUnit
        Mock -CommandName Restore-ADCommonObject
    }

    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $false
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    Ensure                          = 'Present'
                }
            }
        }

        BeforeDiscovery {
            $testCases = @(
                @{
                    Property = 'Description'
                    Value    = 'Changed Test AD OU description'
                }
                @{
                    Property = 'ProtectedFromAccidentalDeletion'
                    Value    = $true
                }
            )
        }

        Context 'When the Resource should be Present' {
            Context 'When <Property> has changed' -ForEach $testCases {
                It 'Should not throw' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                        }

                        $mockParameters.$Property = $Value

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $Name -eq 'TestOU'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter {
                        $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the "Credential" parameter is specified' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                            Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the "DomainController" parameter is specified' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                            DomainController                = 'TESTDC'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter { $Server -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When Set-ADOrganizationalUnit throws an exception' {
                BeforeAll {
                    Mock -CommandName Set-ADOrganizationalUnit -MockWith { throw }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.SetResourceError -f $mockParameters.Name)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $Name -eq 'TestOU'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter {
                        $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $Name -eq 'TestOU'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Remove-ADOrganizationalUnit -ParameterFilter {
                    $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
            }

            Context 'When the OrganizationalUnit is protected from deletion' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $true
                            DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                            Ensure                          = 'Present'
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Absent'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $Name -eq 'TestOU'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter {
                        $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com' -and
                        $ProtectedFromAccidentalDeletion -eq $false
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -ParameterFilter {
                        $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }

                Context 'When the "Credential" parameter is specified' {
                    It 'Should not throw' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'TestOU'
                                Path                            = 'OU=Fake,DC=contoso,DC=com'
                                Description                     = 'Test AD OU description'
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Absent'
                                Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                    'DummyUser',
                                    (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                                )
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                            $Name -eq 'TestOU'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter {
                            $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com' -and
                            $ProtectedFromAccidentalDeletion -eq $false -and
                            $null -ne $Credential
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Remove-ADOrganizationalUnit -ParameterFilter {
                            $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com' -and
                            $null -ne $Credential
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When the "DomainController" parameter is specified' {
                    It 'Should not throw' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'TestOU'
                                Path                            = 'OU=Fake,DC=contoso,DC=com'
                                Description                     = 'Test AD OU description'
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Absent'
                                DomainController                = 'TESTDC'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                            $Name -eq 'TestOU' -and
                            $DomainController -eq 'TESTDC'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter {
                            $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com' -and
                            $ProtectedFromAccidentalDeletion -eq $false -and
                            $Server -eq 'TESTDC'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Remove-ADOrganizationalUnit -ParameterFilter {
                            $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com' -and
                            $Server -eq 'TESTDC'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When Set-ADOrganizationalUnit throws an exception' {
                    BeforeAll {
                        Mock -CommandName Set-ADOrganizationalUnit -MockWith { throw 'error' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'TestOU'
                                Path                            = 'OU=Fake,DC=contoso,DC=com'
                                Description                     = 'Test AD OU description'
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Absent'
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.SetResourceError -f $mockParameters.Name)

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                            $Name -eq 'TestOU'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADOrganizationalUnit -ParameterFilter {
                            $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com' -and
                            $ProtectedFromAccidentalDeletion -eq $false
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When Remove-ADOrganizationalUnit throws an exception' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                            Ensure                          = 'Present'
                        }
                    }

                    Mock -CommandName Remove-ADOrganizationalUnit -MockWith { throw }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Absent'
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RemoveResourceError -f $mockParameters.Name)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $Name -eq 'TestOU'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -ParameterFilter {
                        $Identity -eq 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                            = 'TestOU'
                    Path                            = 'OU=Fake,DC=contoso,DC=com'
                    Description                     = 'Test AD OU description'
                    ProtectedFromAccidentalDeletion = $true
                    DistinguishedName               = 'OU=TestOU,OU=Fake,DC=contoso,DC=com'
                    Ensure                          = 'Absent'
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Present'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADOrganizationalUnit -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
            }

            Context 'When the "RestoreFromRecycleBin" parameter is specified' {
                BeforeAll {
                    Mock -CommandName Restore-ADCommonObject -MockWith { $true }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                            RestoreFromRecycleBin           = $true
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter { $Identity -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                }

                Context 'When the "Credential" parameter is specified' {
                    It 'Should not throw' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'TestOU'
                                Path                            = 'OU=Fake,DC=contoso,DC=com'
                                Description                     = 'Test AD OU description'
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Present'
                                RestoreFromRecycleBin           = $true
                                Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                    'DummyUser',
                                    (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                                )
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                            $Name -eq 'TestOU'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter {
                            $Identity -eq 'TestOU' -and
                            $null -ne $Credential
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When the "DomainController" parameter is specified' {
                    It 'Should not throw' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'TestOU'
                                Path                            = 'OU=Fake,DC=contoso,DC=com'
                                Description                     = 'Test AD OU description'
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Present'
                                RestoreFromRecycleBin           = $true
                                DomainController                = 'TESTDC'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                            $Name -eq 'TestOU'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter {
                            $Identity -eq 'TestOU' -and
                            $Server -eq 'TESTDC'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When Restore from Recycle Bin was unsuccessful' {
                    BeforeAll {
                        Mock -CommandName Restore-ADCommonObject -MockWith { $false }
                    }

                    It 'Should not throw' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                            = 'TestOU'
                                Path                            = 'OU=Fake,DC=contoso,DC=com'
                                Description                     = 'Test AD OU description'
                                ProtectedFromAccidentalDeletion = $false
                                Ensure                          = 'Present'
                                RestoreFromRecycleBin           = $true
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter { $Identity -eq 'TestOU' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName New-ADOrganizationalUnit -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When the "Credential" parameter is specified' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                            Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADOrganizationalUnit -ParameterFilter {
                        $Name -eq 'TestOU' -and
                        $null -ne $Credential
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the "DomainController" parameter is specified' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                            DomainController                = 'TESTDC'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADOrganizationalUnit -ParameterFilter {
                        $Name -eq 'TestOU' -and
                        $Server -eq 'TESTDC'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When New-ADOrganizationalUnit throws ADIdentityNotFoundException' {
                BeforeAll {
                    Mock -CommandName New-ADOrganizationalUnit -MockWith { throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new() }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message $($script:localizedData.PathNotFoundError -f $mockParameters.Path)


                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADOrganizationalUnit -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When New-ADOrganizationalUnit throws an unexpected exception' {
                BeforeAll {
                    Mock -CommandName New-ADOrganizationalUnit -MockWith { throw }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                            = 'TestOU'
                            Path                            = 'OU=Fake,DC=contoso,DC=com'
                            Description                     = 'Test AD OU description'
                            ProtectedFromAccidentalDeletion = $false
                            Ensure                          = 'Present'
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.NewResourceError -f $mockParameters.Name)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADOrganizationalUnit -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                            = 'TestOU'
                        Path                            = 'OU=Fake,DC=contoso,DC=com'
                        Description                     = 'Test AD OU description'
                        ProtectedFromAccidentalDeletion = $false
                        Ensure                          = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'TestOU' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
            }
        }
    }
}
