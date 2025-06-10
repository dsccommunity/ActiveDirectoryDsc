
# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
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
    $script:dscResourceName = 'MSFT_ADReplicationSubnet'

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

Describe 'MSFT_ADReplicationSubnet\Get-TargetResource' -Tag 'Get' {
    Context 'When subnet does not exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSubnet
        }

        It 'Should return absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name = '10.0.0.0/8'
                    Site = 'Default-First-Site-Name'
                }

                $result = Get-TargetResource @testDefaultParameters

                $result.Ensure | Should -Be 'Absent'
                $result.Name | Should -Be $testDefaultParameters.Name
                $result.Site | Should -Be ''
                $result.Location | Should -BeNullOrEmpty
                $result.Description | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When subnet does exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSubnet -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'Seattle'
                    Site              = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Default First Site Description'
                }
            }
            Mock -CommandName Get-ADObject -MockWith {
                [PSCustomObject] @{
                    Name = 'Default-First-Site-Name'
                }
            }
        }

        It 'Should return present with the correct subnet' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name = '10.0.0.0/8'
                    Site = 'Default-First-Site-Name'
                }

                $result = Get-TargetResource @testDefaultParameters

                $result.Ensure | Should -Be 'Present'
                $result.Name | Should -Be $testDefaultParameters.Name
                $result.Site | Should -Be 'Default-First-Site-Name'
                $result.Location | Should -Be 'Seattle'
                $result.Description | Should -Be 'Default First Site Description'
            }
        }
    }

    Context 'When subnet does exist, but site is empty' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSubnet -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'Seattle'
                    Site              = $null
                }
            }
        }

        It 'Should return present with the correct subnet' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name = '10.0.0.0/8'
                    Site = 'Default-First-Site-Name'
                }

                $result = Get-TargetResource @testDefaultParameters

                $result.Ensure | Should -Be 'Present'
                $result.Name | Should -Be $testDefaultParameters.Name
                $result.Site | Should -Be ''
                $result.Location | Should -Be 'Seattle'
            }
        }
    }
}

Describe 'MSFT_ADReplicationSubnet\Test-TargetResource' -Tag 'Test' {
    Context 'When the subnet does not exist' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure      = 'Absent'
                    Name        = '10.0.0.0/8'
                    Site        = ''
                    Location    = $null
                    Description = $null
                }
            }
        }

        It 'Should return false for present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                }

                $result = Test-TargetResource -Ensure 'Present' @testDefaultParameters
                $result | Should -BeFalse
            }
        }

        It 'Should return true for absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                }

                $result = Test-TargetResource -Ensure 'Absent' @testDefaultParameters
                $result | Should -BeTrue
            }
        }
    }

    Context 'When the subnet does exist' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure      = 'Present'
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                }
            }
        }

        It 'Should return true for present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                    Ensure      = 'Present'
                }

                Test-TargetResource @testDefaultParameters | Should -BeTrue
            }
        }

        It 'Should return false for absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                    Ensure      = 'Absent'
                }

                Test-TargetResource @testDefaultParameters | Should -BeFalse
            }
        }

        It 'Should return false for wrong site' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'WrongSite'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                    Ensure      = 'Present'
                }

                Test-TargetResource @testDefaultParameters | Should -BeFalse
            }
        }

        It 'Should return false for wrong location' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'WrongLocation'
                    Description = 'Default First Site Description'
                    Ensure      = 'Present'
                }

                Test-TargetResource @testDefaultParameters | Should -BeFalse
            }
        }

        It 'Should return false for wrong Description' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Test description mismatch'
                    Ensure      = 'Present'
                }

                Test-TargetResource @testDefaultParameters | Should -BeFalse
            }
        }

        It 'Should return true for matching Description' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                    Ensure      = 'Present'
                }

                Test-TargetResource @testDefaultParameters | Should -BeTrue
            }
        }
    }
}

Describe 'MSFT_ADReplicationSubnet\Set-TargetResource' -Tag 'Set' {
    Context 'When subnet does not exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSubnet
            Mock -CommandName Get-ADObject -MockWith {
                [PSCustomObject] @{
                    Name = 'Default-First-Site-Name'
                }
            }

            Mock -CommandName New-ADReplicationSubnet -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'Seattle'
                    Site              = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Default First Site Description'
                }
            }
        }

        It 'Should create the subnet' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParameters = @{
                    Ensure      = 'Present'
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                }

                { Set-TargetResource @testPresentParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName New-ADReplicationSubnet -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the subnet does exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSubnet -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'Seattle'
                    Site              = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Default First Site Description'
                }
            }

            Mock -CommandName Get-ADObject -MockWith {
                [PSCustomObject] @{
                    Name = 'Default-First-Site-Name'
                }
            }

            Mock -CommandName Set-ADReplicationSubnet -ParameterFilter { $Site -ne $null } -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'Seattle'
                    Site              = 'CN=OtherSite,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Default First Site Description'
                }
            }

            Mock -CommandName Set-ADReplicationSubnet -ParameterFilter { $Location -eq 'OtherLocation' } -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'OtherLocation'
                    Site              = 'CN=OtherSite,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Default First Site Description'
                }
            }

            Mock -CommandName Set-ADReplicationSubnet -ParameterFilter { $Location -eq $null } -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = $null
                    Site              = 'CN=OtherSite,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Default First Site Description'
                }
            }

            Mock -CommandName Set-ADReplicationSubnet -ParameterFilter { $Description -eq 'Test Description' } -MockWith {
                [PSCustomObject] @{
                    DistinguishedName = 'CN=10.0.0.0/8,CN=Subnets,CN=Sites,CN=Configuration,DC=arcade,DC=local'
                    Name              = '10.0.0.0/8'
                    Location          = 'OtherLocation'
                    Site              = 'CN=OtherSite,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Test Description'
                }
            }

            Mock -CommandName Remove-ADReplicationSubnet
        }

        It 'Should update the subnet site' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParameters = @{
                    Ensure      = 'Present'
                    Name        = '10.0.0.0/8'
                    Site        = 'OtherSite'
                    Location    = 'Seattle'
                    Description = 'Default First Site Description'
                }

                { Set-TargetResource @testPresentParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADReplicationSubnet -ParameterFilter { $Site -ne $null } -Exactly -Times 1 -Scope It
        }

        It 'Should update the subnet location' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParameters = @{
                    Ensure      = 'Present'
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'OtherLocation'
                    Description = 'Default First Site Description'
                }

                { Set-TargetResource @testPresentParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADReplicationSubnet -ParameterFilter { $Location -eq 'OtherLocation' } -Exactly -Times 1 -Scope It
        }

        It 'Should update the subnet location to $null when an empty string is passed' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParameters = @{
                    Ensure      = 'Present'
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = ''
                    Description = 'Default First Site Description'
                }

                { Set-TargetResource @testPresentParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADReplicationSubnet -ParameterFilter { $Location -eq $null } -Exactly -Times 1 -Scope It
        }

        It 'Should update the subnet description' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testPresentParameters = @{
                    Ensure      = 'Present'
                    Name        = '10.0.0.0/8'
                    Site        = 'Default-First-Site-Name'
                    Location    = 'Seattle'
                    Description = 'Test description fail'
                }

                { Set-TargetResource @testPresentParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Set-ADReplicationSubnet -ParameterFilter { $Description -eq 'Test description fail' } -Exactly -Times 1 -Scope It
        }

        It 'Should remove the subnet' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testAbsentParameters = @{
                    Ensure = 'Absent'
                    Name   = '10.0.0.0/8'
                    Site   = 'Default-First-Site-Name'
                }

                { Set-TargetResource @testAbsentParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Remove-ADReplicationSubnet -Exactly -Times 1 -Scope It
        }
    }
}
