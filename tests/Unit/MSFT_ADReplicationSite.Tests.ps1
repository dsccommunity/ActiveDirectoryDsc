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
    $script:dscResourceName = 'MSFT_ADReplicationSite'

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

Describe 'MSFT_ADReplicationSite\Get-TargetResource' -Tag 'Get' {
    Context 'When the resource exists' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite -MockWith {
                @{
                    Name              = 'DemoSite'
                    DistinguishedName = 'CN=DemoSite,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Demonstration Site Description'
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-TargetResource -Name 'DemoSite'

                $result | Should -BeOfType [System.Collections.Hashtable]
                $result.Name | Should -Be 'DemoSite'
                $result.Description | Should -Be 'Demonstration Site Description'
                $result.Ensure | Should -Be 'Present'
            }
        }
    }

    Context 'When the resource does not exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite
        }

        It 'Should return absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-TargetResource -Name 'MissingSite'

                $result.Ensure | Should -Be 'Absent'
                $result.Name | Should -Be 'MissingSite'
                $result.Description | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'MSFT_ADReplicationSite\Test-TargetResource' -Tag 'Test' {
    Context 'When a resource exists' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite -MockWith {
                @{
                    Name              = 'DemoSite'
                    DistinguishedName = 'CN=DemoSite,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    Description       = 'Demonstration Site Description'
                }
            }
        }

        Context 'When the resource is in the desired state' {
            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Ensure      = 'Present'
                        Name        = 'DemoSite'
                        Description = 'Demonstration Site Description'
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
                        Ensure      = 'Absent'
                        Name        = 'DemoSite'
                        Description = 'Demonstration Site Description'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }
            }
        }
    }

    Context 'When a resource does not exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite
        }

        Context 'When the resource is in the desired state' {
            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Ensure      = 'Absent'
                        Name        = 'DemoSite'
                        Description = 'Demonstration Site Description'
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
                        Ensure      = 'Present'
                        Name        = 'MissingSite'
                        Description = 'Demonstration Site Description'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }
            }
        }
    }
}


Describe 'MSFT_ADReplicationSite\Set-TargetResource' -Tag 'Set' {
    Context 'When a site is missing' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite
            Mock -CommandName New-ADReplicationSite
            Mock -CommandName Set-ADReplicationSite
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure      = 'Absent'
                    Name        = 'DemoSite'
                    Description = 'Demonstration Site Description'
                }
            }
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Ensure      = 'Present'
                    Name        = 'DemoSite'
                    Description = 'Demonstration Site Description'
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName New-ADReplicationSite -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the Default-First-Site-Name exists and should be renamed' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure                     = 'Absent'
                    Name                       = 'DemoSite'
                    Description                = $null
                    RenameDefaultFirstSiteName = $true
                }
            }

            Mock -CommandName Get-ADReplicationSite -MockWith {
                [PSCustomObject] @{
                    Name              = 'Default-First-Site-Name'
                    DistinguishedName = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                }
            }

            Mock -CommandName Rename-ADObject
            Mock -CommandName New-ADReplicationSite
            Mock -CommandName Set-ADReplicationSite
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Ensure                     = 'Present'
                    Name                       = 'DemoSite'
                    Description                = 'Demonstration Site Description'
                    RenameDefaultFirstSiteName = $true
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName New-ADReplicationSite -Exactly -Times 0 -Scope It
        }
    }

    Context 'When the Default-First-Site-Name does not exist' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure      = 'Absent'
                    Name        = 'DemoSite'
                    Description = $null
                }
            }

            Mock -CommandName Get-ADReplicationSite
            Mock -CommandName Rename-ADObject
            Mock -CommandName New-ADReplicationSite
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Ensure      = 'Present'
                    Name        = 'DemoSite'
                    Description = 'Demonstration Site Description'
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName New-ADReplicationSite -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the site description does not match' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure      = 'Present'
                    Name        = 'DemoSite'
                    Description = $null
                }
            }

            Mock -CommandName Set-ADReplicationSite
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Ensure      = 'Present'
                    Name        = 'DemoSite'
                    Description = 'Some random test description'
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Set-ADReplicationSite -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the site should be removed' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Ensure      = 'Present'
                    Name        = 'DemoSite'
                    Description = 'Demonstration Site Description'
                }
            }

            Mock -CommandName Remove-ADReplicationSite
        }

        It 'Should call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Ensure      = 'Absent'
                    Name        = 'DemoSite'
                    Description = 'Demonstration Site Description'
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Remove-ADReplicationSite -Exactly -Times 1 -Scope It
        }
    }
}
