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
    $script:dscResourceName = 'MSFT_ADObjectEnabledState'

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

$mockComputerNamePresent = 'TEST01'
$mockDomain = 'contoso.com'
$mockEnabled = $true
$mockDisabled = $false
$mockObjectClass_Computer = 'Computer'
$mockDomainController = 'DC01'

$mockCredentialUserName = 'COMPANY\User'
$mockCredentialPassword = ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
$mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
    'COMPANY\User',
    ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
)

Describe 'MSFT_ADObjectEnabledState\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the system is not in the desired state' {
        Context 'When the Get-ADComputer throws an unknown error' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    throw 'Mocked error'
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.FailedToRetrieveComputerAccount -f $mockParameters.Identity)

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }

                Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account is absent in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.FailedToRetrieveComputerAccount -f $mockParameters.Identity)

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }

                Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is in the desired state' {
        Context 'When the computer account is present in Active Directory' {
            Context 'When the computer account is enabled' {
                BeforeAll {
                    Mock -CommandName Get-ADComputer -MockWith {
                        return @{
                            CN          = 'TEST01'
                            Enabled     = $true
                            ObjectClass = 'Computer'
                        }
                    }
                }

                It 'Should return the correct result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Identity         = 'TEST01'
                            ObjectClass      = 'Computer'
                            DomainController = 'DC01'
                            Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'COMPANY\User',
                                ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                            )
                            Enabled          = $false
                        }

                        $result = Get-TargetResource @mockParameters

                        $result.Enabled | Should -BeTrue
                        $result.Identity | Should -Be $mockParameters.Identity
                        $result.ObjectClass | Should -Be $mockParameters.ObjectClass
                        $result.DomainController | Should -Be $mockParameters.DomainController
                        $result.Credential.UserName | Should -Be $mockParameters.Credential.UserName
                    }

                    Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the computer account is disabled' {
                BeforeAll {
                    Mock -CommandName Get-ADComputer -MockWith {
                        return @{
                            CN          = 'TEST01'
                            Enabled     = $false
                            ObjectClass = 'Computer'
                        }
                    }
                }

                It 'Should return the correct result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Identity         = 'TEST01'
                            ObjectClass      = 'Computer'
                            DomainController = 'DC01'
                            Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'COMPANY\User',
                                ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                            )
                            Enabled          = $true
                        }

                        $result = Get-TargetResource @mockParameters

                        $result.Enabled | Should -BeFalse
                        $result.Identity | Should -Be $mockParameters.Identity
                        $result.ObjectClass | Should -Be $mockParameters.ObjectClass
                        $result.DomainController | Should -Be $mockParameters.DomainController
                        $result.Credential.UserName | Should -Be $mockParameters.Credential.UserName
                    }

                    Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When Get-TargetResource is called with only mandatory parameters' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    return @{
                        CN          = 'TEST01'
                        Enabled     = $true
                        ObjectClass = 'Computer'
                    }
                }
            }

            It 'Should only call Get-ADComputer with only Identity parameter' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }

                    Get-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Get-ADComputer -ParameterFilter {
                    $PesterBoundParameters.ContainsKey('Identity') -and -not
                    $PesterBoundParameters.ContainsKey('Server') -and -not
                    $PesterBoundParameters.ContainsKey('Credential')
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When Get-TargetResource is called with DomainController parameter' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    return @{
                        CN          = 'TEST01'
                        Enabled     = $true
                        ObjectClass = 'Computer'
                    }
                }
            }

            It 'Should only call Get-ADComputer with Identity and Server parameter' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity         = 'TEST01'
                        ObjectClass      = 'Computer'
                        Enabled          = $false
                        DomainController = 'DC01'
                    }

                    Get-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Get-ADComputer -ParameterFilter {
                    $PesterBoundParameters.ContainsKey('Identity') -and
                    $PesterBoundParameters.ContainsKey('Server') -and -not
                    $PesterBoundParameters.ContainsKey('Credential')
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When Get-TargetResource is called with Credential parameter' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    return @{
                        CN          = 'TEST01'
                        Enabled     = $true
                        ObjectClass = 'Computer'
                    }
                }
            }

            It 'Should only call Get-ADComputer with Identity and Credential parameter' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                        Credential  = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }

                    Get-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Get-ADComputer -ParameterFilter {
                    $PesterBoundParameters.ContainsKey('Identity') -and -not
                    $PesterBoundParameters.ContainsKey('Server') -and
                    $PesterBoundParameters.ContainsKey('Credential')
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADObjectEnabledState\Test-TargetResource' -Tag 'Test' {
    Context 'When the system is in the desired state' {
        Context 'When the computer account is disabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Get-TargetResource {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $false
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account is enabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $true
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $true
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the computer account should be enabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Get-TargetResource {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $false
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $true
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account should be disabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $true
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADObjectEnabledState\Set-TargetResource' -Tag 'Set' {
    Context 'When the system is in the desired state' {
        Context 'When the computer account is enabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Set-ADComputer
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $true
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should not call any mocks that changes state' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $true
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the computer account is disabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Set-ADComputer
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $false
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should not call any mocks that changes state' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the computer account should be enabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Set-ADComputer
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $false
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $true
                    }
                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Set-ADComputer -ParameterFilter {
                    $Enabled -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account should be disabled in Active Directory' {
            BeforeAll {
                Mock -CommandName Assert-Module
                Mock -CommandName Set-ADComputer
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Identity         = $null
                        ObjectClass      = 'Computer'
                        Enabled          = $true
                        DomainController = 'DC01'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User',
                            ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Identity    = 'TEST01'
                        ObjectClass = 'Computer'
                        Enabled     = $false
                    }
                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Set-ADComputer -ParameterFilter {
                    $Enabled -eq $false
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}
