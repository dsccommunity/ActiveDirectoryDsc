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
    $script:dscResourceName = 'MSFT_ADComputer'

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

Describe 'MSFT_ADComputer\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the Get-ADComputer throws an unhandled error' {
        BeforeAll {
            Mock -CommandName Get-ADComputer -MockWith { throw }
        }

        It 'Should return the state as absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $getParameters = @{
                    ComputerName = 'TEST01'
                }

                $errorMessage = Get-InvalidOperationRecord -Message ($script:localizedData.FailedToRetrieveComputerAccount -f $getParameters.ComputerName)

                { Get-TargetResource @getParameters } | Should -Throw -ExpectedMessage $errorMessage.Message
            }

            Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is in the desired state' {
        Context 'When the computer account is absent in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        ComputerName          = 'TEST01'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                    }

                    $result = Get-TargetResource @getParameters

                    $result.Ensure | Should -Be 'Absent'
                    $result.DomainController | Should -Be $getParameters.DomainController
                    $result.Credential.UserName | Should -Be $getParameters.Credential.UserName
                    $result.RequestFile | Should -Be $getParameters.RequestFile
                    $result.RestoreFromRecycleBin | Should -Be $getParameters.RestoreFromRecycleBin
                    $result.EnabledOnCreation | Should -Be $getParameters.EnabledOnCreation
                    $result.ComputerName | Should -BeNullOrEmpty
                    $result.Location | Should -BeNullOrEmpty
                    $result.DnsHostName | Should -BeNullOrEmpty
                    $result.ServicePrincipalNames | Should -BeNullOrEmpty
                    $result.UserPrincipalName | Should -BeNullOrEmpty
                    $result.DisplayName | Should -BeNullOrEmpty
                    $result.Path | Should -BeNullOrEmpty
                    $result.Description | Should -BeNullOrEmpty
                    $result.Enabled | Should -BeFalse
                    $result.Manager | Should -BeFalse
                    $result.DistinguishedName | Should -BeNullOrEmpty
                    $result.SID | Should -BeNullOrEmpty
                    $result.SamAccountName | Should -BeNullOrEmpty
                }

                Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account is present in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    return @{
                        CN                    = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b') + @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Description           = 'Test description'
                        Enabled               = $true
                        ManagedBy             = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SamAccountName        = 'TEST01$'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        ObjectClass           = 'Computer'
                    }
                }
            }

            It 'Should return the state as present' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        ComputerName          = 'TEST01'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                    }

                    $result = Get-TargetResource @getParameters
                    $result.Ensure | Should -Be 'Present'
                    $result.DomainController | Should -Be $getParameters.DomainController
                    $result.Credential.UserName | Should -Be $getParameters.Credential.UserName
                    $result.RequestFile | Should -Be $getParameters.RequestFile
                    $result.RestoreFromRecycleBin | Should -Be $getParameters.RestoreFromRecycleBin
                    $result.EnabledOnCreation | Should -Be $getParameters.EnabledOnCreation
                    $result.ComputerName | Should -Be 'TEST01'
                    $result.Location | Should -Be 'Test location'
                    $result.DnsHostName | Should -Be 'TEST01.contoso.com'
                    $result.ServicePrincipalNames | Should -Be (@('spn/a', 'spn/b') + @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com'))
                    $result.UserPrincipalName | Should -Be 'TEST01@contoso.com'
                    $result.DisplayName | Should -Be 'TEST01'
                    $result.Path | Should -Be 'CN=Computers,DC=contoso,DC=com'
                    $result.Description | Should -Be 'Test description'
                    $result.Enabled | Should -BeTrue
                    $result.Manager | Should -Be 'CN=Manager,CN=Users,DC=contoso,DC=com'
                    $result.DistinguishedName | Should -Be 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                    $result.SID | Should -Be 'S-1-5-21-1409167834-891301383-2860967316-1143'
                    $result.SamAccountName | Should -Be 'TEST01$'
                }

                Should -Invoke -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
            }
        }

        Context 'When Get-TargetResource is called with only mandatory parameters' {
            BeforeAll {
                Mock -CommandName Get-ADComputer -MockWith {
                    return @{
                        CN                    = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b') + @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Description           = 'Test description'
                        Enabled               = $true
                        ManagedBy             = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SamAccountName        = 'TEST01$'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        ObjectClass           = 'Computer'
                    }
                }
            }

            It 'Should only call Get-ADComputer with only Identity parameter' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        ComputerName = 'TEST01'
                    }

                    $result = Get-TargetResource @getParameters
                    $result.Ensure | Should -Be 'Present'
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
                        CN                    = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b') + @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Description           = 'Test description'
                        Enabled               = $true
                        ManagedBy             = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SamAccountName        = 'TEST01$'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        ObjectClass           = 'Computer'
                    }
                }
            }

            It 'Should only call Get-ADComputer with Identity and Server parameter' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        ComputerName     = 'TEST01'
                        DomainController = 'DC01'
                    }

                    $result = Get-TargetResource @getParameters
                    $result.Ensure | Should -Be 'Present'
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
                        CN                    = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b') + @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Description           = 'Test description'
                        Enabled               = $true
                        ManagedBy             = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SamAccountName        = 'TEST01$'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        ObjectClass           = 'Computer'
                    }
                }
            }

            It 'Should only call Get-ADComputer with Identity and Credential parameter' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        ComputerName = 'TEST01'
                        Credential   = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                    }

                    $result = Get-TargetResource @getParameters
                    $result.Ensure | Should -Be 'Present'
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

Describe 'MSFT_ADComputer\Test-TargetResource' -Tag 'Test' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the system is in the desired state' {
        Context 'When the computer account is absent in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource {
                    return @{
                        Ensure                = 'Absent'
                        ComputerName          = $null
                        Location              = $null
                        DnsHostName           = $null
                        ServicePrincipalNames = $null
                        UserPrincipalName     = $null
                        DisplayName           = $null
                        Path                  = $null
                        Description           = $null
                        Enabled               = $false
                        Manager               = $null
                        DomainController      = $null
                        Credential            = $null
                        RequestFile           = $null
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = $null
                        SID                   = $null
                        SamAccountName        = $null
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testParameters = @{
                        Ensure       = 'Absent'
                        ComputerName = 'TEST01'
                    }

                    $result = Test-TargetResource @testParameters
                    $result | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account is present in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testParameters = @{
                        ComputerName          = 'TEST01'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                    }

                    $result = Test-TargetResource @testParameters
                    $result | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When service principal names are in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testParameters = @{
                        ComputerName          = 'TEST01'
                        ServicePrincipalNames = @('spn/a', 'spn/b')
                    }

                    $result = Test-TargetResource @testParameters
                    $result | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the computer account is absent in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Absent'
                        ComputerName          = $null
                        Location              = $null
                        DnsHostName           = $null
                        ServicePrincipalNames = $null
                        UserPrincipalName     = $null
                        DisplayName           = $null
                        Path                  = $null
                        Description           = $null
                        Enabled               = $false
                        Manager               = $null
                        DomainController      = $null
                        Credential            = $null
                        RequestFile           = $null
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = $null
                        SID                   = $null
                        SamAccountName        = $null
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testParameters = @{
                        Ensure       = 'Present'
                        ComputerName = 'TEST01'
                    }

                    $result = Test-TargetResource @testParameters
                    $result | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the computer account is present in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testParameters = @{
                        Ensure       = 'Absent'
                        ComputerName = 'TEST01'
                    }
                    $result = Test-TargetResource @testParameters
                    $result | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When a property is not in desired state' {
            BeforeAll {
                # Mock a specific desired state.
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('spn/a', 'spn/b')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            Context 'When a property should be set to a new non-empty value' {
                BeforeDiscovery {
                    # One test case per property with a value that differs from the desired state.
                    $testCases = @(
                        @{
                            ParameterName = 'Location'
                            Value         = 'NewLocation'
                        },
                        @{
                            ParameterName = 'DnsHostName'
                            Value         = 'New@contoso.com'
                        },
                        @{
                            ParameterName = 'ServicePrincipalNames'
                            Value         = @('spn/new')
                        },
                        @{
                            ParameterName = 'UserPrincipalName'
                            Value         = 'New@contoso.com'
                        },
                        @{
                            ParameterName = 'DisplayName'
                            Value         = 'New'
                        },
                        @{
                            ParameterName = 'Path'
                            Value         = 'OU=New,CN=Computers,DC=contoso,DC=com'
                        },
                        @{
                            ParameterName = 'Description'
                            Value         = 'New description'
                        },
                        @{
                            ParameterName = 'Manager'
                            Value         = 'CN=NewManager,CN=Users,DC=contoso,DC=com'
                        }
                    )
                }

                It 'Should return $false when non-empty property <ParameterName> is not in desired state' -TestCases $testCases {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testParameters = @{
                            ComputerName   = 'TEST01'
                            $ParameterName = $Value
                        }

                        $result = Test-TargetResource @testParameters
                        $result | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                }
            }

            Context 'When a property should be set to an empty value' {
                BeforeDiscovery {
                    $testCases = @(
                        @{
                            ParameterName = 'Location'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'DnsHostName'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'ServicePrincipalNames'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'ServicePrincipalNames'
                            Value         = @()
                        },
                        @{
                            ParameterName = 'UserPrincipalName'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'DisplayName'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'Path'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'Description'
                            Value         = ''
                        },
                        @{
                            ParameterName = 'Manager'
                            Value         = ''
                        }
                    )
                }

                It 'Should return $false when empty property <ParameterName> is not in desired state' -TestCases $testCases {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testParameters = @{
                            ComputerName   = 'TEST01'
                            $ParameterName = $Value
                        }

                        $result = Test-TargetResource @testParameters
                        $result | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                }
            }
        }
    }
}

Describe 'MSFT_ADComputer\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Remove-ADComputer
            Mock -CommandName Set-ADComputer
            Mock -CommandName New-ADComputer
            Mock -CommandName Move-ADObject
        }

        Context 'When the computer account is absent in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Absent'
                        ComputerName          = $null
                        Location              = $null
                        DnsHostName           = $null
                        ServicePrincipalNames = $null
                        UserPrincipalName     = $null
                        DisplayName           = $null
                        Path                  = $null
                        Description           = $null
                        Enabled               = $false
                        Manager               = $null
                        DomainController      = $null
                        Credential            = $null
                        RequestFile           = $null
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = $null
                        SID                   = $null
                        SamAccountName        = $null
                    }
                }
            }

            It 'Should not call any mocks that changes state' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        Ensure       = 'Absent'
                        ComputerName = 'TEST01'
                    }

                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the computer account is present in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            It 'Should not call any mocks that changes state' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        ComputerName          = 'TEST01'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                    }

                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When service principal names are in desired state' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            It 'Should not call any mocks that changes state' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        ComputerName          = 'TEST01'
                        ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                    }
                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Remove-ADComputer
            Mock -CommandName Set-ADComputer
            Mock -CommandName Move-ADObject
            Mock -CommandName New-ADComputer -MockWith {
                $script:mockNewADComputerWasCalled = $true
            }
        }

        Context 'When the computer account is absent from Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    if (-not $script:mockNewADComputerWasCalled)
                    {
                        # First call.
                        $mockGetTargetResourceResult = & {
                            return @{
                                Ensure                = 'Absent'
                                ComputerName          = $null
                                Location              = $null
                                DnsHostName           = $null
                                ServicePrincipalNames = $null
                                UserPrincipalName     = $null
                                DisplayName           = $null
                                Path                  = $null
                                Description           = $null
                                Enabled               = $false
                                Manager               = $null
                                DomainController      = $null
                                Credential            = $null
                                RequestFile           = $null
                                RestoreFromRecycleBin = $false
                                EnabledOnCreation     = $false
                                DistinguishedName     = $null
                                SID                   = $null
                                SamAccountName        = $null
                            }
                        }
                    }
                    else
                    {
                        # Second call - After New-ADComputer has been called.
                        $mockGetTargetResourceResult = & {
                            return @{
                                Ensure                = 'Present'
                                ComputerName          = 'TEST01'
                                Location              = 'Test location'
                                DnsHostName           = 'TEST01.contoso.com'
                                ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                                UserPrincipalName     = 'TEST01@contoso.com'
                                DisplayName           = 'TEST01'
                                Path                  = 'CN=Computers,DC=contoso,DC=com'
                                Description           = 'Test description'
                                Enabled               = $true
                                Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                                DomainController      = 'DC01'
                                Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                    'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                                )
                                RequestFile           = 'TestDrive:\ODJ.txt'
                                RestoreFromRecycleBin = $false
                                EnabledOnCreation     = $false
                                DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                                SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                                SamAccountName        = 'TEST01$'
                            }
                        }
                    }

                    return $mockGetTargetResourceResult
                }
            }

            BeforeEach {
                $script:mockNewADComputerWasCalled = $false
            }

            Context 'When the computer account is created on the default path' {
                It 'Should call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            Ensure       = 'Present'
                            ComputerName = 'TEST01'
                        }

                        { Set-TargetResource @setParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the computer account is created on the specified path' {
                It 'Should call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            Ensure       = 'Present'
                            ComputerName = 'TEST01'
                            Path         = 'CN=Computers,DC=contoso,DC=com'
                        }

                        { Set-TargetResource @setParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the computer account is present in Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        Ensure       = 'Absent'
                        ComputerName = 'TEST01'
                    }

                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the computer account should be force to be created enabled' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Absent'
                        ComputerName          = $null
                        Location              = $null
                        DnsHostName           = $null
                        ServicePrincipalNames = $null
                        UserPrincipalName     = $null
                        DisplayName           = $null
                        Path                  = $null
                        Description           = $null
                        Enabled               = $false
                        Manager               = $null
                        DomainController      = $null
                        Credential            = $null
                        RequestFile           = $null
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = $null
                        SID                   = $null
                        SamAccountName        = $null
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        ComputerName      = 'TEST01'
                        EnabledOnCreation = $true
                    }

                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -ParameterFilter {
                    $PesterBoundParameters.ContainsKey('Enabled') -and
                    $Enabled -eq $true
                } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the computer account should be force to be created disabled' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Absent'
                        ComputerName          = $null
                        Location              = $null
                        DnsHostName           = $null
                        ServicePrincipalNames = $null
                        UserPrincipalName     = $null
                        DisplayName           = $null
                        Path                  = $null
                        Description           = $null
                        Enabled               = $false
                        Manager               = $null
                        DomainController      = $null
                        Credential            = $null
                        RequestFile           = $null
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = $null
                        SID                   = $null
                        SamAccountName        = $null
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        ComputerName      = 'TEST01'
                        EnabledOnCreation = $false
                    }

                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -ParameterFilter {
                    $PesterBoundParameters.ContainsKey('Enabled') -and
                    $Enabled -eq $false
                } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the computer account should be created using offline domain join (ODJ) request file' {
            BeforeAll {
                Mock -CommandName Wait-Process
                Mock -CommandName Get-TargetResource -MockWith {
                    if (-not $script:mockSuccessDomainJoin)
                    {
                        # First call.
                        $mockGetTargetResourceResult = & {
                            return @{
                                Ensure                = 'Absent'
                                ComputerName          = $null
                                Location              = $null
                                DnsHostName           = $null
                                ServicePrincipalNames = $null
                                UserPrincipalName     = $null
                                DisplayName           = $null
                                Path                  = $null
                                Description           = $null
                                Enabled               = $false
                                Manager               = $null
                                DomainController      = $null
                                Credential            = $null
                                RequestFile           = $null
                                RestoreFromRecycleBin = $false
                                EnabledOnCreation     = $false
                                DistinguishedName     = $null
                                SID                   = $null
                                SamAccountName        = $null
                            }
                        }
                    }
                    else
                    {
                        <#
                            Second call - After Offline Domain Join request file has been
                            created and the computer account has been provisioned.
                        #>
                        $mockGetTargetResourceResult = & {
                            return @{
                                Ensure                = 'Present'
                                ComputerName          = 'TEST01'
                                Location              = 'Test location'
                                DnsHostName           = 'TEST01.contoso.com'
                                ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                                UserPrincipalName     = 'TEST01@contoso.com'
                                DisplayName           = 'TEST01'
                                Path                  = 'CN=Computers,DC=contoso,DC=com'
                                Description           = 'Test description'
                                Enabled               = $true
                                Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                                DomainController      = 'DC01'
                                Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                    'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                                )
                                RequestFile           = 'TestDrive:\ODJ.txt'
                                RestoreFromRecycleBin = $false
                                EnabledOnCreation     = $false
                                DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                                SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                                SamAccountName        = 'TEST01$'
                            }
                        }
                    }

                    return $mockGetTargetResourceResult
                }

                Mock -CommandName Get-DomainName -MockWith {
                    return 'contoso.com'
                }

                Mock -CommandName Start-ProcessWithTimeout -MockWith {
                    $script:mockSuccessDomainJoin = $true

                    return 0
                }
            }

            BeforeEach {
                $script:mockSuccessDomainJoin = $false
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        ComputerName     = 'TEST01'
                        Path             = 'CN=Computers,DC=contoso,DC=com'
                        DomainController = 'dc01.contoso.com'
                        RequestFile      = 'c:\ODJTest.txt'
                    }

                    { Set-TargetResource @setParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Start-ProcessWithTimeout -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When an offline domain join (ODJ) request file fails to be created' {
            BeforeAll {
                Mock -CommandName Wait-Process
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Absent'
                        ComputerName          = $null
                        Location              = $null
                        DnsHostName           = $null
                        ServicePrincipalNames = $null
                        UserPrincipalName     = $null
                        DisplayName           = $null
                        Path                  = $null
                        Description           = $null
                        Enabled               = $false
                        Manager               = $null
                        DomainController      = $null
                        Credential            = $null
                        RequestFile           = $null
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = $null
                        SID                   = $null
                        SamAccountName        = $null
                    }
                }

                Mock -CommandName Get-DomainName -MockWith {
                    return 'contoso.com'
                }

                Mock -CommandName Start-ProcessWithTimeout -MockWith {
                    # ExitCode for 'The parameter is incorrect.'.
                    return 87
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        ComputerName = 'TEST01'
                        RequestFile  = 'c:\ODJTest.txt'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.FailedToCreateOfflineDomainJoinRequest -f $setParameters.ComputerName, 87)

                    { Set-TargetResource @setParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }

                Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When a property is not in desired state' {
            BeforeAll {
                # Mock a specific desired state.
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                = 'Present'
                        ComputerName          = 'TEST01'
                        Location              = 'Test location'
                        DnsHostName           = 'TEST01.contoso.com'
                        ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                        UserPrincipalName     = 'TEST01@contoso.com'
                        DisplayName           = 'TEST01'
                        Path                  = 'CN=Computers,DC=contoso,DC=com'
                        Description           = 'Test description'
                        Enabled               = $true
                        Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                        DomainController      = 'DC01'
                        Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                        )
                        RequestFile           = 'TestDrive:\ODJ.txt'
                        RestoreFromRecycleBin = $false
                        EnabledOnCreation     = $false
                        DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                        SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName        = 'TEST01$'
                    }
                }
            }

            Context 'When a property should be replaced' {
                BeforeDiscovery {
                    # One test case per property with a value that differs from the desired state.
                    $testCases = @(
                        @{
                            ParameterName = 'Location'
                            PropertyName  = 'Location'
                            Value         = 'NewLocation'
                        },
                        @{
                            ParameterName = 'DnsHostName'
                            PropertyName  = 'DnsHostName'
                            Value         = 'New@contoso.com'
                        },
                        @{
                            ParameterName = 'ServicePrincipalNames'
                            PropertyName  = 'ServicePrincipalName'
                            Value         = @('spn/new')
                        },
                        @{
                            ParameterName = 'UserPrincipalName'
                            PropertyName  = 'UserPrincipalName'
                            Value         = 'New@contoso.com'
                        },
                        @{
                            ParameterName = 'DisplayName'
                            PropertyName  = 'DisplayName'
                            Value         = 'New'
                        },
                        @{
                            ParameterName = 'Description'
                            PropertyName  = 'Description'
                            Value         = 'New description'
                        },
                        @{
                            ParameterName = 'Manager'
                            PropertyName  = 'ManagedBy'
                            Value         = 'CN=NewManager,CN=Users,DC=contoso,DC=com'
                        }
                    )
                }

                It 'Should set the correct property when property <PropertyName> is not in desired state' -TestCases $testCases {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            ComputerName   = 'TEST01'
                            $ParameterName = $Value
                        }

                        $result = Set-TargetResource @setParameters

                        { $result } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADComputer -ParameterFilter {
                        $Replace.ContainsKey($PropertyName) -eq $true
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When a property should be removed' {
                BeforeDiscovery {
                    # One test case per property with a value that differs from the desired state.
                    $testCases = @(
                        @{
                            ParameterName = 'Location'
                            PropertyName  = 'Location'
                            Value         = $null
                        },
                        @{
                            ParameterName = 'DnsHostName'
                            PropertyName  = 'DnsHostName'
                            Value         = $null
                        },
                        @{
                            ParameterName = 'ServicePrincipalNames'
                            PropertyName  = 'ServicePrincipalName'
                            Value         = @()
                        },
                        @{
                            ParameterName = 'UserPrincipalName'
                            PropertyName  = 'UserPrincipalName'
                            Value         = $null
                        },
                        @{
                            ParameterName = 'DisplayName'
                            PropertyName  = 'DisplayName'
                            Value         = $null
                        },
                        @{
                            ParameterName = 'Description'
                            PropertyName  = 'Description'
                            Value         = $null
                        },
                        @{
                            ParameterName = 'Manager'
                            PropertyName  = 'ManagedBy'
                            Value         = $null
                        }
                    )
                }

                It 'Should set the correct property when property <PropertyName> is not in desired state' -TestCases $testCases {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            ComputerName   = 'TEST01'
                            $ParameterName = $Value
                        }

                        { Set-TargetResource @setParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADComputer -ParameterFilter {
                        $Remove.ContainsKey($PropertyName) -eq $true
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the computer account should be moved' {
                It 'Should call the correct mock to move the computer account' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            ComputerName = 'TEST01'
                            Path         = 'OU=New,CN=Computers,DC=contoso,DC=com'
                        }

                        { Set-TargetResource @setParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When RestoreFromRecycleBin is used' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    if (-not $script:mockRestoreADCommonObjectSuccessfullyRestoredObject)
                    {
                        # First call.
                        $mockGetTargetResourceResult = & {
                            return @{
                                Ensure                = 'Absent'
                                ComputerName          = $null
                                Location              = $null
                                DnsHostName           = $null
                                ServicePrincipalNames = $null
                                UserPrincipalName     = $null
                                DisplayName           = $null
                                Path                  = $null
                                Description           = $null
                                Enabled               = $false
                                Manager               = $null
                                DomainController      = $null
                                Credential            = $null
                                RequestFile           = $null
                                RestoreFromRecycleBin = $false
                                EnabledOnCreation     = $false
                                DistinguishedName     = $null
                                SID                   = $null
                                SamAccountName        = $null
                            }
                        }
                    }
                    else
                    {
                        # Second call - After Restore-ADCommonObject has been called.
                        $mockGetTargetResourceResult = & {
                            return @{
                                Ensure                = 'Present'
                                ComputerName          = 'TEST01'
                                Location              = 'Test location'
                                DnsHostName           = 'TEST01.contoso.com'
                                ServicePrincipalNames = @('TERMSRV/TEST01', 'TERMSRV/TEST01.contoso.com')
                                UserPrincipalName     = 'TEST01@contoso.com'
                                DisplayName           = 'TEST01'
                                Path                  = 'CN=Computers,DC=contoso,DC=com'
                                Description           = 'Test description'
                                Enabled               = $true
                                Manager               = 'CN=Manager,CN=Users,DC=contoso,DC=com'
                                DomainController      = 'DC01'
                                Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                    'COMPANY\User', 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
                                )
                                RequestFile           = 'TestDrive:\ODJ.txt'
                                RestoreFromRecycleBin = $false
                                EnabledOnCreation     = $false
                                DistinguishedName     = 'CN=TEST01,CN=Computers,DC=contoso,DC=com'
                                SID                   = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                                SamAccountName        = 'TEST01$'
                            }
                        }
                    }

                    return $mockGetTargetResourceResult
                }
            }

            BeforeEach {
                $script:mockRestoreADCommonObjectSuccessfullyRestoredObject = $false
            }

            Context 'When the computer object exist in the recycle bin' {
                BeforeAll {
                    Mock -CommandName Restore-ADCommonObject -MockWith {
                        return @{
                            ObjectClass = 'computer'
                        }

                        $script:mockRestoreADCommonObjectSuccessfullyRestoredObject = $true
                    }
                }

                It 'Should call Restore-ADCommonObject and successfully restore the computer account' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            ComputerName          = 'TEST01'
                            RestoreFromRecycleBin = $true
                        }

                        { Set-TargetResource @setParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Times 0 -Exactly -Scope It
                    Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the computer object does not exist in the recycle bin' {
                BeforeAll {
                    Mock -CommandName Restore-ADCommonObject
                }

                It 'Should create a new computer account' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            ComputerName          = 'TEST01'
                            RestoreFromRecycleBin = $true
                        }

                        { Set-TargetResource @setParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADComputer -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the cmdlet Restore-ADCommonObject throws an error' {
                BeforeAll {
                    Mock -CommandName Restore-ADCommonObject -MockWith { throw }
                }

                It 'Should throw the correct error' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $setParameters = @{
                            ComputerName          = 'TEST01'
                            RestoreFromRecycleBin = $true
                        }

                        { Set-TargetResource @setParameters } | Should -Throw
                    }

                    Should -Invoke -CommandName Restore-ADCommonObject -Scope It -Exactly -Times 1
                    Should -Invoke -CommandName New-ADComputer -Scope It -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADComputer -Scope It -Exactly -Times 0
                }
            }
        }
    }
}
