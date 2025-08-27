# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies have been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies have not been resolved, this will throw an error.
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
    $script:dscResourceName = 'MSFT_ADDomain'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    # Load stub cmdlets and classes.
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1')
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ADDSDeployment_2019.psm1')

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
    Remove-Module -Name ADDSDeployment_2019 -Force

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_ADDomain\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
        Mock -CommandName Test-Path -ParameterFilter {
            $Path -eq 'C:\Windows\SysVol\contoso.com'
        } -MockWith { $true }

        Mock -CommandName Get-ItemProperty -ParameterFilter {
            $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        } -MockWith {
            @{
                'DSA Working Directory'   = 'C:\Windows\NTDS'
                'Database log files path' = 'C:\Windows\NTDS'
            }
        }

        Mock -CommandName Get-ItemProperty -ParameterFilter {
            $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        } -MockWith {
            @{
                SysVol = 'C:\Windows\SysVol\sysvol'
            }
        }
    }

    Context 'When the domain has not yet been installed' {
        BeforeAll {
            Mock -CommandName Get-DomainObject -MockWith {
                @{
                    Forest       = 'contoso.com'
                    DomainMode   = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain
                    ParentDomain = ''
                    NetBIOSName  = 'CONTOSO'
                    DnsRoot      = 'contoso.com'
                }
            }

            Mock -CommandName Get-AdForest -MockWith {
                @{
                    Name       = 'contoso.com'
                    ForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest
                }
            }

            Mock -CommandName Get-ItemPropertyValue -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -and
                $Name -eq 'SysVol'
            } -MockWith {
                throw [System.Management.Automation.ProviderInvocationException]
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $getParameters = @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $result = Get-TargetResource @getParameters

                $result.DomainName | Should -Be $getParameters.DomainName
                $result.Credential | Should -Be $getParameters.Credential
                $result.SafeModeAdministratorPassword | Should -Be $getParameters.SafeModeAdministratorPassword
                $result.ParentDomainName | Should -Be ''
                $result.DomainNetBiosName | Should -BeNullOrEmpty
                $result.DnsDelegationCredential | Should -BeNullOrEmpty
                $result.DomainType | Should -Be 'ChildDomain'
                $result.DatabasePath | Should -BeNullOrEmpty
                $result.LogPath | Should -BeNullOrEmpty
                $result.SysvolPath | Should -BeNullOrEmpty
                $result.ForestMode | Should -BeNullOrEmpty
                $result.DomainMode | Should -BeNullOrEmpty
                $result.DomainExist | Should -BeFalse
                $result.Forest | Should -BeNullOrEmpty
                $result.DnsRoot | Should -BeNullOrEmpty
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ItemPropertyValue -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -and
                $Name -eq 'SysVol'
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Test-Path -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Get-DomainObject -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Get-ADForest -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Get-ItemProperty -Exactly -Times 0 -Scope It
        }
    }

    Context 'When the domain has been installed' {
        BeforeAll {
            Mock -CommandName Get-DomainObject -MockWith {
                @{
                    Forest       = 'contoso.com'
                    DomainMode   = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain
                    ParentDomain = ''
                    NetBIOSName  = 'CONTOSO'
                    DnsRoot      = 'contoso.com'
                }
            }

            Mock -CommandName Get-AdForest -MockWith {
                @{
                    Name       = 'contoso.com'
                    ForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest
                }
            }

            Mock -CommandName Get-ItemPropertyValue -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -and
                $Name -eq 'SysVol'
            } -MockWith { 'C:\Windows\SysVol' }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $getParameters = @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $result = Get-TargetResource @getParameters

                $result.DomainName | Should -Be $getParameters.DomainName
                $result.Credential | Should -Be $getParameters.Credential
                $result.SafeModeAdministratorPassword | Should -Be $getParameters.SafeModeAdministratorPassword
                $result.ParentDomainName | Should -Be ''
                $result.DomainNetBiosName | Should -Be 'CONTOSO'
                $result.DnsDelegationCredential | Should -Be $null
                $result.DomainType | Should -Be 'ChildDomain'
                $result.DatabasePath | Should -Be 'C:\Windows\NTDS'
                $result.LogPath | Should -Be 'C:\Windows\NTDS'
                $result.SysvolPath | Should -Be 'C:\Windows\SysVol'
                $result.ForestMode | Should -Be 'WinThreshold'
                $result.DomainMode | Should -Be 'WinThreshold'
                $result.DomainExist | Should -Be $true
                $result.Forest | Should -Be 'contoso.com'
                $result.DnsRoot | Should -Be 'contoso.com'
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ItemPropertyValue -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -and
                $Name -eq 'SysVol'
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Test-Path -ParameterFilter {
                $Path -eq 'C:\Windows\SysVol\contoso.com'
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADForest -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Get-ItemProperty -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Get-ItemProperty -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            } -Exactly -Times 1 -Scope It
        }

        Context 'When the correct domain SysVol path does not exist' {
            BeforeAll {
                Mock -CommandName Test-Path -ParameterFilter {
                    $Path -eq 'C:\Windows\SysVol\contoso.com'
                } -MockWith { $false }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        DomainName                    = 'contoso.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.SysVolPathDoesNotExistError -f 'C:\Windows\SysVol\contoso.com')

                    { Get-TargetResource @getParameters } | Should -Throw -ExpectedMessage $errorRecord
                }
            }
        }

        Context 'When Get-ADForest throws an unexpected error' {
            BeforeAll {
                Mock -CommandName Get-AdForest -MockWith { Throw 'Unknown Error' }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $getParameters = @{
                        DomainName                    = 'contoso.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.GetAdForestUnexpectedError -f 'contoso.com')

                    { Get-TargetResource @getParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }
    }
}

Describe 'MSFT_ADDomain\Test-TargetResource' -Tag 'Test' {
    Context 'When the resource is in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    ParentDomainName              = ''
                    DomainNetBiosName             = 'CONTOSO'
                    DnsDelegationCredential       = $null
                    DomainType                    = 'ChildDomain'
                    DatabasePath                  = 'C:\Windows\NTDS'
                    LogPath                       = 'C:\Windows\NTDS'
                    SysvolPath                    = 'C:\Windows\SysVol'
                    ForestMode                    = [Microsoft.DirectoryServices.Deployment.Types.ForestMode]::WinThreshold
                    DomainMode                    = [Microsoft.DirectoryServices.Deployment.Types.DomainMode]::WinThreshold
                    DomainExist                   = $true
                    Forest                        = 'contoso.com'
                    DnsRoot                       = 'contoso.com'
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                Test-TargetResource @testParameters | Should -BeTrue
            }
        }
    }

    Context 'when the resource is not in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    ParentDomainName              = ''
                    DomainNetBiosName             = $null
                    DnsDelegationCredential       = $null
                    DomainType                    = 'ChildDomain'
                    DatabasePath                  = $null
                    LogPath                       = $null
                    SysvolPath                    = $null
                    ForestMode                    = $null
                    DomainMode                    = $null
                    DomainExist                   = $false
                    Forest                        = $null
                    DnsRoot                       = $null
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                Test-TargetResource @testParameters | Should -BeFalse
            }
        }
    }
}

Describe 'MSFT_ADDomain\Set-TargetResource' -Tag 'Set' {
    Context 'When Installing a Forest Root Domain' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    ParentDomainName              = ''
                    DomainNetBiosName             = $null
                    DnsDelegationCredential       = $null
                    DomainType                    = 'ChildDomain'
                    DatabasePath                  = $null
                    LogPath                       = $null
                    SysvolPath                    = $null
                    ForestMode                    = $null
                    DomainMode                    = $null
                    DomainExist                   = $false
                    Forest                        = $null
                    DnsRoot                       = $null
                }
            }

            Mock -CommandName Install-ADDSForest
        }

        Context 'When supplying parameter "DomainName"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $DomainName -eq 'present.com' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Install-ADDSForest -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "DnsDelegationCredential"' {
            It 'Should call the correct mocks' {

                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        DnsDelegationCredential       = [System.Management.Automation.PSCredential]::new('Delegation',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $CreateDnsDelegation -eq $true } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "DatabasePath"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        DatabasePath                  = 'TestPath'
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $DatabasePath -eq 'TestPath' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "LogPath"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        LogPath                       = 'TestPath'
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $LogPath -eq 'TestPath' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "SysvolPath"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SysvolPath                    = 'TestPath'
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $SysvolPath -eq 'TestPath' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "DomainNetbiosName"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        DomainNetBIOSName             = 'PRESENT'
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $DomainNetbiosName -eq 'PRESENT' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "ForestMode"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        ForestMode                    = 'WinThreshold'
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $ForestMode -eq 'WinThreshold' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When supplying parameter "DomainMode"' {
            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $setParameters = @{
                        DomainName                    = 'present.com'
                        Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        DomainMode                    = 'WinThreshold'
                    }

                    Set-TargetResource @setParameters
                }

                Should -Invoke -CommandName Install-ADDSForest -ParameterFilter { $DomainMode -eq 'WinThreshold' } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When Installing a Child Domain' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                    = 'contoso.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    ParentDomainName              = ''
                    DomainNetBiosName             = $null
                    DnsDelegationCredential       = $null
                    DomainType                    = 'ChildDomain'
                    DatabasePath                  = $null
                    LogPath                       = $null
                    SysvolPath                    = $null
                    ForestMode                    = $null
                    DomainMode                    = $null
                    DomainExist                   = $false
                    Forest                        = $null
                    DnsRoot                       = $null
                }
            }

            Mock -CommandName Install-ADDSDomain
        }

        It 'Should call "Install-ADDSDomain" with "NewDomainName"' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $NewDomainName -eq 'present.com'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "ParentDomainName"' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $ParentDomainName -eq 'parent.com'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "DomainType"' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $DomainType -eq 'ChildDomain'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "SafeModeAdministratorPassword"' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $SafeModeAdministratorPassword -ne $null
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "Credential"' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $Credential -is [System.Management.Automation.PSCredential]
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "ParentDomainName"' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $ParentDomainName -eq 'parent.com'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "DnsDelegationCredential", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    DnsDelegationCredential       = [System.Management.Automation.PSCredential]::new('Delegation',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $DnsDelegationCredential -is [System.Management.Automation.PSCredential]
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "CreateDnsDelegation", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    DnsDelegationCredential       = [System.Management.Automation.PSCredential]::new('Delegation',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $CreateDnsDelegation -eq $true
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "DatabasePath", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    DatabasePath                  = 'TestPath'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $DatabasePath -eq 'TestPath'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "LogPath", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    LogPath                       = 'TestPath'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $LogPath -eq 'TestPath'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "SysvolPath", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    SysvolPath                    = 'TestPath'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $SysvolPath -eq 'TestPath'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "NewDomainNetbiosName", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    DomainNetBIOSName             = 'PRESENT'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $NewDomainNetbiosName -eq 'PRESENT'
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call "Install-ADDSDomain" with "DomainMode", if specified' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $setParameters = @{
                    DomainName                    = 'present.com'
                    ParentDomainName              = 'parent.com'
                    Credential                    = [System.Management.Automation.PSCredential]::new('DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force))
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::new('Safemode', (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainType                    = 'ChildDomain'
                    DomainMode                    = 'WinThreshold'
                }

                Set-TargetResource @setParameters
            }

            Should -Invoke -CommandName Install-ADDSDomain -ParameterFilter {
                $DomainMode -eq 'WinThreshold'
            } -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADDomain\Resolve-DomainFQDN' -Tag 'Helpers' {
    Context 'When the "ParentDomainName" Parameter is not supplied' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDomainName = 'contoso.com'

                $result = Resolve-DomainFQDN -DomainName $testDomainName
                $result | Should -Be $testDomainName
            }
        }
    }

    Context 'When the "ParentDomainName" Parameter is $null' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDomainName = 'contoso.com'
                $testParentDomainName = $null

                $result = Resolve-DomainFQDN -DomainName $testDomainName -ParentDomainName $testParentDomainName
                $result | Should -Be $testDomainName
            }
        }
    }

    Context 'When the "ParentDomainName" Parameter is supplied' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDomainName = 'contoso.com'
                $testParentDomainName = 'contoso.com'

                $result = Resolve-DomainFQDN -DomainName $testDomainName -ParentDomainName $testParentDomainName
                $result | Should -Be "$testDomainName.$testParentDomainName"
            }
        }
    }
}
