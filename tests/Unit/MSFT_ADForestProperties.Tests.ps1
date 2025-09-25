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
    $script:dscResourceName = 'MSFT_ADForestProperties'

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

Describe 'MSFT_ADForestProperties\Get-TargetResource' -Tag 'Get' {
    Context 'When getting the current state' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-ADRootDSE -MockWith {
                @{
                    configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
                }
            }

            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name        = 'contoso.com'
                    SpnSuffixes = 'test.com'
                    UpnSuffixes = 'pester.net'
                }
            }
            Mock -CommandName Get-ADObject -ParameterFilter {
                $Properties -eq 'tombstonelifetime'
            } -MockWith {
                @{
                    tombstonelifetime = 180
                }
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestName = 'contoso.com'
                }

                $result = Get-TargetResource @mockParameters

                $result.ForestName | Should -Be 'contoso.com'
                $result.ServicePrincipalNameSuffix | Should -Be 'test.com'
                $result.UserPrincipalNameSuffix | Should -Be 'pester.net'
                $result.TombstoneLifetime | Should -Be 180
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADRootDSE -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADObject -ParameterFilter { $Properties -eq 'tombstonelifetime' } -Exactly -Times 1 -Scope It
        }


        Context 'When the Credential parameter is specified' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' `
                            -ArgumentList @(
                            'admin@contoso.com',
                            ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                        )

                        ForestName = 'contoso.com'
                    }

                    { Get-TargetResource @mockParameters } | Should -Not -Throw
                }
            }
        }
    }
}

Describe 'MSFT_ADForestProperties\Test-TargetResource' -Tag 'Test' {
    BeforeAll {
        Mock -CommandName Assert-Module
        Mock -CommandName Assert-MemberParameters

        Mock -CommandName Get-TargetResource -MockWith {
            @{
                Credential                         = New-CimCredentialInstance -Credential (New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                )

                ForestName                         = 'contoso.com'
                ServicePrincipalNameSuffix         = 'test.com'
                ServicePrincipalNameSuffixToAdd    = @()
                ServicePrincipalNameSuffixToRemove = @()
                TombstoneLifetime                  = 180
                UserPrincipalNameSuffix            = 'pester.net'
                UserPrincipalNameSuffixToAdd       = @()
                UserPrincipalNameSuffixToRemove    = @()
            }
        }
    }

    Context 'When the target resource is in the desired state' {
        Context 'When using add/remove parameters' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ForestName                         = 'contoso.com'
                        ServicePrincipalNameSuffixToRemove = 'test.net'
                        ServicePrincipalNameSuffixToAdd    = 'test.com'
                        UserPrincipalNameSuffixToRemove    = 'cloudapp.net', 'fabrikam.com'
                        UserPrincipalNameSuffixToAdd       = 'pester.net'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When using replace parameters' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ForestName                 = 'contoso.com'
                        ServicePrincipalNameSuffix = 'test.com'
                        UserPrincipalNameSuffix    = 'pester.net'
                        TombstoneLifetime          = 180
                        Credential                 = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'admin@contoso.com',
                            ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }

                    Test-TargetResource @mockParameters -Verbose | Should -BeTrue
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the target resource is not in the desired state' {
        BeforeDiscovery {
            $testCases = @(
                @{
                    Property = 'ServicePrincipalNameSuffix'
                    Value    = 'test.net'
                }
                @{
                    Property = 'UserPrincipalNameSuffix'
                    Value    = 'cloudapp.net', 'fabrikam.com'
                }
                @{
                    Property = 'TombstoneLifetime'
                    Value    = 200
                }
                @{
                    Property = 'ServicePrincipalNameSuffixToRemove'
                    Value    = 'test.com'
                }
                @{
                    Property = 'ServicePrincipalNameSuffixToAdd'
                    Value    = 'test.net'
                }
                @{
                    Property = 'UserPrincipalNameSuffixToRemove'
                    Value    = 'pester.net'
                }
                @{
                    Property = 'UserPrincipalNameSuffixToAdd'
                    Value    = 'cloudapp.net', 'fabrikam.com'
                }
            )
        }

        Context 'When the <Property> resource property is not in the desired state' -ForEach $testCases {
            It 'Should return $false' {
                InModuleScope -Parameters $_ -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ForestName = 'contoso.com'
                        Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'admin@contoso.com',
                            ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                        )
                    }

                    $mockParameters.$Property = $Value

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADForestProperties\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName Assert-Module
        Mock -CommandName Get-ADRootDSE -MockWith {
            @{
                configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
            }
        }

        Mock -CommandName Get-TargetResource -MockWith {
            @{
                Credential                         = New-CimCredentialInstance -Credential (New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                )
                ForestName                         = 'contoso.com'
                ServicePrincipalNameSuffix         = 'test.com'
                ServicePrincipalNameSuffixToAdd    = @()
                ServicePrincipalNameSuffixToRemove = @()
                TombstoneLifetime                  = 180
                UserPrincipalNameSuffix            = 'pester.net'
                UserPrincipalNameSuffixToAdd       = @()
                UserPrincipalNameSuffixToRemove    = @()
            }
        }

        Mock -CommandName Set-ADForest
        Mock -CommandName Set-ADObject
    }

    BeforeDiscovery {
        $testCases = @(
            @{
                Property = 'ServicePrincipalNameSuffix'
                Value    = 'test.net'
            }
            @{
                Property = 'UserPrincipalNameSuffix'
                Value    = 'cloudapp.net', 'fabrikam.com'
            }
            @{
                Property = 'TombstoneLifetime'
                Value    = 200
            }
            @{
                Property = 'ServicePrincipalNameSuffixToRemove'
                Value    = 'test.com'
            }
            @{
                Property = 'ServicePrincipalNameSuffixToAdd'
                Value    = 'test.net'
            }
            @{
                Property = 'UserPrincipalNameSuffixToRemove'
                Value    = 'pester.net'
            }
            @{
                Property = 'UserPrincipalNameSuffixToAdd'
                Value    = 'cloudapp.net', 'fabrikam.com'
            }
        )
    }

    Context 'When <Property> has changed' -ForEach $testCases {
        It 'Should not throw' {
            InModuleScope -Parameters $_ -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestName = 'contoso.com'
                    Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                }

                $mockParameters.$Property = $Value

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It

            if ($Property -eq 'TombstoneLifeTime')
            {
                Should -Invoke -CommandName Set-ADForest -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADObject -Exactly -Times 1 -Scope It
            }
            else
            {
                Should -Invoke -CommandName Set-ADForest -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When both ServicePrincipalNameSuffixAdd and ServicePrincipalNameSuffixRemove have been specified' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestName                         = 'contoso.com'
                    Credential                         = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                    ServicePrincipalNameSuffixToAdd    = 'test.net'
                    ServicePrincipalNameSuffixToRemove = 'test.com'
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADForest -Exactly -Times 1 -Scope It
        }
    }

    Context 'When both UserPrincipalNameSuffixAdd and UserPrincipalNameSuffixRemove have been specified' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestName                      = 'contoso.com'
                    Credential                      = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                    UserPrincipalNameSuffixToAdd    = 'cloudapp.net', 'fabrikam.com'
                    UserPrincipalNameSuffixToRemove = 'pester.net'
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADForest -Exactly -Times 1 -Scope It
        }
    }

    Context 'When <_> has changed to an empty value' -ForEach @('ServicePrincipalNameSuffix', 'UserPrincipalNameSuffix' , 'TombstoneLifetime') {
        It 'Should not throw' {
            InModuleScope -Parameters @{ Value = $_ } -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestName = 'contoso.com'
                    Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                    $Value     = ''
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It

            if ($_ -eq 'TombstoneLifeTime')
            {
                Should -Invoke -CommandName Set-ADForest -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADObject -Exactly -Times 1 -Scope It
            }
            else
            {
                Should -Invoke -CommandName Set-ADForest -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When Set-ADObject throws an exception' {
        BeforeAll {
            Mock -CommandName Set-ADObject -MockWith { throw 'Error' }
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ForestName        = 'contoso.com'
                    TombstoneLifetime = 200
                    Credential        = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'admin@contoso.com',
                        ('P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force)
                    )
                }

                $errorRecord = Get-InvalidOperationRecord -Message (
                    $script:localizedData.SetTombstoneLifetimeError -f $mockParameters.TombstoneLifetime, $mockParameters.ForestName
                )

                { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }
        }
    }
}
