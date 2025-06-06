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
    $script:dscResourceName = 'MSFT_WaitForADDomain'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscResourceName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    Restore-TestEnvironment -TestEnvironment $script:testEnvironment

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_WaitForADDomain\Get-TargetResource' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When no domain controller is found in the domain' {
            BeforeAll {
                Mock -CommandName Find-DomainController -MockWith {
                    return $null
                }

                InModuleScope -ScriptBlock {
                    # Mock PsDscRunAsCredential context.
                    $script:PsDscContext = @{
                        RunAsUser = $null
                    }
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainName | Should -Be 'contoso.com'
                    $result.WaitTimeout | Should -Be 300
                    $result.SiteName | Should -BeNullOrEmpty
                    $result.Credential | Should -BeNullOrEmpty
                    $result.RestartCount | Should -Be 0
                    $result.WaitForValidCredentials | Should -BeFalse
                }
            }
        }

        Context 'When a domain controller is found in the domain' {
            BeforeAll {
                Mock -CommandName Find-DomainController -MockWith {
                    return New-Object -TypeName PSObject |
                        Add-Member -MemberType ScriptProperty -Name 'Domain' -Value {
                            New-Object -TypeName PSObject |
                                Add-Member -MemberType ScriptMethod -Name 'ToString' -Value {
                                    return 'contoso.com'
                                } -PassThru -Force
                            } -PassThru |
                            Add-Member -MemberType NoteProperty -Name 'SiteName' -Value 'Europe' -PassThru -Force
                }
            }

            Context 'When using the default parameters' {
                It 'Should return the correct result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                        }

                        $result = Get-TargetResource @mockParameters
                        $result.DomainName | Should -Be 'contoso.com'
                        $result.WaitTimeout | Should -Be 300
                        $result.SiteName | Should -Be 'Europe'
                        $result.Credential | Should -BeNullOrEmpty
                        $result.RestartCount | Should -Be 0
                        $result.WaitForValidCredentials | Should -BeFalse
                    }
                }
            }

            Context 'When using all available parameters' {
                It 'Should return the same values as passed as parameters' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName              = 'contoso.com'
                            Credential              = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'User1',
                                (ConvertTo-SecureString -String 'Password' -AsPlainText -Force)
                            )

                            SiteName                = 'Europe'
                            WaitTimeout             = 600
                            RestartCount            = 2
                            WaitForValidCredentials = $true
                        }

                        $result = Get-TargetResource @mockParameters

                        $result.DomainName | Should -Be 'contoso.com'
                        $result.SiteName | Should -Be 'Europe'
                        $result.WaitTimeout | Should -Be 600
                        $result.RestartCount | Should -Be 2
                        $result.Credential.UserName | Should -Be $mockParameters.Credential.UserName
                        $result.WaitForValidCredentials | Should -BeTrue
                    }

                    Should -Invoke -CommandName Find-DomainController -ParameterFilter {
                        $PesterBoundParameters.ContainsKey('WaitForValidCredentials')
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When using BuiltInCredential parameter' {
                BeforeAll {
                    Mock -CommandName Write-Verbose -ParameterFilter {
                        $Message -like 'Impersonating the credentials ''BuiltInCredential''*'
                    } -MockWith {
                        Write-Verbose -Message ('VERBOSE OUTPUT FROM MOCK: {0}' -f $Message)
                    }

                    InModuleScope -ScriptBlock {
                        # Mock PsDscRunAsCredential context.
                        $script:PsDscContext = @{
                            RunAsUser = 'BuiltInCredential'
                        }
                    }
                }

                It 'Should return the same values as passed as parameters' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                        }

                        $result = Get-TargetResource @mockParameters

                        $result.DomainName | Should -Be 'contoso.com'
                        $result.Credential | Should -BeNullOrEmpty
                    }

                    Should -Invoke -CommandName Write-Verbose -Exactly -Times 1 -Scope It
                }
            }
        }
    }
}

Describe 'MSFT_WaitForADDomain\Test-TargetResource' -tag 'Test' {
    Context 'When the system is in the desired state' {
        Context 'When a domain controller is found' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'IsAvailable'
                            InDesiredState = $true
                        }
                    )
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            }
        }

        Context 'When a domain controller is found, and RestartCount was used' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'IsAvailable'
                            InDesiredState = $true
                        }
                    )
                }

                Mock -CommandName Remove-Item
                Mock -CommandName Test-Path -MockWith {
                    return $true
                }
            }

            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName   = 'contoso.com'
                        RestartCount = 2
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-Path -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-Item -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When a domain controller cannot be reached' {
            BeforeAll {
                Mock -CommandName Compare-TargetResourceState -MockWith {
                    return @(
                        @{
                            ParameterName  = 'IsAvailable'
                            InDesiredState = $false
                        }
                    )
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_WaitForADDomain\Compare-TargetResourceState' -Tag 'Compare' {
    Context 'When the system is in the desired state' {
        Context 'When a domain controller is found' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName   = 'contoso.com'
                        SiteName     = 'Europe'
                        Credential   = $null
                        WaitTimeout  = 300
                        RestartCount = 0
                        IsAvailable  = $true
                    }
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                    }

                    $result = Compare-TargetResourceState @mockParameters
                    $result | Should -HaveCount 1

                    $comparedReturnValue = $result.Where( { $_.ParameterName -eq 'IsAvailable' })
                    $comparedReturnValue | Should -Not -BeNullOrEmpty
                    $comparedReturnValue.Expected | Should -BeTrue
                    $comparedReturnValue.Actual | Should -BeTrue
                    $comparedReturnValue.InDesiredState | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    DomainName   = 'contoso.com'
                    SiteName     = $null
                    Credential   = $null
                    WaitTimeout  = 300
                    RestartCount = 0
                    IsAvailable  = $false
                }
            }
        }

        It 'Should return the correct values' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainName = 'contoso.com'
                }

                $result = Compare-TargetResourceState @mockParameters
                $result | Should -HaveCount 1

                $comparedReturnValue = $result.Where( { $_.ParameterName -eq 'IsAvailable' })
                $comparedReturnValue | Should -Not -BeNullOrEmpty
                $comparedReturnValue.Expected | Should -BeTrue
                $comparedReturnValue.Actual | Should -BeFalse
                $comparedReturnValue.InDesiredState | Should -BeFalse
            }

            Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_WaitForADDomain\Set-TargetResource' -Tag 'Set' {
    BeforeEach {
        InModuleScope -ScriptBlock {
            $global:DSCMachineStatus = 0
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Remove-RestartLogFile
            Mock -CommandName Receive-Job
            Mock -CommandName Start-Job
            Mock -CommandName Wait-Job
            Mock -CommandName Remove-Job

            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    @{
                        ParameterName  = 'IsAvailable'
                        InDesiredState = $true
                    }
                )
            }
        }

        Context 'When a domain controller is found' {
            It 'Should not throw and call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw

                    $global:DSCMachineStatus | Should -Be 0
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Receive-Job -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Start-Job -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Wait-Job -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-Job -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Remove-RestartLogFile
            Mock -CommandName Receive-Job

            <#
                The code being tested is using parameter Job, so here
                that parameter must be avoided so that we don't mock
                in an endless loop.
            #>
            Mock -CommandName Start-Job -ParameterFilter {
                $PesterBoundParameters.ContainsKey('ArgumentList')
            } -MockWith {
                <#
                    Need to mock an object by actually creating a job
                    that completes successfully.
                #>
                $mockJobObject = Start-Job -ScriptBlock {
                    Start-Sleep -Milliseconds 1
                }

                Remove-Job -Id $mockJobObject.Id -Force

                return $mockJobObject
            }

            <#
                The code being tested is using parameter Job, so here
                that parameter must be avoided so that we don't mock
                in an endless loop.
            #>
            Mock -CommandName Remove-Job -ParameterFilter {
                $null -ne $Job
            }

            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    @{
                        ParameterName  = 'IsAvailable'
                        InDesiredState = $false
                    }
                )
            }
        }

        Context 'When a domain controller is reached before the timeout period' {
            BeforeAll {
                <#
                    The code being tested is using parameter Job, so here
                    that parameter must be avoided so that we don't mock
                    in an endless loop.
                #>
                Mock -CommandName Wait-Job -ParameterFilter {
                    $null -ne $Job
                } -MockWith {
                    <#
                        Need to mock an object by actually creating a job
                        that completes successfully.
                    #>
                    $mockJobObject = Start-Job -ScriptBlock {
                        Start-Sleep -Milliseconds 1
                    }

                    <#
                        The variable name must not be the same as the one
                        used in the call to Wait-Job.
                    #>
                    $mockWaitJobObject = Wait-Job -Id $mockJobObject.Id

                    Remove-Job -Id $mockJobObject.Id -Force

                    return $mockJobObject
                }
            }

            Context 'When only specifying the default parameter' {
                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            Verbose    = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw

                        $global:DSCMachineStatus | Should -Be 0
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It

                    Should -Invoke -CommandName Start-Job -ParameterFilter {
                        $PesterBoundParameters.ContainsKey('ArgumentList') -and
                        $ArgumentList[0] -eq $false -and
                        $ArgumentList[1] -eq 'contoso.com' -and
                        [System.String]::IsNullOrEmpty($ArgumentList[2]) -and
                        [System.String]::IsNullOrEmpty($ArgumentList[3]) -and
                        $ArgumentList[4] -eq $false
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When specifying a site name' {
                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            SiteName   = 'Europe'
                            Verbose    = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw

                        $global:DSCMachineStatus | Should -Be 0
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It

                    Should -Invoke -CommandName Start-Job -ParameterFilter {
                        $PesterBoundParameters.ContainsKey('ArgumentList') -and
                        $ArgumentList[0] -eq $false -and
                        $ArgumentList[1] -eq 'contoso.com' -and
                        $ArgumentList[2] -eq 'Europe' -and
                        [System.String]::IsNullOrEmpty($ArgumentList[3]) -and
                        $ArgumentList[4] -eq $false
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When specifying credentials' {
                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'User1',
                                (ConvertTo-SecureString -String 'Password' -AsPlainText -Force)
                            )

                            Verbose    = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw

                        $global:DSCMachineStatus | Should -Be 0
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It

                    Should -Invoke -CommandName Start-Job -ParameterFilter {
                        $PesterBoundParameters.ContainsKey('ArgumentList') -and
                        $ArgumentList[0] -eq $false -and
                        $ArgumentList[1] -eq 'contoso.com' -and
                        [System.String]::IsNullOrEmpty($ArgumentList[2]) -and
                        $ArgumentList[3].UserName -eq 'User1' -and
                        $ArgumentList[4] -eq $false
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When specifying that credentials errors should be ignored' {
                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName              = 'contoso.com'
                            WaitForValidCredentials = $true
                            Verbose                 = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw

                        $global:DSCMachineStatus | Should -Be 0
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It

                    Should -Invoke -CommandName Start-Job -ParameterFilter {
                        $PesterBoundParameters.ContainsKey('ArgumentList') -and
                        $ArgumentList[0] -eq $false -and
                        $ArgumentList[1] -eq 'contoso.com' -and
                        [System.String]::IsNullOrEmpty($ArgumentList[2]) -and
                        [System.String]::IsNullOrEmpty($ArgumentList[2]) -and
                        $ArgumentList[4] -eq $true
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When a restart was requested' {
                It 'Should not throw and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName   = 'contoso.com'
                            RestartCount = 1
                            Verbose      = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw

                        $global:DSCMachineStatus | Should -Be 0
                    }

                    Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When the script that searches for a domain controller fails' {
            BeforeAll {
                <#
                    The code being tested is using parameter Job, so here
                    that parameter must be avoided so that we don't mock
                    in an endless loop.
                #>
                Mock -CommandName Wait-Job -ParameterFilter {
                    $null -ne $Job
                } -MockWith {
                    <#
                        Need to mock an object by actually creating a job
                        that completes successfully.
                    #>
                    $mockJobObject = Start-Job -ScriptBlock {
                        throw 'Mocked error in mocked script'
                    }

                    <#
                        The variable name must not be the same as the one
                        used in the call to Wait-Job.
                    #>
                    $mockWaitJobObject = Wait-Job -Id $mockJobObject.Id

                    Remove-Job -Id $mockJobObject.Id -Force

                    return $mockJobObject
                }
            }

            It 'Should throw and call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                    }

                    { Set-TargetResource @mockParameters } | Should -Throw $script:localizedData.NoDomainController

                    $global:DSCMachineStatus | Should -Be 0
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Start-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It
            }
        }

        Context 'When a domain controller cannot be reached before the timeout period' {
            BeforeAll {
                <#
                    The code being tested is using parameter Job, so here
                    that parameter must be avoided so that we don't mock
                    in an endless loop.
                #>
                Mock -CommandName Wait-Job -ParameterFilter {
                    $null -ne $Job
                } -MockWith {
                    return $null
                }
            }

            It 'Should throw the correct error message and call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        Verbose    = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Throw $script:localizedData.NoDomainController

                    $global:DSCMachineStatus | Should -Be 0
                }

                Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Start-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It
            }

            Context 'When a restart is requested when a domain controller cannot be found' {
                BeforeAll {
                    Mock -CommandName Get-Content
                    Mock -CommandName Set-Content

                    <#
                        The code being tested is using parameter Job, so here
                        that parameter must be avoided so that we don't mock
                        in an endless loop.
                    #>
                    Mock -CommandName Wait-Job -ParameterFilter {
                        $null -ne $Job
                    } -MockWith {
                        return $null
                    }
                }

                It 'Should throw the correct error message and call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName   = 'contoso.com'
                            RestartCount = 1
                            Verbose      = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Throw $script:localizedData.NoDomainController

                        $global:DSCMachineStatus | Should -Be 1
                    }

                    Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Receive-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Start-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Wait-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-Job -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Get-Content -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-Content -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-RestartLogFile -Exactly -Times 0 -Scope It
                }
            }
        }
    }
}

Describe 'MSFT_WaitForADDomain\WaitForDomainControllerScriptBlock' -Tag 'Helper' {
    BeforeAll {
        Mock -CommandName Clear-DnsClientCache
        Mock -CommandName Start-Sleep
    }

    Context 'When a domain controller cannot be found' {
        BeforeAll {
            Mock -CommandName Find-DomainController
        }

        It 'Should not throw and call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                Invoke-Command -ScriptBlock $script:waitForDomainControllerScriptBlock -ArgumentList @(
                    $true # RunOnce
                    'contoso.com' # DomainName
                    'Europe' # SiteName
                    New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'User1',
                        (ConvertTo-SecureString -String 'Password' -AsPlainText -Force)
                    ) # Credential
                )
            }

            Should -Invoke -CommandName Find-DomainController -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('WaitForValidCredentials')
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Clear-DnsClientCache -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the Find-DomainController should ignore authentication exceptions' {
        BeforeAll {
            Mock -CommandName Find-DomainController
        }

        Context 'When the parameter WaitForValidCredentials is set to $true' {
            It 'Should output a warning message' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    Invoke-Command -ScriptBlock $script:waitForDomainControllerScriptBlock -ArgumentList @(
                        $true # RunOnce
                        'contoso.com' # DomainName
                        'Europe' # SiteName
                        New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'User1',
                            (ConvertTo-SecureString -String 'Password' -AsPlainText -Force)
                        ) # Credential
                        $true
                    )
                }

                Should -Invoke -CommandName Find-DomainController -ParameterFilter {
                    $PesterBoundParameters.ContainsKey('WaitForValidCredentials')
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When a domain controller is found' {
        BeforeAll {
            Mock -CommandName Find-DomainController -MockWith {
                return [PSCustomObject] @{}
            }
        }

        It 'Should not throw and call the correct mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                Invoke-Command -ScriptBlock $script:waitForDomainControllerScriptBlock -ArgumentList @(
                    $true # RunOnce
                    'contoso.com' # DomainName
                    'Europe' # SiteName
                    $null # Credential
                )
            }

            Should -Invoke -CommandName Find-DomainController -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Clear-DnsClientCache -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 0 -Scope It
        }
    }
}
