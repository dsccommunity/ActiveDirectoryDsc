$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_WaitForADDomain'

#region HEADER

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit

#endregion HEADER

function Invoke-TestSetup
{
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope $script:dscResourceName {
        $mockUserName = 'User1'
        $mockDomainUserCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockUserName,
            (ConvertTo-SecureString -String 'Password' -AsPlainText -Force)
        )

        $mockDomainName = 'example.com'
        $mockSiteName = 'Europe'

        $mockDefaultParameters = @{
            DomainName = $mockDomainName
            Verbose    = $true
        }

        #region Function Get-TargetResource
        Describe 'WaitForADDomain\Get-TargetResource' -Tag 'Get' {
            Context 'When the system is in the desired state' {
                Context 'When no domain controller is found in the domain' {
                    BeforeAll {
                        Mock -CommandName Find-DomainController -MockWith {
                            return $null
                        }

                        $getTargetResourceParameters = $mockDefaultParameters.Clone()
                    }

                    It 'Should return the same values as passed as parameters' {
                        $result = Get-TargetResource @getTargetResourceParameters
                        $result.DomainName | Should -Be $mockDomainName
                    }

                    It 'Should return default value for property WaitTimeout' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.WaitTimeout | Should -Be 300
                    }

                    It 'Should return $null for the rest of the properties' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.SiteName | Should -BeNullOrEmpty
                        $getTargetResourceResult.Credential | Should -BeNullOrEmpty
                        $getTargetResourceResult.RestartCount | Should -Be 0
                    }
                }

                Context 'When a domain controller is found in the domain' {
                    BeforeAll {
                        Mock -CommandName Find-DomainController -MockWith {
                            return New-Object -TypeName PSObject |
                                Add-Member -MemberType ScriptProperty -Name 'Domain' -Value {
                                    New-Object -TypeName PSObject |
                                        Add-Member -MemberType ScriptMethod -Name 'ToString' -Value {
                                            return $mockDomainName
                                        } -PassThru -Force
                                } -PassThru |
                                Add-Member -MemberType NoteProperty -Name 'SiteName' -Value $mockSiteName -PassThru -Force
                        }

                        $getTargetResourceParameters = $mockDefaultParameters.Clone()
                    }

                    Context 'When using the default parameters' {
                        It 'Should return the same values as passed as parameters' {
                            $result = Get-TargetResource @getTargetResourceParameters
                            $result.DomainName | Should -Be $mockDomainName
                        }

                        It 'Should return default value for property WaitTimeout' {
                            $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                            $getTargetResourceResult.WaitTimeout | Should -Be 300
                        }

                        It 'Should return $null for the rest of the properties' {
                            $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                            $getTargetResourceResult.SiteName | Should -Be 'Europe'
                            $getTargetResourceResult.Credential | Should -BeNullOrEmpty
                            $getTargetResourceResult.RestartCount | Should -Be 0
                        }
                    }

                    Context 'When using all available parameters' {
                        BeforeAll {
                            $getTargetResourceParameters['Credential'] = $mockDomainUserCredential
                            $getTargetResourceParameters['SiteName'] = 'Europe'
                            $getTargetResourceParameters['WaitTimeout'] = 600
                            $getTargetResourceParameters['RestartCount'] = 2
                        }

                        It 'Should return the same values as passed as parameters' {
                            $result = Get-TargetResource @getTargetResourceParameters
                            $result.DomainName | Should -Be $mockDomainName
                            $result.SiteName | Should -Be 'Europe'
                            $result.WaitTimeout | Should -Be 600
                            $result.RestartCount | Should -Be 2
                            $result.Credential.UserName | Should -Be $mockUserName
                        }
                    }

                    Context 'When using all available parameters' {
                        BeforeAll {
                            $mockBuiltInCredentialName = 'BuiltInCredential'

                            # Mock PsDscRunAsCredential context.
                            $PsDscContext = @{
                                RunAsUser = $mockBuiltInCredentialName
                            }

                            Mock -CommandName Write-Verbose -ParameterFilter {
                                $Message -eq ($script:localizedData.ImpersonatingCredentials -f $mockBuiltInCredentialName)
                            } -MockWith {
                                Write-Verbose -Message ('VERBOSE OUTPUT FROM MOCK: {0}' -f $Message) -Verbose
                            }

                            $getTargetResourceParameters = $mockDefaultParameters.Clone()
                        }

                        It 'Should return the same values as passed as parameters' {
                            $result = Get-TargetResource @getTargetResourceParameters
                            $result.DomainName | Should -Be $mockDomainName
                            $result.Credential | Should -BeNullOrEmpty

                            Assert-MockCalled -CommandName Write-Verbose -Exactly -Times 1 -Scope It
                        }
                    }
                }
            }
        }
        #endregion


        #region Function Test-TargetResource
        Describe 'WaitForADDomain\Test-TargetResource' -tag 'Test' {
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
                        $testTargetResourceResult = Test-TargetResource @mockDefaultParameters
                        $testTargetResourceResult | Should -BeTrue

                        Assert-MockCalled -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
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

                        $testTargetResourceParameters = $mockDefaultParameters.Clone()
                        $testTargetResourceParameters['RestartCount'] = 2
                    }

                    It 'Should return $true' {
                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeTrue

                        Assert-MockCalled -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                        Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                        Assert-MockCalled -CommandName Remove-Item -Exactly -Times 1 -Scope It
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
                        $testTargetResourceResult = Test-TargetResource @mockDefaultParameters
                        $testTargetResourceResult | Should -BeFalse

                        Assert-MockCalled -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
                    }
                }
            }
        }
        #endregion

        Describe 'MSFT_ADDomainTrust\Compare-TargetResourceState' -Tag 'Compare' {
            BeforeAll {
                $mockGetTargetResource_Absent = {
                    return @{
                        DomainName   = $mockDomainName
                        SiteName     = $null
                        Credential   = $null
                        WaitTimeout  = 300
                        RestartCount = 0
                        IsAvailable  = $false
                    }
                }

                $mockGetTargetResource_Present = {
                    return @{
                        DomainName   = $mockDomainName
                        SiteName     = $mockSiteName
                        Credential   = $null
                        WaitTimeout  = 300
                        RestartCount = 0
                        IsAvailable  = $true
                    }
                }
            }

            Context 'When the system is in the desired state' {
                Context 'When a domain controller is found' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $testTargetResourceParameters = $mockDefaultParameters.Clone()
                        $testTargetResourceParameters['DomainName'] = $mockDomainName
                    }

                    It 'Should return the correct values' {
                        $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
                        $compareTargetResourceStateResult | Should -HaveCount 1

                        $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'IsAvailable' })
                        $comparedReturnValue | Should -Not -BeNullOrEmpty
                        $comparedReturnValue.Expected | Should -Be $true
                        $comparedReturnValue.Actual | Should -Be $true
                        $comparedReturnValue.InDesiredState | Should -BeTrue

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }

            }

            Context 'When the system is not in the desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Absent

                    $testTargetResourceParameters = $mockDefaultParameters.Clone()
                    $testTargetResourceParameters['DomainName'] = $mockDomainName
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
                    $compareTargetResourceStateResult | Should -HaveCount 1

                    $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'IsAvailable' })
                    $comparedReturnValue | Should -Not -BeNullOrEmpty
                    $comparedReturnValue.Expected | Should -Be $true
                    $comparedReturnValue.Actual | Should -Be $false
                    $comparedReturnValue.InDesiredState | Should -BeFalse

                    Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                }
            }
        }

        #region Function Set-TargetResource
        Describe 'WaitForADDomain\Set-TargetResource' -Tag 'Set' {
            BeforeEach {
                $global:DSCMachineStatus = $null
            }

            It "Doesn't throw exception and doesn't call Start-Sleep, Clear-DnsClientCache or set `$global:DSCMachineStatus when domain found" {
                Mock -CommandName Get-Domain -MockWith { return $fakeDomainObject }
                Mock -CommandName Start-Sleep
                Mock -CommandName Clear-DnsClientCache
                { Set-TargetResource @testParams } | Should -Not -Throw
                $global:DSCMachineStatus | Should -Not -Be 1
                Assert-MockCalled -CommandName Start-Sleep -Times 0 -Scope It
                Assert-MockCalled -CommandName Clear-DnsClientCache -Times 0 -Scope It
            }

            It "Throws exception and does not set `$global:DSCMachineStatus when domain not found after $($testParams.RetryCount) retries when RebootRetryCount is not set" {
                Mock -CommandName Get-Domain
                { Set-TargetResource @testParams } | Should -Throw
                $global:DSCMachineStatus | Should -Not -Be 1
            }

            It "Throws exception when domain not found after $($rebootTestParams.RebootRetryCount) reboot retries when RebootRetryCount is exceeded" {
                Mock -CommandName Get-Domain
                Mock -CommandName Get-Content -MockWith { return $rebootTestParams.RebootRetryCount }
                { Set-TargetResource @rebootTestParams } | Should -Throw
            }

            It "Calls Set-Content if reboot count is less than RebootRetryCount when domain not found" {
                Mock -CommandName Get-Domain
                Mock -CommandName Get-Content -MockWith { return 0 }
                Mock -CommandName Set-Content
                { Set-TargetResource @rebootTestParams } | Should -Not -Throw
                Assert-MockCalled -CommandName Set-Content -Times 1 -Exactly -Scope It
            }

            It "Sets `$global:DSCMachineStatus = 1 and does not throw an exception if the domain is not found and RebootRetryCount is not exceeded" {
                Mock -CommandName Get-Domain
                Mock -CommandName Get-Content -MockWith { return 0 }
                { Set-TargetResource @rebootTestParams } | Should -Not -Throw
                $global:DSCMachineStatus | Should -Be 1
            }

            It "Calls Get-Domain exactly $($testParams.RetryCount) times when domain not found" {
                Mock -CommandName Get-Domain
                Mock -CommandName Start-Sleep
                Mock -CommandName Clear-DnsClientCache
                { Set-TargetResource @testParams } | Should -Throw
                Assert-MockCalled -CommandName Get-Domain -Times $testParams.RetryCount -Exactly -Scope It
            }

            It "Calls Start-Sleep exactly $($testParams.RetryCount) times when domain not found" {
                Mock -CommandName Get-Domain
                Mock -CommandName Start-Sleep
                Mock -CommandName Clear-DnsClientCache
                { Set-TargetResource @testParams } | Should -Throw
                Assert-MockCalled -CommandName Start-Sleep -Times $testParams.RetryCount -Exactly -Scope It
            }

            It "Calls Clear-DnsClientCache exactly $($testParams.RetryCount) times when domain not found" {
                Mock -CommandName Get-Domain
                Mock -CommandName Start-Sleep
                Mock -CommandName Clear-DnsClientCache
                { Set-TargetResource @testParams } | Should -Throw
                Assert-MockCalled -CommandName Clear-DnsClientCache -Times $testParams.RetryCount -Exactly -Scope It
            }
        }
        #endregion

        Describe 'MSFT_ADDomainTrust\WaitForDomainControllerScriptBlock' -Tag 'Helper' {
            BeforeAll {
                Mock -CommandName Clear-DnsClientCache
                Mock -CommandName Start-Sleep
            }

            Context 'When a domain controller cannot be found' {
                BeforeAll {
                    Mock -CommandName Find-DomainController
                }

                It 'Should not throw and call the correct mocks' {
                    Invoke-Command -ScriptBlock $script:waitForDomainControllerScriptBlock -ArgumentList @(
                        'contoso.com' # DomainName
                        'Europe', # SiteName
                        $mockDomainUserCredential, # Credential
                        $true # RunOnce
                    )

                    Assert-MockCalled -CommandName Find-DomainController -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Clear-DnsClientCache -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Start-Sleep -Exactly -Times 1 -Scope It
                }
            }

            Context 'When a domain controller is found' {
                BeforeAll {
                    Mock -CommandName Find-DomainController -MockWith {
                        return New-Object -TypeName 'PSObject'
                    }
                }

                It 'Should not throw and call the correct mocks' {
                    Invoke-Command -ScriptBlock $script:waitForDomainControllerScriptBlock -ArgumentList @(
                        'contoso.com' # DomainName
                        'Europe', # SiteName
                        $null, # Credential
                        $true # RunOnce
                    )

                    Assert-MockCalled -CommandName Find-DomainController -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Clear-DnsClientCache -Exactly -Times 0 -Scope It
                    Assert-MockCalled -CommandName Start-Sleep -Exactly -Times 0 -Scope It
                }
            }
        }
    }
    #endregion
}
finally
{
    Invoke-TestCleanup
}
