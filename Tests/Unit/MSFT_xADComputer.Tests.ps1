[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param()

$script:dscModuleName = 'xActiveDirectory'
$script:dscResourceName = 'MSFT_xADComputer'

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

# TODO: Insert the correct <ModuleName> and <ResourceName> for your resource
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
        $mockComputerNamePresent = 'TEST01'
        $mockComputerNameAbsent = 'MISSING01'
        $mockLocation = 'Test location'
        $mockDnsHostName = '{0}.contoso.com' -f $mockComputerNamePresent
        $mockServicePrincipalNames = @('spn/a', 'spn/b')
        $mockUserPrincipalName = '{0}@contoso.com' -f $mockComputerNamePresent
        $mockDisplayName = $mockComputerNamePresent
        $mockDescription = 'Test description'
        $mockEnabled = $true
        $mockManagedBy = 'CN=Manager,CN=Users,DC=contoso,DC=com'
        $mockDistinguishedName = 'CN={0},CN=Computers,DC=contoso,DC=com' -f $mockComputerNamePresent
        $mockSamAccountName = '{0}$' -f $mockComputerNamePresent
        $mockSID = 'S-1-5-21-1409167834-891301383-2860967316-1143'
        $mockObjectClass = 'Computer'
        $mockParentContainer = 'CN=Computers,DC=contoso,DC=com'

        $mockCredentialUserName = 'COMPANY\User'
        $mockCredentialPassword = 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockCredentialUserName, $mockCredentialPassword
        )

        $mockGetADComputer = {
            return @{
                CN                    = $mockComputerNamePresent
                Location              = $mockLocation
                DnsHostName           = $mockDnsHostName
                ServicePrincipalNames = $mockServicePrincipalNames
                UserPrincipalName     = $mockUserPrincipalName
                DisplayName           = $mockDisplayName
                Description           = $mockDescription
                Enabled               = $mockEnabled
                ManagedBy             = $mockManagedBy
                DistinguishedName     = $mockDistinguishedName
                SamAccountName        = $mockSamAccountName
                SID                   = $mockSID
                ObjectClass           = $mockObjectClass
            }
        }

        Describe 'MSFT_xADComputer\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                Mock -CommandName Assert-Module
            }

            Context 'When the system is in the desired state' {
                Context 'When the computer account is absent in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith {
                            throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                        }

                        $getTargetResourceParameters = @{
                            ComputerName                  = $mockComputerNamePresent
                            DomainController              = 'DC01'
                            DomainAdministratorCredential = $mockCredential
                            RequestFile                   = 'TestDrive:\ODJ.txt'
                            RestoreFromRecycleBin         = $false
                            EnabledOnCreation             = $false
                        }
                    }

                    It 'Should return the state as absent' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.Ensure | Should -Be 'Absent'

                        Assert-MockCalled -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
                    }

                    It 'Should return the same values as passed as parameters' {
                        $result = Get-TargetResource @getTargetResourceParameters
                        $result.DomainController | Should -Be $getTargetResourceParameters.DomainController
                        $result.DomainAdministratorCredential.UserName | Should -Be $getTargetResourceParameters.DomainAdministratorCredential.UserName
                        $result.RequestFile | Should -Be $getTargetResourceParameters.RequestFile
                        $result.RestoreFromRecycleBin | Should -Be $getTargetResourceParameters.RestoreFromRecycleBin
                        $result.EnabledOnCreation | Should -Be $getTargetResourceParameters.EnabledOnCreation
                    }

                    It 'Should return $null for the rest of the properties' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.ComputerName | Should -BeNullOrEmpty
                        $getTargetResourceResult.Location | Should -BeNullOrEmpty
                        $getTargetResourceResult.DnsHostName | Should -BeNullOrEmpty
                        $getTargetResourceResult.ServicePrincipalNames | Should -BeNullOrEmpty
                        $getTargetResourceResult.UserPrincipalName | Should -BeNullOrEmpty
                        $getTargetResourceResult.DisplayName | Should -BeNullOrEmpty
                        $getTargetResourceResult.Path | Should -BeNullOrEmpty
                        $getTargetResourceResult.Description | Should -BeNullOrEmpty
                        $getTargetResourceResult.Enabled | Should -BeFalse
                        $getTargetResourceResult.Manager | Should -BeFalse
                        $getTargetResourceResult.DistinguishedName | Should -BeNullOrEmpty
                        $getTargetResourceResult.SID | Should -BeNullOrEmpty
                        $getTargetResourceResult.SamAccountName | Should -BeNullOrEmpty
                    }
                }

                Context 'When the computer account is present in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer

                        $getTargetResourceParameters = @{
                            ComputerName                  = $mockComputerNamePresent
                            DomainController              = 'DC01'
                            DomainAdministratorCredential = $mockCredential
                            RequestFile                   = 'TestDrive:\ODJ.txt'
                            RestoreFromRecycleBin         = $false
                            EnabledOnCreation             = $false
                        }
                    }

                    It 'Should return the state as present' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.Ensure | Should -Be 'Present'

                        Assert-MockCalled -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
                    }

                    It 'Should return the same values as passed as parameters' {
                        $result = Get-TargetResource @getTargetResourceParameters
                        $result.DomainController | Should -Be $getTargetResourceParameters.DomainController
                        $result.DomainAdministratorCredential.UserName | Should -Be $getTargetResourceParameters.DomainAdministratorCredential.UserName
                        $result.RequestFile | Should -Be $getTargetResourceParameters.RequestFile
                        $result.RestoreFromRecycleBin | Should -Be $getTargetResourceParameters.RestoreFromRecycleBin
                        $result.EnabledOnCreation | Should -Be $getTargetResourceParameters.EnabledOnCreation
                    }

                    It 'Should return correct values for the rest of the properties' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.ComputerName | Should -Be $mockComputerNamePresent
                        $getTargetResourceResult.Location | Should -Be $mockLocation
                        $getTargetResourceResult.DnsHostName | Should -Be $mockDnsHostName
                        $getTargetResourceResult.ServicePrincipalNames | Should -Be $mockServicePrincipalNames
                        $getTargetResourceResult.UserPrincipalName | Should -Be $mockUserPrincipalName
                        $getTargetResourceResult.DisplayName | Should -Be $mockDisplayName
                        $getTargetResourceResult.Path | Should -Be $mockParentContainer
                        $getTargetResourceResult.Description | Should -Be $mockDescription
                        $getTargetResourceResult.Enabled | Should -BeTrue
                        $getTargetResourceResult.Manager | Should -Be $mockManagedBy
                        $getTargetResourceResult.DistinguishedName | Should -Be $mockDistinguishedName
                        $getTargetResourceResult.SID | Should -Be $mockSID
                        $getTargetResourceResult.SamAccountName | Should -Be $mockSamAccountName
                    }
                }

                Context 'When the the parameter Enabled is used' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer
                        Mock -CommandName Write-Warning

                        $getTargetResourceParameters = @{
                            ComputerName = $mockComputerNamePresent
                            Enabled      = $true
                        }
                    }

                    It 'Should return the state as present, but write a warning message' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.Ensure | Should -Be 'Present'

                        Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When Get-TargetResource is called with only mandatory parameters' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer

                        $getTargetResourceParameters = @{
                            ComputerName = $mockComputerNamePresent
                        }
                    }

                    It 'Should only call Get-ADComputer with only Identity parameter' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.Ensure | Should -Be 'Present'

                        Assert-MockCalled -CommandName Get-ADComputer -ParameterFilter {
                            $PSBoundParameters.ContainsKey('Identity') `
                                -and -not $PSBoundParameters.ContainsKey('Server') `
                                -and -not $PSBoundParameters.ContainsKey('Credential')
                        } -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When Get-TargetResource is called with DomainController parameter' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer

                        $getTargetResourceParameters = @{
                            ComputerName     = $mockComputerNamePresent
                            DomainController = 'DC01'
                        }
                    }

                    It 'Should only call Get-ADComputer with Identity and Server parameter' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.Ensure | Should -Be 'Present'

                        Assert-MockCalled -CommandName Get-ADComputer -ParameterFilter {
                            $PSBoundParameters.ContainsKey('Identity') `
                                -and $PSBoundParameters.ContainsKey('Server') `
                                -and -not $PSBoundParameters.ContainsKey('Credential')
                        } -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When Get-TargetResource is called with DomainAdministratorCredential parameter' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer

                        $getTargetResourceParameters = @{
                            ComputerName                  = $mockComputerNamePresent
                            DomainAdministratorCredential = $mockCredential
                        }
                    }

                    It 'Should only call Get-ADComputer with Identity and Credential parameter' {
                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                        $getTargetResourceResult.Ensure | Should -Be 'Present'

                        Assert-MockCalled -CommandName Get-ADComputer -ParameterFilter {
                            $PSBoundParameters.ContainsKey('Identity') `
                                -and -not $PSBoundParameters.ContainsKey('Server') `
                                -and $PSBoundParameters.ContainsKey('Credential')
                        } -Exactly -Times 1 -Scope It
                    }
                }
            }
        }

        Describe 'MSFT_xADComputer\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                Mock -CommandName Assert-Module
            }

            Context 'When the system is in the desired state' {
                Context 'When the computer account is absent in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure                        = 'Absent'
                                ComputerName                  = $null
                                Location                      = $null
                                DnsHostName                   = $null
                                ServicePrincipalNames         = $null
                                UserPrincipalName             = $null
                                DisplayName                   = $null
                                Path                          = $null
                                Description                   = $null
                                Enabled                       = $false
                                Manager                       = $null
                                DomainController              = $null
                                DomainAdministratorCredential = $null
                                RequestFile                   = $null
                                RestoreFromRecycleBin         = $false
                                EnabledOnCreation             = $false
                                DistinguishedName             = $null
                                SID                           = $null
                                SamAccountName                = $null
                            }
                        }

                        $testTargetResourceParameters = @{
                            Ensure       = 'Absent'
                            ComputerName = $mockComputerNamePresent
                        }
                    }

                    It 'Should return $true' {
                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeTrue

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When the computer account is present in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure                        = 'Present'
                                ComputerName                  = $mockComputerNamePresent
                                Location                      = $mockLocation
                                DnsHostName                   = $mockDnsHostName
                                ServicePrincipalNames         = $mockServicePrincipalNames
                                UserPrincipalName             = $mockUserPrincipalName
                                DisplayName                   = $mockDisplayName
                                Path                          = $mockParentContainer
                                Description                   = $mockDescription
                                Enabled                       = $true
                                Manager                       = $mockManagedBy
                                DomainController              = 'DC01'
                                DomainAdministratorCredential = $mockCredential
                                RequestFile                   = 'TestDrive:\ODJ.txt'
                                RestoreFromRecycleBin         = $false
                                EnabledOnCreation             = $false
                                DistinguishedName             = $mockDistinguishedName
                                SID                           = $mockSID
                                SamAccountName                = $mockSamAccountName
                            }
                        }

                        $testTargetResourceParameters = @{
                            ComputerName                  = $mockComputerNamePresent
                            DomainController              = 'DC01'
                            DomainAdministratorCredential = $mockCredential
                            RequestFile                   = 'TestDrive:\ODJ.txt'
                            RestoreFromRecycleBin         = $false
                            EnabledOnCreation             = $false
                        }
                    }

                    It 'Should return $true' {
                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeTrue

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When the the parameter Enabled is used' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure                        = 'Absent'
                            }
                        }

                        Mock -CommandName Write-Warning

                        $testTargetResourceParameters = @{
                            ComputerName = $mockComputerNamePresent
                            Enabled      = $true
                        }
                    }

                    It 'Should return the state as present, but write a warning message' {
                        { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw

                        Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
                    }
                }
            }

            Context 'When the system is not in the desired state' {
                It 'Should ....test-description' {
                    # test-code
                }
            }
        }

        #region Function Test-TargetResource
        # Describe 'xADComputer\Test-TargetResource' {

        #     $testStringProperties = @(
        #         'Location',
        #         'DnsHostName',
        #         'UserPrincipalName',
        #         'DisplayName',
        #         'Path',
        #         'Description',
        #         'Manager'
        #     )
        #     $testArrayProperties = @(
        #         'ServicePrincipalNames'
        #     )
        #     $testBooleanProperties = @(
        #         'Enabled'
        #     )

        #     It "Passes when computer account does not exist and 'Ensure' is 'Absent'" {
        #         Mock -CommandName Get-TargetResource -MockWith { return $testAbsentParams }

        #         Test-TargetResource @testAbsentParams | Should Be $true
        #     }

        #     It "Passes when computer account exists and 'Ensure' is 'Present'" {
        #         Mock -CommandName Get-TargetResource -MockWith { return $testPresentParams }

        #         Test-TargetResource @testPresentParams | Should Be $true
        #     }

        #     It "Fails when computer account does not exist and 'Ensure' is 'Present'" {
        #         Mock -CommandName Get-TargetResource -MockWith { return $testAbsentParams }

        #         Test-TargetResource @testPresentParams | Should Be $false
        #     }

        #     It "Fails when computer account exists, and 'Ensure' is 'Absent'" {
        #         Mock -CommandName Get-TargetResource -MockWith { return $testPresentParams }

        #         Test-TargetResource @testAbsentParams | Should Be $false
        #     }

        #     foreach ($testParameter in $testStringProperties)
        #     {
        #         It "Passes when computer account '$testParameter' matches AD account property" {
        #             $testParameterValue = 'Test Parameter String Value'
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = $testParameterValue
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #         It "Fails when computer account '$testParameter' does not match incorrect AD account property value" {
        #             $testParameterValue = 'Test Parameter String Value'
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $invalidADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $invalidADComputer[$testParameter] = $testParameterValue.Substring(0, ([System.Int32] $testParameterValue.Length / 2))
        #                 return $invalidADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #         It "Fails when computer account '$testParameter' does not match empty AD account property value" {
        #             $testParameterValue = 'Test Parameter String Value'
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $invalidADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $invalidADComputer[$testParameter] = ''
        #                 return $invalidADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #         It "Fails when computer account '$testParameter' does not match null AD account property value" {
        #             $testParameterValue = 'Test Parameter String Value'
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $invalidADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $invalidADComputer[$testParameter] = $null
        #                 return $invalidADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #         It "Passes when empty computer account '$testParameter' matches empty AD account property" {
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = ''
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #         It "Passes when empty computer account '$testParameter' matches null AD account property" {
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = $null
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #     } #end foreach test string property

        #     foreach ($testParameter in $testArrayProperties)
        #     {
        #         It "Passes when computer account '$testParameter' matches empty AD account property" {
        #             $testParameterValue = @()
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = $testParameterValue
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #         It "Passes when computer account '$testParameter' matches single AD account property" {
        #             $testParameterValue = @('Entry1')
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = $testParameterValue
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #         It "Passes when computer account '$testParameter' matches multiple AD account property" {
        #             $testParameterValue = @('Entry1', 'Entry2')
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = $testParameterValue
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #         It "Fails when computer account '$testParameter' does not match AD account property count" {
        #             $testParameterValue = @('Entry1', 'Entry2')
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = @('Entry1')
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #         It "Fails when computer account '$testParameter' does not match AD account property name" {
        #             $testParameterValue = @('Entry1')
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = @('Entry2')
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #         It "Fails when computer account '$testParameter' does not match empty AD account property" {
        #             $testParameterValue = @('Entry1')
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = @()
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #         It "Fails when empty computer account '$testParameter' does not match AD account property" {
        #             $testParameterValue = @()
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = @('ExtraEntry1')
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #     } #end foreach test string property

        #     foreach ($testParameter in $testBooleanProperties)
        #     {
        #         It "Passes when computer account '$testParameter' matches AD account property" {
        #             $testParameterValue = $true
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $validADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $validADComputer[$testParameter] = $testParameterValue
        #                 return $validADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $true
        #         }

        #         It "Fails when computer account '$testParameter' does not match AD account property value" {
        #             $testParameterValue = $true
        #             $testValidPresentParams = $testPresentParams.Clone()
        #             $testValidPresentParams[$testParameter] = $testParameterValue
        #             $invalidADComputer = $testPresentParams.Clone()
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $invalidADComputer[$testParameter] = -not $testParameterValue
        #                 return $invalidADComputer
        #             }

        #             Test-TargetResource @testValidPresentParams | Should Be $false
        #         }

        #     } #end foreach test boolean property

        #     Context 'When configuration is in desired state' {
        #         BeforeAll {
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 return $fakeADComputer
        #             }
        #         }

        #         Context 'When not specifying the parameter Enabled' {
        #             It 'Should return the desired state as $true' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $true
        #             }
        #         }

        #         Context 'When specifying the parameter Enabled with the value $true' {
        #             It 'Should return the desired state as $true' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $true

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $true
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $false' {
        #             It 'Should return the desired state as $true' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $false

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $true
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $false and parameter Enabled with value $true' {
        #             It 'Should return the desired state as $true' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $true
        #                 $setTargetResourceParameters['CreateDisabled'] = $false

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $true
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $true' {
        #             It 'Should return the desired state as $true' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $true

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $true
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $true and parameter Enabled with value $true' {
        #             It 'Should return the desired state as $true' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $true
        #                 $setTargetResourceParameters['CreateDisabled'] = $true

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $true
        #             }
        #         }
        #     }

        #     Context 'When configuration is not in desired state' {
        #         BeforeAll {
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 return $fakeADComputer
        #             }
        #         }

        #         Context 'When specifying the parameter Enabled with the value $false' {
        #             It 'Should return the desired state as $false' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $false

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $false
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $false and parameter Enabled with value $false' {
        #             It 'Should return the desired state as $false' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $false
        #                 $setTargetResourceParameters['CreateDisabled'] = $false

        #                 $testTargetResourceResult = Test-TargetResource @setTargetResourceParameters
        #                 $testTargetResourceResult | Should -Be $false
        #             }
        #         }
        #     }
        # }
        # #endregion

        # #region Function Set-TargetResource
        # Describe 'xADComputer\Set-TargetResource' {
        #     $testStringProperties = @(
        #         'Location',
        #         'DnsHostName',
        #         'UserPrincipalName',
        #         'DisplayName',
        #         'Description'
        #         # Manager is translated to ManagedBy
        #     )

        #     $testArrayProperties = @(
        #         'ServicePrincipalNames'
        #     )
        #     $testBooleanProperties = @(
        #         'Enabled'
        #     )

        #     It "Calls 'New-ADComputer' when 'Ensure' is 'Present' and the account does not exist" {
        #         $newComputerName = 'NEWCOMPUTER'
        #         $newAbsentParams = $testAbsentParams.Clone()
        #         $newAbsentParams['ComputerName'] = $newComputerName
        #         $newPresentParams = $testPresentParams.Clone()
        #         $newPresentParams['ComputerName'] = $newComputerName
        #         Mock -CommandName New-ADComputer -ParameterFilter { $Name -eq $newComputerName }
        #         Mock -CommandName Set-ADComputer
        #         Mock -CommandName Get-TargetResource -ParameterFilter { $ComputerName -eq $newComputerName } -MockWith { return $newAbsentParams }

        #         Set-TargetResource @newPresentParams

        #         Assert-MockCalled -CommandName New-ADComputer -ParameterFilter { $Name -eq $newComputerName } -Scope It
        #     }

        #     It "Calls 'New-ADComputer' when 'Ensure' is 'Present' and the account does not exist, RequestFile is set, DJOIN OK" {
        #         $newComputerName = 'NEWCOMPUTER'
        #         $newAbsentParams = $testAbsentParams.Clone()
        #         $newAbsentParams['ComputerName'] = $newComputerName
        #         $newPresentParams = $testPresentParams.Clone()
        #         $newPresentParams['ComputerName'] = $newComputerName
        #         $newPresentParams['RequestFile'] = 'c:\ODJTest.txt'
        #         Mock -CommandName New-ADComputer -ParameterFilter { $Name -eq $newComputerName }
        #         Mock -CommandName djoin.exe -MockWith {
        #             $LASTEXITCODE = 0
        #             return 'OK'
        #         }
        #         Mock -CommandName Set-ADComputer
        #         Mock -CommandName Get-TargetResource -ParameterFilter { $ComputerName -eq $newComputerName } -MockWith { return $newAbsentParams }

        #         Set-TargetResource @newPresentParams

        #         Assert-MockCalled -CommandName New-ADComputer -ParameterFilter { $Name -eq $newComputerName } -Scope It -Exactly 0
        #         Assert-MockCalled -CommandName djoin.exe -Exactly 1
        #     }

        #     It "Calls 'New-ADComputer' with 'Path' when specified" {
        #         $newComputerName = 'NEWCOMPUTER'
        #         $newAbsentParams = $testAbsentParams.Clone()
        #         $newAbsentParams['ComputerName'] = $newComputerName
        #         $newPresentParams = $testPresentParams.Clone()
        #         $newPresentParams['ComputerName'] = $newComputerName
        #         $targetPath = 'OU=Test,DC=contoso,DC=com'
        #         Mock -CommandName New-ADComputer -ParameterFilter { $Path -eq $targetPath }
        #         Mock -CommandName Set-ADComputer
        #         Mock -CommandName Get-TargetResource -ParameterFilter { $ComputerName -eq $newComputerName } -MockWith { return $newAbsentParams }

        #         Set-TargetResource @newPresentParams -Path $targetPath

        #         Assert-MockCalled -CommandName New-ADComputer -ParameterFilter { $Path -eq $targetPath } -Scope It
        #     }

        #     It "Calls 'Move-ADObject' when 'Ensure' is 'Present', the computer account exists but Path is incorrect" {
        #         $testTargetPath = 'OU=NewPath,DC=contoso,DC=com'
        #         Mock -CommandName Set-ADComputer
        #         Mock -CommandName Get-ADComputer -MockWith {
        #             $duffADComputer = $fakeADComputer.Clone()
        #             $duffADComputer['DistinguishedName'] = 'CN={0},OU=WrongPath,DC=contoso,DC=com' -f $testPresentParams.ComputerName
        #             return $duffADComputer
        #         }
        #         Mock -CommandName Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath }

        #         Set-TargetResource @testPresentParams -Path $testTargetPath

        #         Assert-MockCalled -CommandName Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -Scope It
        #     }

        #     foreach ($testParameter in $testStringProperties)
        #     {
        #         It "Calls 'Set-ADComputer' with 'Remove' when '$testParameter' is `$null" {
        #             Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #             Mock -CommandName Set-ADComputer -ParameterFilter { $Remove.ContainsKey($testParameter) }

        #             $setTargetResourceParams = $testPresentParams.Clone()
        #             $setTargetResourceParams[$testParameter] = ''
        #             Set-TargetResource @setTargetResourceParams

        #             Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter { $Remove.ContainsKey($testParameter) } -Scope It -Exactly 1
        #         }

        #         It "Calls 'Set-ADComputer' with 'Replace' when existing '$testParameter' is not `$null" {
        #             Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #             Mock -CommandName Set-ADComputer -ParameterFilter { $Replace.ContainsKey($testParameter) }

        #             $setTargetResourceParams = $testPresentParams.Clone()
        #             $setTargetResourceParams[$testParameter] = 'NewStringValue'
        #             Set-TargetResource @setTargetResourceParams

        #             Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter { $Replace.ContainsKey($testParameter) } -Scope It -Exactly 1
        #         }

        #     } #end foreach string parameter

        #     It "Calls 'Set-ADComputer' with 'Remove' when 'Manager' is `$null" {
        #         ## Manager translates to AD attribute 'managedBy'
        #         Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #         Mock -CommandName Set-ADComputer -ParameterFilter { $Remove.ContainsKey('ManagedBy') }

        #         $setTargetResourceParams = $testPresentParams.Clone()
        #         $setTargetResourceParams['Manager'] = ''
        #         Set-TargetResource @setTargetResourceParams

        #         Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter { $Remove.ContainsKey('ManagedBy') } -Scope It -Exactly 1
        #     }

        #     It "Calls 'Set-ADComputer' with 'Replace' when existing 'Manager' is not `$null" {
        #         ## Manager translates to AD attribute 'managedBy'
        #         Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #         Mock -CommandName Set-ADComputer -ParameterFilter { $Replace.ContainsKey('ManagedBy') }

        #         $setTargetResourceParams = $testPresentParams.Clone()
        #         $setTargetResourceParams['Manager'] = 'NewValue'
        #         Set-TargetResource @setTargetResourceParams

        #         Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter { $Replace.ContainsKey('ManagedBy') } -Scope It -Exactly 1
        #     }

        #     It "Calls 'Set-ADComputer' with 'Enabled' = 'True' by default" {
        #         Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #         Mock -CommandName Set-ADComputer -ParameterFilter { $Enabled -eq $true }

        #         $setTargetResourceParams = $testPresentParams.Clone()
        #         $setTargetResourceParams[$testParameter] = -not $fakeADComputer.$testParameter
        #         Set-TargetResource @setTargetResourceParams

        #         Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter { $Enabled -eq $true } -Scope It -Exactly 1
        #     }

        #     It "Calls 'Set-ADComputer' with 'ServicePrincipalNames' when specified" {
        #         $testSPNs = @('spn/a', 'spn/b')
        #         Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #         Mock -CommandName Set-ADComputer -ParameterFilter { $Replace.ContainsKey('ServicePrincipalName') }

        #         Set-TargetResource @testPresentParams -ServicePrincipalNames $testSPNs

        #         Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter { $Replace.ContainsKey('ServicePrincipalName') } -Scope It -Exactly 1
        #     }

        #     It "Calls 'Remove-ADComputer' when 'Ensure' is 'Absent' and computer account exists" {
        #         Mock -CommandName Get-ADComputer -MockWith { return $fakeADComputer }
        #         Mock -CommandName Remove-ADComputer -ParameterFilter { $Identity.ToString() -eq $testAbsentParams.ComputerName }

        #         Set-TargetResource @testAbsentParams

        #         Assert-MockCalled -CommandName Remove-ADComputer -ParameterFilter { $Identity.ToString() -eq $testAbsentParams.ComputerName } -Scope It
        #     }

        #     Context 'When RestoreFromRecycleBin is used' {
        #         BeforeAll {
        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 if ($script:mockCounter -gt 0)
        #                 {
        #                     return @{
        #                         Ensure = 'Present'
        #                     }
        #                 }

        #                 $script:mockCounter++

        #                 return @{
        #                     Ensure = 'Absent'
        #                 }
        #             }

        #             Mock -CommandName New-ADComputer
        #             # Had to overwrite parameter filter from an earlier test
        #             Mock -CommandName Set-ADComputer -ParameterFilter {
        #                 return $true
        #             }
        #         }

        #         It 'Should call Restore-AdCommonObject' {
        #             $restoreParam = $testPresentParams.Clone()
        #             $restoreParam.RestoreFromRecycleBin = $true

        #             $script:mockCounter = 0

        #             Mock -CommandName Restore-ADCommonObject -MockWith {
        #                 return [PSCustomObject]@{
        #                     ObjectClass = 'computer'
        #                 }
        #             }

        #             Set-TargetResource @restoreParam

        #             Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
        #             Assert-MockCalled -CommandName New-ADComputer -Times 0 -Exactly -Scope It
        #             Assert-MockCalled -CommandName Set-ADComputer -Exactly -Times 1 -Scope It
        #         }

        #         It 'Should call New-ADComputer if no object was found in the recycle bin' {
        #             $restoreParam = $testPresentParams.Clone()
        #             $restoreParam.RestoreFromRecycleBin = $true
        #             $script:mockCounter = 0

        #             Mock -CommandName Restore-ADCommonObject

        #             Set-TargetResource @restoreParam

        #             Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
        #             Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 1 -Scope It
        #             Assert-MockCalled -CommandName Set-ADComputer -Exactly -Times 1 -Scope It
        #         }

        #         It 'Should throw the correct error when then object cannot be restored from recycle bin' {
        #             $restoreParam = $testPresentParams.Clone()
        #             $restoreParam.RestoreFromRecycleBin = $true
        #             $script:mockCounter = 0


        #             Mock -CommandName Restore-ADCommonObject -MockWith {
        #                 throw (New-Object -TypeName System.InvalidOperationException)
        #             }

        #             { Set-TargetResource @restoreParam } | Should -Throw -ExceptionType ([System.InvalidOperationException])

        #             Assert-MockCalled -CommandName Restore-ADCommonObject -Scope It -Exactly -Times 1
        #             Assert-MockCalled -CommandName New-ADComputer -Scope It -Exactly -Times 0
        #             Assert-MockCalled -CommandName Set-ADComputer -Scope It -Exactly -Times 0
        #         }
        #     }

        #     Context 'When a computer account that should be disabled' {
        #         BeforeAll {
        #             Mock -CommandName Set-ADComputer
        #             Mock -CommandName Set-DscADComputer
        #             Mock -CommandName New-ADComputer

        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 return $fakeADComputer
        #             }
        #         }

        #         Context 'When specifying the parameter Enabled with the value $false' {
        #             It 'Should call Set-ADComputer to disable the computer account' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $false

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -Scope It -Exactly -Times 0
        #                 Assert-MockCalled -CommandName Set-DscADComputer -ParameterFilter {
        #                     $SetADComputerParameters.Enabled -eq $false
        #                 } -Scope It -Exactly -Times 1
        #             }
        #         }
        #     }

        #     Context 'When a computer account that should be enabled' {
        #         BeforeAll {
        #             Mock -CommandName Set-ADComputer
        #             Mock -CommandName Set-DscADComputer
        #             Mock -CommandName New-ADComputer

        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 $disabledFakeADComputer = $fakeADComputer.Clone()
        #                 $disabledFakeADComputer['Enabled'] = $false
        #                 return $disabledFakeADComputer
        #             }
        #         }

        #         Context 'When specifying the parameter Enabled with the value $true' {
        #             It 'Should call Set-ADComputer to enable the computer account' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $true

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -Scope It -Exactly -Times 0
        #                 Assert-MockCalled -CommandName Set-DscADComputer -ParameterFilter {
        #                     $SetADComputerParameters.Enabled -eq $true
        #                 } -Scope It -Exactly -Times 1
        #             }
        #         }
        #     }

        #     Context 'When creating a computer account that should be enabled' {
        #         BeforeAll {
        #             Mock -CommandName Set-ADComputer
        #             Mock -CommandName New-ADComputer

        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 return @{
        #                     Ensure = 'Absent'
        #                 }
        #             }
        #         }

        #         Context 'When not specifying the parameter Enabled' {
        #             It 'Should create a computer account that is enabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }

        #         Context 'When specifying the parameter Enabled with the value $true' {
        #             It 'Should create a computer account that is enabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $true

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $false and parameter Enabled with value $true' {
        #             It 'Should create a computer account that is enabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $false
        #                 $setTargetResourceParameters['Enabled'] = $true

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $true and parameter Enabled with value $true' {
        #             It 'Should create a computer account that are enabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $true
        #                 $setTargetResourceParameters['Enabled'] = $true

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }
        #     }

        #     Context 'When creating a computer account that should be disabled' {
        #         BeforeAll {
        #             Mock -CommandName Set-ADComputer
        #             Mock -CommandName New-ADComputer

        #             Mock -CommandName Get-TargetResource -MockWith {
        #                 return @{
        #                     Ensure = 'Absent'

        #                     # This is needed for the second call to Get-TargetResource.
        #                     # Enabled = $true
        #                 }
        #             }
        #         }

        #         Context 'When specifying the parameter Enabled with the value $false' {
        #             It 'Should create a computer account that is disabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['Enabled'] = $false

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $true' {
        #             It 'Should create a computer account that is disabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $true

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $false and Enabled with value $false' {
        #             It 'Should create a computer account that is disabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $false
        #                 $setTargetResourceParameters['Enabled'] = $false

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }

        #         Context 'When specifying the parameter CreateDisabled with the value $true and Enabled with value $false' {
        #             It 'Should create a computer account that is disabled' {
        #                 $setTargetResourceParameters = $testPresentParams.Clone()
        #                 $setTargetResourceParameters['CreateDisabled'] = $true
        #                 $setTargetResourceParameters['Enabled'] = $false

        #                 Set-TargetResource @setTargetResourceParameters

        #                 Assert-MockCalled -CommandName New-ADComputer -ParameterFilter {
        #                     $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 1

        #                 Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
        #                     $Enabled -eq $true -or $Enabled -eq $false
        #                 } -Scope It -Exactly -Times 0
        #             }
        #         }
        #     }
        #}
        #endregion
    }
    #endregion
}
finally
{
    Invoke-TestCleanup
}
