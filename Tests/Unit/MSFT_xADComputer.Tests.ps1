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
        $mockDomain = 'contoso.com'
        $mockComputerNameAbsent = 'MISSING01'
        $mockLocation = 'Test location'
        $mockDnsHostName = '{0}.{1}' -f $mockComputerNamePresent, $mockDomain
        $mockServicePrincipalNames_DefaultValues = @(
            ('TERMSRV/{0}' -f $mockComputerNamePresent),
            ('TERMSRV/{0}.{1}' -f $mockComputerNamePresent, $mockDomain)
        )
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

        Describe 'MSFT_xADComputer\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                Mock -CommandName Assert-Module

                $mockGetADComputer = {
                    return @{
                        CN                    = $mockComputerNamePresent
                        Location              = $mockLocation
                        DnsHostName           = $mockDnsHostName
                        ServicePrincipalNames = $mockServicePrincipalNames + $mockServicePrincipalNames_DefaultValues
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
            }

            Context 'When the Get-ADComputer throws an unhandled error' {
                BeforeAll {
                    $errorMessage = 'Mocked error'
                    Mock -CommandName Get-ADComputer -MockWith {
                        throw $errorMessage
                    }

                    $getTargetResourceParameters = @{
                        ComputerName = $mockComputerNamePresent
                    }
                }

                It 'Should return the state as absent' {
                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw $errorMessage

                    Assert-MockCalled -CommandName Get-ADComputer -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the the parameter Enabled is used' {
                BeforeAll {
                    Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer
                    Mock -CommandName Write-Warning

                    $getTargetResourceParameters = @{
                        ComputerName = $mockComputerNamePresent
                        Enabled      = $true
                        Verbose      = $true
                    }
                }

                It 'Should return the state as present, but write a warning message' {
                    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters
                    $getTargetResourceResult.Ensure | Should -Be 'Present'

                    Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
                }
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
                            Verbose                       = $true
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
                            Verbose                       = $true
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
                        $getTargetResourceResult.ServicePrincipalNames | Should -Be ($mockServicePrincipalNames + $mockServicePrincipalNames_DefaultValues)
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

                Context 'When Get-TargetResource is called with only mandatory parameters' {
                    BeforeAll {
                        Mock -CommandName Get-ADComputer -MockWith $mockGetADComputer

                        $getTargetResourceParameters = @{
                            ComputerName = $mockComputerNamePresent
                            Verbose      = $true
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
                            Verbose          = $true
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
                            Verbose                       = $true
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

                $mockGetTargetResource_Absent = {
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

                $mockGetTargetResource_Present = {
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
            }

            Context 'When the system is in the desired state' {
                Context 'When the computer account is absent in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource $mockGetTargetResource_Absent

                        $testTargetResourceParameters = @{
                            Ensure       = 'Absent'
                            ComputerName = $mockComputerNamePresent
                            Verbose      = $true
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
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $testTargetResourceParameters = @{
                            ComputerName                  = $mockComputerNamePresent
                            DomainController              = 'DC01'
                            DomainAdministratorCredential = $mockCredential
                            RequestFile                   = 'TestDrive:\ODJ.txt'
                            RestoreFromRecycleBin         = $false
                            EnabledOnCreation             = $false
                            Verbose                       = $true
                        }
                    }

                    It 'Should return $true' {
                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeTrue

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When service principal names are in desired state' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $testTargetResourceParameters = @{
                            ComputerName          = $mockComputerNamePresent
                            ServicePrincipalNames = $mockServicePrincipalNames
                            Verbose               = $true
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
                                Ensure = 'Absent'
                            }
                        }

                        Mock -CommandName Write-Warning

                        $testTargetResourceParameters = @{
                            ComputerName = $mockComputerNamePresent
                            Enabled      = $true
                            Verbose      = $true
                        }
                    }

                    It 'Should return the state as present, but write a warning message' {
                        { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw

                        Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
                    }
                }
            }

            Context 'When the system is not in the desired state' {
                Context 'When the computer account is absent in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Absent

                        $testTargetResourceParameters = @{
                            Ensure       = 'Present'
                            ComputerName = $mockComputerNamePresent
                            Verbose      = $true
                        }
                    }

                    It 'Should return $false' {
                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeFalse

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When the computer account is present in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $testTargetResourceParameters = @{
                            Ensure       = 'Absent'
                            ComputerName = $mockComputerNamePresent
                            Verbose      = $true
                        }
                    }

                    It 'Should return $false' {
                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeFalse

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When a property is not in desired state' {
                    BeforeAll {
                        # Mock a specific desired state.
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        # One test case per property with a value that differs from the desired state.
                        $testCases_Properties = @(
                            @{
                                PropertyName = 'Location'
                                Value        = 'NewLocation'
                            },
                            @{
                                PropertyName = 'DnsHostName'
                                Value        = 'New@contoso.com'
                            },
                            @{
                                PropertyName = 'ServicePrincipalName'
                                Value        = @('spn/new')
                            },
                            @{
                                PropertyName = 'UserPrincipalName'
                                Value        = 'New@contoso.com'
                            },
                            @{
                                PropertyName = 'DisplayName'
                                Value        = 'New'
                            },
                            @{
                                PropertyName = 'Path'
                                Value        = 'OU=New,CN=Computers,DC=contoso,DC=com'
                            },
                            @{
                                PropertyName = 'Description'
                                Value        = 'New description'
                            },
                            @{
                                PropertyName = 'Manager'
                                Value        = 'CN=NewManager,CN=Users,DC=contoso,DC=com'
                            }
                        )
                    }

                    It 'Should return $false when property <PropertyName> is not in desired state' -TestCases $testCases_Properties {
                        param
                        (
                            [Parameter()]
                            $PropertyName,

                            [Parameter()]
                            $Value
                        )

                        $testTargetResourceParameters = @{
                            ComputerName  = $mockComputerNamePresent
                            $PropertyName = $Value
                            Verbose       = $true
                        }

                        $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
                        $testTargetResourceResult | Should -BeFalse

                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    }
                }
            }
        }

        Describe 'MSFT_xADComputer\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                Mock -CommandName Assert-Module

                $mockGetTargetResource_Absent = {
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

                $mockGetTargetResource_Present = {
                    return @{
                        Ensure                        = 'Present'
                        ComputerName                  = $mockComputerNamePresent
                        Location                      = $mockLocation
                        DnsHostName                   = $mockDnsHostName
                        ServicePrincipalNames         = $mockServicePrincipalNames_DefaultValues
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
            }

            Context 'When the the parameter Enabled is used' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure = 'Absent'
                        }
                    }

                    Mock -CommandName Write-Warning

                    $setTargetResourceParameters = @{
                        Ensure       = 'Absent'
                        ComputerName = $mockComputerNamePresent
                        Enabled      = $true
                        Verbose      = $true
                    }
                }

                It 'Should return the state as present, but write a warning message' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                    Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the system is in the desired state' {
                BeforeAll {
                    Mock -CommandName Remove-ADComputer
                    Mock -CommandName Set-DscADComputer
                    Mock -CommandName New-ADComputer
                    Mock -CommandName Move-ADObject
                }

                Context 'When the computer account is absent in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Absent

                        $setTargetResourceParameters = @{
                            Ensure       = 'Absent'
                            ComputerName = $mockComputerNamePresent
                            Verbose      = $true
                        }
                    }

                    It 'Should not call any mocks that changes state' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                        Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When the computer account is present in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $setTargetResourceParameters = @{
                            ComputerName                  = $mockComputerNamePresent
                            DomainController              = 'DC01'
                            DomainAdministratorCredential = $mockCredential
                            RequestFile                   = 'TestDrive:\ODJ.txt'
                            RestoreFromRecycleBin         = $false
                            EnabledOnCreation             = $false
                            Verbose                       = $true
                        }
                    }

                    It 'Should not call any mocks that changes state' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                        Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When service principal names are in desired state' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $setTargetResourceParameters = @{
                            ComputerName          = $mockComputerNamePresent
                            ServicePrincipalNames = $mockServicePrincipalNames_DefaultValues
                            Verbose               = $true
                        }
                    }

                    It 'Should not call any mocks that changes state' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                        Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When the system is not in the desired state' {
                BeforeAll {
                    Mock -CommandName Remove-ADComputer
                    Mock -CommandName Set-DscADComputer
                    Mock -CommandName Move-ADObject
                    Mock -CommandName New-ADComputer -MockWith {
                        $script:mockNewADComputerWasCalled = $true
                    }

                }

                Context 'When the computer account is absent in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            if (-not $script:mockNewADComputerWasCalled)
                            {
                                # First call.
                                $mockGetTargetResourceResult = & $mockGetTargetResource_Absent
                            }
                            else
                            {
                                # Second call - After New-ADComputer has been called.
                                $mockGetTargetResourceResult = & $mockGetTargetResource_Present
                            }

                            return $mockGetTargetResourceResult
                        }
                    }

                    BeforeEach {
                        $script:mockNewADComputerWasCalled = $false
                    }

                    Context 'When the computer account is created on the default path' {
                        BeforeAll {
                            $setTargetResourceParameters = @{
                                Ensure       = 'Present'
                                ComputerName = $mockComputerNamePresent
                                Verbose      = $true
                            }
                        }

                        It 'Should call the correct mocks' {
                            { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                            Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 1 -Scope It
                            Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the computer account is created on the specified path' {
                        BeforeAll {
                            $setTargetResourceParameters = @{
                                Ensure       = 'Present'
                                ComputerName = $mockComputerNamePresent
                                Path         = $mockParentContainer
                                Verbose      = $true
                            }
                        }

                        It 'Should call the correct mocks' {
                            { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                            Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 1 -Scope It
                            Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                        }
                    }
                }

                Context 'When the computer account is present in Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                        $setTargetResourceParameters = @{
                            Ensure       = 'Absent'
                            ComputerName = $mockComputerNamePresent
                            Verbose      = $true
                        }
                    }

                    It 'Should call the correct mocks' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                        Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 1 -Scope It
                        Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                        Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When a property is not in desired state' {
                    Context 'When a property should be replaced' {
                        BeforeAll {
                            # Mock a specific desired state.
                            Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                            # One test case per property with a value that differs from the desired state.
                            $testCases_Properties = @(
                                @{
                                    PropertyName = 'Location'
                                    Value        = 'NewLocation'
                                },
                                @{
                                    PropertyName = 'DnsHostName'
                                    Value        = 'New@contoso.com'
                                },
                                @{
                                    ParameterName = 'ServicePrincipalNames'
                                    PropertyName  = 'ServicePrincipalName'
                                    Value         = @('spn/new')
                                },
                                @{
                                    PropertyName = 'UserPrincipalName'
                                    Value        = 'New@contoso.com'
                                },
                                @{
                                    PropertyName = 'DisplayName'
                                    Value        = 'New'
                                },
                                @{
                                    PropertyName = 'Description'
                                    Value        = 'New description'
                                },
                                @{
                                    ParameterName = 'Manager'
                                    PropertyName  = 'ManagedBy'
                                    Value         = 'CN=NewManager,CN=Users,DC=contoso,DC=com'
                                }
                            )
                        }

                        It 'Should set the correct property when property <PropertyName> is not in desired state' -TestCases $testCases_Properties {
                            param
                            (
                                [Parameter()]
                                $PropertyName,

                                [Parameter()]
                                $ParameterName = $PropertyName,

                                [Parameter()]
                                $Value
                            )

                            $setTargetResourceParameters = @{
                                ComputerName   = $mockComputerNamePresent
                                $ParameterName = $Value
                                Verbose        = $true
                            }

                            { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                            Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Set-DscADComputer -ParameterFilter {
                                $Parameters.Replace.ContainsKey($PropertyName) -eq $true
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When a property should be removed' {
                        BeforeAll {
                            # Mock a specific desired state.
                            Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                            # One test case per property with a value that differs from the desired state.
                            $testCases_Properties = @(
                                @{
                                    PropertyName = 'Location'
                                    Value        = $null
                                },
                                @{
                                    PropertyName = 'DnsHostName'
                                    Value        = $null
                                },
                                @{
                                    ParameterName = 'ServicePrincipalNames'
                                    PropertyName  = 'ServicePrincipalName'
                                    Value         = @()
                                },
                                @{
                                    PropertyName = 'UserPrincipalName'
                                    Value        = $null
                                },
                                @{
                                    PropertyName = 'DisplayName'
                                    Value        = $null
                                },
                                @{
                                    PropertyName = 'Description'
                                    Value        = $null
                                },
                                @{
                                    ParameterName = 'Manager'
                                    PropertyName  = 'ManagedBy'
                                    Value         = $null
                                }
                            )
                        }

                        It 'Should set the correct property when property <PropertyName> is not in desired state' -TestCases $testCases_Properties {
                            param
                            (
                                [Parameter()]
                                $PropertyName,

                                [Parameter()]
                                $ParameterName = $PropertyName,

                                [Parameter()]
                                $Value
                            )

                            $setTargetResourceParameters = @{
                                ComputerName   = $mockComputerNamePresent
                                $ParameterName = $Value
                                Verbose        = $true
                            }

                            { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                            Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Set-DscADComputer -ParameterFilter {
                                $Parameters.Remove.ContainsKey($PropertyName) -eq $true
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the computer account should be moved' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

                            $setTargetResourceParameters = @{
                                ComputerName = $mockComputerNamePresent
                                Path         = 'OU=New,CN=Computers,DC=contoso,DC=com'
                                Verbose      = $true
                            }
                        }

                        It 'Should call the correct mock to move the computer account' {
                            { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                            Assert-MockCalled -CommandName Remove-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName New-ADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Set-DscADComputer -Exactly -Times 0 -Scope It
                            Assert-MockCalled -CommandName Move-ADObject -Exactly -Times 1 -Scope It
                        }
                    }
                }
            }
        }

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
