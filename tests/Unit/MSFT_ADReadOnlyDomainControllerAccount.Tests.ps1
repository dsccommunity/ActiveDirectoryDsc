[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
param ()

$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADReadOnlyDomainControllerAccount'

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

# Begin Testing

Invoke-TestSetup

try
{
    InModuleScope $script:dscResourceName {
        Set-StrictMode -Version 1.0

        # Load stub cmdlets and classes.
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1') -Force
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ADDSDeployment_2019.psm1') -Force

        #region Pester Test Variable Initialization
        $domainControllerAccountName = 'RODC01'
        $correctDomainName = 'present.com'
        $testAdminCredential = [System.Management.Automation.PSCredential]::Empty
        $correctSiteName = 'PresentSite'
        $incorrectSiteName = 'IncorrectSite'
        $mockNtdsSettingsObjectDn = 'CN=NTDS Settings,CN=ServerName,CN=Servers,CN=PresentSite,CN=Sites,CN=Configuration,DC=present,DC=com'
        $delegatedAdminAccount = 'contoso\delegatedAdminAccount'
        $delegatedAdminAccountSid = 'S-1-0-0'
        $allowedAccount = 'allowedAccount'
        $deniedAccount = 'deniedAccount'

        $testDefaultParams = @{
            DomainControllerAccountName   = $domainControllerAccountName
            Credential                    = $testAdminCredential
        }

        #endregion Pester Test Variable Initialization

        #region Function Get-TargetResource
        Describe 'ADReadOnlyDomainControllerAccount\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                Mock -CommandName Assert-Module
            }

            Context 'When the domain name is not available' {
                BeforeAll {
                    Mock -CommandName Get-DomainObject -MockWith {
                        return $null
                    }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName } |
                        Should -Throw ($script:localizedData.MissingDomain -f $correctDomainName)
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-DomainObject `
                        -Exactly -Times 1
                }
            }

            Context 'When the system is in the desired state' {
                BeforeAll {
                    Mock -CommandName Get-DomainObject -MockWith { $true }
                    Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy
                }

                Context 'When the Read-Only Domain Controller account exists' {
                    BeforeAll {
                        $mockDomainControllerObject = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADDomainController
                        $mockDomainControllerComputerObject = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADComputer
                        $mockDomainControllerDelegatedAdminObject = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADObject
                        $mockDomainControllerObject.Name = $domainControllerAccountName
                        $mockDomainControllerObject.Site = $correctSiteName
                        $mockDomainControllerObject.Domain = $correctDomainName
                        $mockDomainControllerObject.IsGlobalCatalog = $true
                        $mockDomainControllerObject.IsReadOnly = $true
                        $mockDomainControllerDelegatedAdminObject.objectSid = $delegatedAdminAccountSid
                        $mockDomainControllerComputerObject.ManagedBy = $mockDomainControllerDelegatedAdminObject
                        $mockDomainControllerObject.ComputerObjectDN = $mockDomainControllerComputerObject
                        $mockGetADDomainControllerPasswordReplicationAllowedPolicy = @{
                            SamAccountName = $allowedAccount
                        }
                        $mockGetADDomainControllerPasswordReplicationDeniedPolicy = @{
                            SamAccountName = $deniedAccount
                        }

                        Mock -CommandName Get-DomainControllerObject { $mockDomainControllerObject }

                        Mock -CommandName Get-ADComputer { $mockDomainControllerComputerObject }

                        Mock -CommandName Get-ADObject { $mockDomainControllerDelegatedAdminObject }

                        Mock -CommandName Resolve-SamAccountName `
                            -ParameterFilter { $ObjectSid -eq $delegatedAdminAccountSid } `
                            -MockWith { $delegatedAdminAccount }

                        Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                            -ParameterFilter { $Allowed.IsPresent } `
                            -MockWith { $mockGetADDomainControllerPasswordReplicationAllowedPolicy }

                        Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                            -ParameterFilter { $Denied.IsPresent } `
                            -MockWith { $mockGetADDomainControllerPasswordReplicationDeniedPolicy }
                    }

                    It 'Should return the expected result' {
                        $result = Get-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName

                        $result.DomainControllerAccountName | Should -Be $domainControllerAccountName
                        $result.DomainName | Should -Be $correctDomainName
                        $result.SiteName | Should -Be $correctSiteName
                        $result.Ensure | Should -BeTrue
                        $result.IsGlobalCatalog | Should -BeTrue
                        $result.DelegatedAdministratorAccountName | Should -Be $delegatedAdminAccount
                        $result.AllowPasswordReplicationAccountName | Should -HaveCount 1
                        $result.AllowPasswordReplicationAccountName | Should -Be $allowedAccount
                        $result.DenyPasswordReplicationAccountName | Should -Be $deniedAccount
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-DomainObject `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-DomainControllerObject `
                            -ParameterFilter { $DomainName -eq $correctDomainName -and $ComputerName -eq $domainControllerAccountName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADComputer `
                            -ParameterFilter { $Properties -eq 'ManagedBy' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADObject `
                            -ParameterFilter { $Properties -eq 'objectSid' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Resolve-SamAccountName `
                            -ParameterFilter { $ObjectSid -eq $delegatedAdminAccountSid } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                            -ParameterFilter { $Allowed -eq $true } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                            -ParameterFilter { $Denied -eq $true } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Read-Only Domain Controller account does not exist' {
                    BeforeAll {
                        Mock -CommandName Get-DomainControllerObject
                    }

                    It 'Should return the expected result' {
                        $result = Get-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName

                        $result.DomainControllerAccountName | Should -Be $domainControllerAccountName
                        $result.DomainName | Should -Be $correctDomainName
                        $result.SiteName | Should -BeNullOrEmpty
                        $result.Ensure | Should -BeFalse
                        $result.IsGlobalCatalog | Should -BeFalse
                        $result.DelegatedAdministratorAccountName | Should -BeNullOrEmpty
                        $result.AllowPasswordReplicationAccountName | Should -BeNullOrEmpty
                        $result.DenyPasswordReplicationAccountName | Should -BeNullOrEmpty
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-DomainObject `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-DomainControllerObject `
                            -ParameterFilter { $DomainName -eq $correctDomainName -and $ComputerName -eq $domainControllerAccountName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                            -ParameterFilter { $Allowed -eq $true } `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                            -ParameterFilter { $Denied -eq $true } `
                            -Exactly -Times 0
                    }
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADReadOnlyDomainControllerAccount\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $mockGetADDomainControllerPasswordReplicationAllowedPolicy = @{
                    SamAccountName = $allowedAccount
                }
                $mockGetADDomainControllerPasswordReplicationDeniedPolicy = @{
                    SamAccountName = $deniedAccount
                }

                Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                    -ParameterFilter { $Allowed.IsPresent } `
                    -MockWith { $mockGetADDomainControllerPasswordReplicationAllowedPolicy }

                Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy `
                    -ParameterFilter { $Denied.IsPresent } `
                    -MockWith { $mockGetADDomainControllerPasswordReplicationDeniedPolicy }
            }

            Context 'When the system is in the desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainControllerAccountName         = $domainControllerAccountName
                            DomainName                          = $correctDomainName
                            SiteName                            = $correctSiteName
                            IsGlobalCatalog                     = $true
                            DelegatedAdministratorAccountName   = $delegatedAdminAccount
                            AllowPasswordReplicationAccountName = @($allowedAccount)
                            DenyPasswordReplicationAccountName  = @($deniedAccount)
                            Ensure                              = $true
                        }
                    }

                    Mock -CommandName Test-ADReplicationSite -MockWith { $true }
                }

                Context 'When creating a read only domain controller account with only mandatory parameters' {
                    It 'Should return $true' {
                        $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName
                        $result | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }

                Context 'When property IsGlobalCatalog is in desired state' {
                    It 'Should return $true' {
                        $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                            -IsGlobalCatalog $true
                        $result | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }

                Context 'When property DelegatedAdministratorAccountName is in desired state' {
                    It 'Should return $true' {
                        $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                            -DelegatedAdministratorAccountName $delegatedAdminAccount
                        $result | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }

                Context 'When property AllowPasswordReplicationAccountName is in desired state' {
                    It 'Should return $true' {
                        $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                            -AllowPasswordReplicationAccountName @($allowedAccount)
                        $result | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }

                Context 'When property DenyPasswordReplicationAccountName is in desired state' {
                    It 'Should return $true' {
                        $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                            -DenyPasswordReplicationAccountName @($deniedAccount)
                        $result | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }
            }

            Context 'When the system is not in the desired state' {
                BeforeAll {
                    Mock -CommandName Test-ADReplicationSite -MockWith { $true }
                }

                Context 'When creating a read only domain controller account with only mandatory parameters' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                DomainControllerAccountName = $domainControllerAccountName
                                DomainName                  = 'WrongDomainName'
                                Ensure                      = $false
                            }
                        }
                    }

                    It 'Should return $false' {
                        $result = Test-TargetResource @testDefaultParams -DomainName 'WrongDomainName' -SiteName $correctSiteName
                        $result | Should -BeFalse
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }

                Context 'When properties are not in desired state' {
                    Context 'When property SiteName is not in desired state' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return @{
                                    DomainControllerAccountName = $domainControllerAccountName
                                    DomainName                  = $correctDomainName
                                    SiteName                    = $correctSiteName
                                    Ensure                      = $true
                                }
                            }
                        }

                        It 'Should return $false' {
                            $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName `
                                -SiteName 'NewSiteName'
                            $result | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                            Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                        }
                    }

                    Context 'When property IsGlobalCatalog is not in desired state' {
                        Context 'When Read Only Domain Controller Account should be a Global Catalog' {
                            BeforeAll {
                                Mock -CommandName Get-TargetResource -MockWith {
                                    return @{
                                        DomainControllerAccountName = $domainControllerAccountName
                                        DomainName                  = $correctDomainName
                                        IsGlobalCatalog             = $false
                                        Ensure                      = $true
                                    }
                                }
                            }

                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $true
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }

                        Context 'When Read Only Domain Controller Account should not be a Global Catalog' {
                            BeforeAll {
                                Mock -CommandName Get-TargetResource -MockWith {
                                    return @{
                                        DomainControllerAccountName = $domainControllerAccountName
                                        DomainName                  = $correctDomainName
                                        IsGlobalCatalog             = $true
                                        Ensure                      = $true
                                    }
                                }
                            }

                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $false
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }
                    }

                    Context 'When property DelegatedAdministratorAccountName is not in desired state' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return @{
                                    DomainControllerAccountName       = $domainControllerAccountName
                                    DomainName                        = $correctDomainName
                                    DelegatedAdministratorAccountName = $delegatedAdminAccount
                                    Ensure                            = $true
                                }
                            }
                        }

                        It 'Should return $false' {
                            $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -DelegatedAdministratorAccountName 'contoso\NewDelegatedAdminAccount'
                            $result | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                            Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                        }
                    }

                    Context 'When property AllowPasswordReplicationAccountName is not in desired state' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return @{
                                    DomainControllerAccountName         = $domainControllerAccountName
                                    DomainName                          = $correctDomainName
                                    AllowPasswordReplicationAccountName = @($allowedAccount, 'Member2')
                                    Ensure                              = $true
                                }
                            }
                        }

                        Context 'When there are different members than the desired state' {
                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -AllowPasswordReplicationAccountName @('NewMember1', 'NewMember2')
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }

                        Context 'When there exist less members than the desired state' {
                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -AllowPasswordReplicationAccountName @($allowedAccount, 'Member2', 'NewMember')
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }

                        Context 'When there exist more members that the desired state' {
                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -AllowPasswordReplicationAccountName @($allowedAccount)
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }
                    }

                    Context 'When property DenyPasswordReplicationAccountName is not in desired state' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return @{
                                    DomainControllerAccountName        = $domainControllerAccountName
                                    DomainName                         = $correctDomainName
                                    DenyPasswordReplicationAccountName = @($deniedAccount, 'Member2')
                                    Ensure                             = $true
                                }
                            }
                        }

                        Context 'When there are different members than the desired state' {
                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -DenyPasswordReplicationAccountName @('NewMember1', 'NewMember2')
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }

                        Context 'When there exist less members than the desired state' {
                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -DenyPasswordReplicationAccountName @($allowedAccount, 'Member2', 'NewMember')
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }

                        Context 'When there exist more members that the desired state' {
                            It 'Should return $false' {
                                $result = Test-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -DenyPasswordReplicationAccountName @($allowedAccount)
                                $result | Should -BeFalse
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 1
                                Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                            }
                        }
                    }
                }

                Context 'When a specified site does not exist in the Active Directory' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                DomainControllerAccountName = $domainControllerAccountName
                                DomainName                  = $correctDomainName
                                SiteName                    = $correctSiteName
                                Ensure                      = $true
                            }
                        }

                        Mock -CommandName Test-ADReplicationSite -MockWith {
                            return $false
                        }
                    }

                    It 'Should throw the correct error' {
                        {
                            Test-TargetResource @testDefaultParams -DomainName $correctDomainName `
                                -SiteName $correctSiteName
                        } | Should -Throw ($script:localizedData.FailedToFindSite -f $correctSiteName, $correctDomainName)
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource -Exactly -Times 0
                        Assert-MockCalled -CommandName Test-ADReplicationSite -Exactly -Times 1
                    }
                }
            }
        }
        #endregion

        #region Function Set-TargetResource
        Describe 'ADReadOnlyDomainControllerAccount\Set-TargetResource' -Tag 'Set' {
            Context 'When the system is not in the desired state' {
                BeforeAll {
                    Mock -CommandName Add-ADDSReadOnlyDomainControllerAccount
                    Mock -CommandName Remove-ADDomainControllerPasswordReplicationPolicy
                    Mock -CommandName Add-ADDomainControllerPasswordReplicationPolicy

                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure = $false
                        }
                    }
                }

                Context 'When adding a read only domain controller account that should not be a Global Catalog' {
                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -IsGlobalCatalog $false } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                            $NoGlobalCatalog -eq $true
                        } -Exactly -Times 1
                    }
                }

                Context 'When adding a read only domain controller account with DelegatedAdministratorAccountName' {
                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -DelegatedAdministratorAccountName $delegatedAdminAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                            $DelegatedAdministratorAccountName -eq $delegatedAdminAccount
                        } -Exactly -Times 1
                    }
                }

                Context 'When adding a read only domain controller account with AllowPasswordReplicationAccountName' {
                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -AllowPasswordReplicationAccountName $allowedAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                            $AllowPasswordReplicationAccountName -eq $allowedAccount
                        } -Exactly -Times 1
                    }
                }

                Context 'When adding a read only domain controller account with DenyPasswordReplicationAccountName' {
                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -DenyPasswordReplicationAccountName $deniedAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                            $DenyPasswordReplicationAccountName -eq $deniedAccount
                        } -Exactly -Times 1
                    }
                }

                Context 'When the read only domain controller account should have a DNS installed' {
                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -InstallDns $true } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                            $InstallDns -eq $true
                        } -Exactly -Times 1
                    }
                }

                Context 'When the read only domain controller account should not have a DNS installed' {
                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -InstallDns $false } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                            $InstallDns -eq $false
                        } -Exactly -Times 1
                    }
                }

                Context 'When a read only domain controller account is in the wrong site' {
                    BeforeAll {
                        Mock -CommandName Move-ADDirectoryServer
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure   = $true
                                SiteName = 'IncorrectSite'
                            }
                        }

                        Mock -CommandName Get-DomainControllerObject -MockWith {
                            return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                        }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -SiteName $correctSiteName } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Move-ADDirectoryServer -ParameterFilter {
                            $Site.ToString() -eq $correctSiteName
                        } -Exactly -Times 1
                    }
                }

                Context 'When specifying the IsGlobalCatalog parameter' {
                    BeforeAll {
                        Mock -CommandName Set-ADObject
                        Mock -CommandName Get-DomainControllerObject {
                            return @{
                                NTDSSettingsObjectDN = $mockNtdsSettingsObjectDn
                            }
                        }
                    }

                    Context 'When the read only domain controller account should be a Global Catalog' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return $stubTargetResource = @{
                                    Ensure          = $true
                                    SiteName        = $correctSiteName
                                    IsGlobalCatalog = $false
                                }
                            }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $true } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADObject -ParameterFilter {
                                $Replace['options'] -eq 1
                            } -Exactly -Times 1
                        }
                    }

                    Context 'When the read only domain controller account should not be a Global Catalog' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return $stubTargetResource = @{
                                    Ensure          = $true
                                    SiteName        = $correctSiteName
                                    IsGlobalCatalog = $true
                                }
                            }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $false } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADObject -ParameterFilter {
                                $Replace['options'] -eq 0
                            } -Exactly -Times 1
                        }
                    }

                    Context 'When the read only domain controller account should change state of Global Catalog, but fail to return a read only domain controller object' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return $stubTargetResource = @{
                                    Ensure          = $true
                                    SiteName        = $correctSiteName
                                    IsGlobalCatalog = $true
                                }
                            }

                            Mock -CommandName Get-DomainControllerObject
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $false } | Should -Throw $script:localizedData.ExpectedDomainController
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADObject -Exactly -Times 0
                        }
                    }
                }

                Context 'When DelegatedAdministratorAccountName is not compliant' {
                    Mock -CommandName Set-ADComputer
                    Mock -CommandName Resolve-SecurityIdentifier `
                        -ParameterFilter { $SamAccountName -eq $delegatedAdminAccount } `
                        -MockWith { $delegatedAdminAccountSid }
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure                            = $true
                            SiteName                          = $correctSiteName
                            DelegatedAdministratorAccountName = 'contoso\PresentDelegatedAdminAccount'
                        }
                    }

                    Mock -CommandName Get-DomainControllerObject -MockWith {
                        $stubDomainController = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADDomainController
                        $stubDomainControllerComputerObject = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADComputer
                        $stubDomainController.ComputerObjectDN = $stubDomainControllerComputerObject

                        return $stubDomainController
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -DelegatedAdministratorAccountName $delegatedAdminAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Resolve-SecurityIdentifier -ParameterFilter {
                            $SamAccountName -eq $delegatedAdminAccount
                        } -Exactly -Times 1
                        Assert-MockCalled -CommandName Set-ADComputer -ParameterFilter {
                            $ManagedBy -eq $delegatedAdminAccountSid
                        } -Exactly -Times 1
                    }
                }

                Context 'When AllowPasswordReplicationAccountName is not compliant' {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure                              = $true
                            SiteName                            = $correctSiteName
                            AllowPasswordReplicationAccountName = 'allowedAccount2'
                        }
                    }

                    Mock -CommandName Get-DomainControllerObject -MockWith {
                        $stubDomainController = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADDomainController

                        return $stubDomainController
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -AllowPasswordReplicationAccountName $allowedAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADDomainControllerPasswordReplicationPolicy `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Add-ADDomainControllerPasswordReplicationPolicy `
                            -Exactly -Times 1
                    }
                }

                Context 'When DenyPasswordReplicationAccountName is not compliant' {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure                             = $true
                            SiteName                           = $correctSiteName
                            DenyPasswordReplicationAccountName = 'deniedAccount2'
                        }
                    }

                    Mock -CommandName Get-DomainControllerObject -MockWith {
                        $stubDomainController = New-Object `
                            -TypeName Microsoft.ActiveDirectory.Management.ADDomainController
                        return $stubDomainController
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams  -DomainName $correctDomainName -SiteName $correctSiteName `
                                -DenyPasswordReplicationAccountName $deniedAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADDomainControllerPasswordReplicationPolicy `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Add-ADDomainControllerPasswordReplicationPolicy `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the system is in the desired state' {
                BeforeAll {
                    Mock -CommandName Remove-ADDomainControllerPasswordReplicationPolicy
                    Mock -CommandName Add-ADDomainControllerPasswordReplicationPolicy
                }

                Context 'When the read only domain controller account is in the correct site' {
                    BeforeAll {
                        Mock -CommandName Move-ADDirectoryServer
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure   = $true
                                SiteName = $correctSiteName
                            }
                        }
                        Mock -CommandName Get-DomainControllerObject {
                            return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                        }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Move-ADDirectoryServer -Exactly -Times 0
                    }
                }

                Context 'When specifying the IsGlobalCatalog parameter' {
                    BeforeAll {
                        Mock -CommandName Set-ADObject
                        Mock -CommandName Get-DomainControllerObject {
                            return @{
                                NTDSSettingsObjectDN = $mockNtdsSettingsObjectDn
                            }
                        }
                    }

                    Context 'When the read only domain controller account should be a Global Catalog' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return $stubTargetResource = @{
                                    Ensure          = $true
                                    SiteName        = $correctSiteName
                                    IsGlobalCatalog = $false
                                }
                            }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $true } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADObject -ParameterFilter {
                                $Replace['options'] -eq 1
                            } -Exactly -Times 1
                        }
                    }

                    Context 'When the read only domain controller account already is a Global Catalog' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return $stubTargetResource = @{
                                    Ensure          = $true
                                    SiteName        = $correctSiteName
                                    IsGlobalCatalog = $true
                                }
                            }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -IsGlobalCatalog $true } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADObject -Exactly -Times 0
                        }
                    }

                    Context 'When the read only domain controller account already is not a Global Catalog' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return $stubTargetResource = @{
                                    Ensure          = $true
                                    SiteName        = $correctSiteName
                                    IsGlobalCatalog = $false
                                }
                            }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName `
                                    -IsGlobalCatalog $false } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADObject -Exactly -Times 0
                        }
                    }
                }

                Context 'When DelegatedAdministratorAccountName is correct' {
                    BeforeAll {
                        Mock -CommandName Set-ADComputer
                        Mock -CommandName Resolve-SecurityIdentifier `
                            -ParameterFilter { $SamAccountName -eq $delegatedAdminAccount } `
                            -MockWith { $delegatedAdminAccountSid }
                        Mock -CommandName Get-DomainControllerObject -MockWith {
                            $stubDomainController = New-Object `
                                -TypeName Microsoft.ActiveDirectory.Management.ADDomainController
                            $stubDomainControllerComputerObject = New-Object `
                                -TypeName Microsoft.ActiveDirectory.Management.ADComputer
                            $stubDomainController.ComputerObjectDN = $stubDomainControllerComputerObject

                            return $stubDomainController
                        }

                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure                            = $true
                                SiteName                          = $correctSiteName
                                DelegatedAdministratorAccountName = $delegatedAdminAccount
                            }
                        }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -DelegatedAdministratorAccountName $delegatedAdminAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Resolve-SecurityIdentifier -ParameterFilter {
                            $SamAccountName -eq $delegatedAdminAccount
                        } -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADComputer -Exactly -Times 0
                    }
                }

                Context 'When AllowPasswordReplicationAccountName is correct' {
                    BeforeAll {
                        Mock -CommandName Get-DomainControllerObject -MockWith {
                            $stubDomainController = New-Object `
                                -TypeName Microsoft.ActiveDirectory.Management.ADDomainController

                            return $stubDomainController
                        }

                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                Ensure                              = $true
                                SiteName                            = $correctSiteName
                                AllowPasswordReplicationAccountName = $allowedAccount
                            }
                        }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                -AllowPasswordReplicationAccountName $allowedAccount } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADDomainControllerPasswordReplicationPolicy `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Add-ADDomainControllerPasswordReplicationPolicy `
                            -Exactly -Times 0
                    }

                    Context 'When DenyPasswordReplicationAccountName is correct' {
                        BeforeAll {
                            Mock -CommandName Get-TargetResource -MockWith {
                                return @{
                                    Ensure                             = $true
                                    SiteName                           = $correctSiteName
                                    DenyPasswordReplicationAccountName = $deniedAccount
                                }
                            }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @testDefaultParams -DomainName $correctDomainName -SiteName $correctSiteName `
                                    -DenyPasswordReplicationAccountName $deniedAccount } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Remove-ADDomainControllerPasswordReplicationPolicy `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Add-ADDomainControllerPasswordReplicationPolicy `
                                -Exactly -Times 0
                        }
                    }
                }
            }
        }

        #endregion

        Describe 'ADReadOnlyDomainControllerAccount\Get-MembersToAddAndRemove' -Tag 'Helper' {
            Context 'When there is one desired member' {
                Context 'When there are no current members' {
                    Context 'When proving a $null value for CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers $null
                            $result.MembersToAdd | Should -HaveCount 1
                            $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                            $result.MembersToRemove | Should -BeNullOrEmpty
                        }
                    }

                    Context 'When proving an empty collection for CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers @()
                            $result.MembersToAdd | Should -HaveCount 1
                            $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                            $result.MembersToRemove | Should -BeNullOrEmpty
                        }
                    }
                }

                Context 'When there is one current member' {
                    Context 'When proving a collection for CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers @('OldMember')
                            $result.MembersToAdd | Should -HaveCount 1
                            $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                            $result.MembersToRemove | Should -HaveCount 1
                            $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                        }
                    }

                    Context 'When proving a string value for CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers 'OldMember'
                            $result.MembersToAdd | Should -HaveCount 1
                            $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                            $result.MembersToRemove | Should -HaveCount 1
                            $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                        }
                    }
                }

                Context 'When there is more than one current member' {
                    It 'Should return the correct values' {
                        $result = Get-MembersToAddAndRemove `
                            -DesiredMembers 'Member1' -CurrentMembers @('OldMember1', 'OldMember2')
                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                        $result.MembersToRemove | Should -HaveCount 2
                        $result.MembersToRemove[0].ToString() | Should -Be 'OldMember1'
                        $result.MembersToRemove[1].ToString() | Should -Be 'OldMember2'
                    }
                }
            }

            Context 'When there are no desired members' {
                Context 'When there are no current members' {
                    Context 'When proving a $null value for DesiredMembers and CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers $null
                            $result.MembersToAdd | Should -BeNullOrEmpty
                            $result.MembersToRemove | Should -BeNullOrEmpty
                        }
                    }

                    Context 'When proving an empty collection for DesiredMembers and CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers @() -CurrentMembers @()
                            $result.MembersToAdd | Should -BeNullOrEmpty
                            $result.MembersToRemove | Should -BeNullOrEmpty
                        }
                    }
                }

                Context 'When there is one current member' {
                    Context 'When proving a collection for CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers @('OldMember')
                            $result.MembersToAdd | Should -BeNullOrEmpty
                            $result.MembersToRemove | Should -HaveCount 1
                            $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                        }
                    }

                    Context 'When proving a string value for CurrentMembers' {
                        It 'Should return the correct values' {
                            $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers 'OldMember'
                            $result.MembersToAdd | Should -BeNullOrEmpty
                            $result.MembersToRemove | Should -HaveCount 1
                            $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                        }
                    }
                }

                Context 'When there is more than one current member' {
                    It 'Should return the correct values' {
                        $result = Get-MembersToAddAndRemove -DesiredMembers $null `
                            -CurrentMembers @('OldMember1', 'OldMember2')
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -HaveCount 2
                        $result.MembersToRemove[0].ToString() | Should -Be 'OldMember1'
                        $result.MembersToRemove[1].ToString() | Should -Be 'OldMember2'
                    }
                }
            }

            Context 'When the same members are present in desired members and current members' {
                Context 'When proving a collection for CurrentMembers' {
                    It 'Should return the correct values' {
                        $result = Get-MembersToAddAndRemove -DesiredMembers @('Member1') -CurrentMembers @('Member1')
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }

                Context 'When proving a string value for CurrentMembers' {
                    It 'Should return the correct values' {
                        $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers 'Member1'
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }

            Context 'When there are more desired members than current members' {
                Context 'When proving a collection for CurrentMembers' {
                    It 'Should return the correct values' {
                        $result = Get-MembersToAddAndRemove -DesiredMembers @('Member1', 'Member2') `
                            -CurrentMembers @('Member1')
                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be 'Member2'
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }

            Context 'When there are fewer desired members than current members' {
                Context 'When proving a string value for CurrentMembers' {
                    It 'Should return the correct values' {
                        $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' `
                            -CurrentMembers @('Member1', 'Member2')
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be 'Member2'
                    }
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
