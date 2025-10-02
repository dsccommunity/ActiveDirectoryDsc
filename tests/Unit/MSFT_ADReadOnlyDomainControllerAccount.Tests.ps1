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
    $script:dscResourceName = 'MSFT_ADReadOnlyDomainControllerAccount'

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

Describe 'MSFT_ADReadOnlyDomainControllerAccount\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the domain could not be found' {
        BeforeAll {
            Mock -CommandName Get-DomainObject -MockWith {
                return $null
            }
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainControllerAccountName = 'RODC01'
                    Credential                  = [System.Management.Automation.PSCredential]::Empty
                    DomainName                  = 'present.com'
                    SiteName                    = 'PresentSite'
                }

                $errorRecord = Get-ObjectNotFoundRecord -Message ($script:localizedData.MissingDomain -f $mockParameters.DomainName)

                { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Get-DomainObject -MockWith { $true }
            Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy
        }

        Context 'When the Read-Only Domain Controller account exists' {
            BeforeAll {
                $mockDomainControllerDelegatedAdminObject = [PSCustomObject] @{
                    objectSid = 'S-1-0-0'
                }

                $mockDomainControllerComputerObject = [PSCustomObject] @{
                    ManagedBy = $mockDomainControllerDelegatedAdminObject
                }

                Mock -CommandName Get-DomainControllerObject {
                    [PSCustomObject] @{
                        Name             = 'RODC01'
                        Site             = 'PresentSite'
                        Domain           = 'present.com'
                        IsGlobalCatalog  = $true
                        IsReadOnly       = $true
                        ComputerObjectDN = $mockDomainControllerComputerObject
                        Enabled          = $true
                    }
                }
                Mock -CommandName Get-ADComputer { $mockDomainControllerComputerObject }
                Mock -CommandName Get-ADObject { $mockDomainControllerDelegatedAdminObject }
                Mock -CommandName Resolve-SamAccountName -ParameterFilter { $ObjectSid -eq 'S-1-0-0' } -MockWith { 'contoso\delegatedAdminAccount' }
                Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed.IsPresent } -MockWith {
                    @{
                        SamAccountName = 'allowedAccount'
                    }
                }

                Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied.IsPresent } -MockWith {
                    @{
                        SamAccountName = 'deniedAccount'
                    }
                }
            }

            It 'Should return the expected result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainControllerAccountName | Should -Be $mockParameters.DomainControllerAccountName
                    $result.DomainName | Should -Be $mockParameters.DomainName
                    $result.SiteName | Should -Be $mockParameters.SiteName
                    $result.Ensure | Should -BeTrue
                    $result.IsGlobalCatalog | Should -BeTrue
                    $result.DelegatedAdministratorAccountName | Should -Be 'contoso\delegatedAdminAccount'
                    $result.AllowPasswordReplicationAccountName | Should -HaveCount 1
                    $result.AllowPasswordReplicationAccountName | Should -Be 'allowedAccount'
                    $result.DenyPasswordReplicationAccountName | Should -Be 'deniedAccount'
                    $result.Enabled | Should -BeTrue
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainControllerObject -ParameterFilter { $DomainName -eq 'present.com' -and $ComputerName -eq 'RODC01' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADComputer -ParameterFilter { $Properties -eq 'ManagedBy' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADObject -ParameterFilter { $Properties -eq 'objectSid' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Resolve-SamAccountName -ParameterFilter { $ObjectSid -eq 'S-1-0-0' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied -eq $true } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the Read-Only Domain Controller account does not exist' {
            BeforeAll {
                Mock -CommandName Get-DomainControllerObject
            }

            It 'Should return the expected result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainControllerAccountName | Should -Be $mockParameters.DomainControllerAccountName
                    $result.DomainName | Should -Be $mockParameters.DomainName
                    $result.SiteName | Should -BeNullOrEmpty
                    $result.Ensure | Should -BeFalse
                    $result.IsGlobalCatalog | Should -BeFalse
                    $result.DelegatedAdministratorAccountName | Should -BeNullOrEmpty
                    $result.AllowPasswordReplicationAccountName | Should -BeNullOrEmpty
                    $result.DenyPasswordReplicationAccountName | Should -BeNullOrEmpty
                    $result.Enabled | Should -BeFalse
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainControllerObject -ParameterFilter {
                    $DomainName -eq 'present.com' -and $ComputerName -eq 'RODC01'
                } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed -eq $true } -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied -eq $true } -Exactly -Times 0 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADReadOnlyDomainControllerAccount\Test-TargetResource' -Tag 'Test' {
    BeforeAll {
        Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed.IsPresent } -MockWith {
            @{
                SamAccountName = 'allowedAccount'
            }
        }

        Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied.IsPresent } -MockWith {
            @{
                SamAccountName = 'deniedAccount'
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainControllerAccountName         = 'RODC01'
                    DomainName                          = 'present.com'
                    SiteName                            = 'PresentSite'
                    IsGlobalCatalog                     = $true
                    DelegatedAdministratorAccountName   = 'contoso\delegatedAdminAccount'
                    AllowPasswordReplicationAccountName = @('allowedAccount')
                    DenyPasswordReplicationAccountName  = @('deniedAccount')
                    Ensure                              = $true
                }
            }

            Mock -CommandName Test-ADReplicationSite -MockWith { $true }
        }

        Context 'When creating a read only domain controller account with only mandatory parameters' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When property IsGlobalCatalog is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                        IsGlobalCatalog             = $true
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When property DelegatedAdministratorAccountName is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName       = 'RODC01'
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When property AllowPasswordReplicationAccountName is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName         = 'RODC01'
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        DomainName                          = 'present.com'
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = @('allowedAccount')
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When property DenyPasswordReplicationAccountName is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName        = 'RODC01'
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        DomainName                         = 'present.com'
                        SiteName                           = 'PresentSite'
                        DenyPasswordReplicationAccountName = @('deniedAccount')
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
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
                        DomainControllerAccountName = 'RODC01'
                        DomainName                  = 'WrongDomainName'
                        Ensure                      = $false
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'WrongDomainName'
                        SiteName                    = 'PresentSite'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When properties are not in desired state' {
            Context 'When property SiteName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainControllerAccountName = 'RODC01'
                            DomainName                  = 'present.com'
                            SiteName                    = 'PresentSite'
                            Ensure                      = $true
                        }
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainControllerAccountName = 'RODC01'
                            Credential                  = [System.Management.Automation.PSCredential]::Empty
                            DomainName                  = 'present.com'
                            SiteName                    = 'NewSiteName'
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                }
            }

            Context 'When property IsGlobalCatalog is not in desired state' {
                Context 'When Read Only Domain Controller Account should be a Global Catalog' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                DomainControllerAccountName = 'RODC01'
                                DomainName                  = 'present.com'
                                IsGlobalCatalog             = $false
                                Ensure                      = $true
                            }
                        }
                    }

                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                DomainControllerAccountName = 'RODC01'
                                Credential                  = [System.Management.Automation.PSCredential]::Empty
                                DomainName                  = 'present.com'
                                SiteName                    = 'PresentSite'
                                IsGlobalCatalog             = $true
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When Read Only Domain Controller Account should not be a Global Catalog' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                DomainControllerAccountName = 'RODC01'
                                DomainName                  = 'present.com'
                                IsGlobalCatalog             = $true
                                Ensure                      = $true
                            }
                        }
                    }

                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName = 'RODC01'
                                Credential                  = [System.Management.Automation.PSCredential]::Empty
                                DomainName                  = 'present.com'
                                SiteName                    = 'PresentSite'
                                IsGlobalCatalog             = $false
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }
            }

            Context 'When property DelegatedAdministratorAccountName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainControllerAccountName       = 'RODC01'
                            DomainName                        = 'present.com'
                            DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                            Ensure                            = $true
                        }
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName       = 'RODC01'
                            Credential                        = [System.Management.Automation.PSCredential]::Empty
                            DomainName                        = 'present.com'
                            SiteName                          = 'PresentSite'
                            DelegatedAdministratorAccountName = 'contoso\NewDelegatedAdminAccount'
                        }

                        Test-TargetResource @testDefaultParams | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                }
            }

            Context 'When property AllowPasswordReplicationAccountName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainControllerAccountName         = 'RODC01'
                            DomainName                          = 'present.com'
                            AllowPasswordReplicationAccountName = @('allowedAccount', 'Member2')
                            Ensure                              = $true
                        }
                    }
                }

                Context 'When there are different members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName         = 'RODC01'
                                Credential                          = [System.Management.Automation.PSCredential]::Empty
                                DomainName                          = 'present.com'
                                SiteName                            = 'PresentSite'
                                AllowPasswordReplicationAccountName = @('NewMember1', 'NewMember2')
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist less members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName         = 'RODC01'
                                Credential                          = [System.Management.Automation.PSCredential]::Empty
                                DomainName                          = 'present.com'
                                SiteName                            = 'PresentSite'
                                AllowPasswordReplicationAccountName = @('allowedAccount', 'Member2', 'NewMember')
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist more members that the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName         = 'RODC01'
                                Credential                          = [System.Management.Automation.PSCredential]::Empty
                                DomainName                          = 'present.com'
                                SiteName                            = 'PresentSite'
                                AllowPasswordReplicationAccountName = @('allowedAccount')
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }
            }

            Context 'When property DenyPasswordReplicationAccountName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainControllerAccountName        = 'RODC01'
                            DomainName                         = 'present.com'
                            DenyPasswordReplicationAccountName = @('deniedAccount', 'Member2')
                            Ensure                             = $true
                        }
                    }
                }

                Context 'When there are different members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName        = 'RODC01'
                                Credential                         = [System.Management.Automation.PSCredential]::Empty
                                DomainName                         = 'present.com'
                                SiteName                           = 'PresentSite'
                                DenyPasswordReplicationAccountName = @('NewMember1', 'NewMember2')
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist less members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName        = 'RODC01'
                                Credential                         = [System.Management.Automation.PSCredential]::Empty
                                DomainName                         = 'present.com'
                                SiteName                           = 'PresentSite'
                                DenyPasswordReplicationAccountName = @('deniedAccount', 'Member2', 'NewMember')
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist more members that the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $testDefaultParams = @{
                                DomainControllerAccountName        = 'RODC01'
                                Credential                         = [System.Management.Automation.PSCredential]::Empty
                                DomainName                         = 'present.com'
                                SiteName                           = 'PresentSite'
                                DenyPasswordReplicationAccountName = @('allowedAccount')
                            }

                            Test-TargetResource @testDefaultParams | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }
            }
        }

        Context 'When a specified site does not exist in the Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainControllerAccountName = 'RODC01'
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                        Ensure                      = $true
                    }
                }

                Mock -CommandName Test-ADReplicationSite -MockWith {
                    return $false
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                    }

                    $errorRecord = Get-ObjectNotFoundRecord -Message (
                        $script:localizedData.FailedToFindSite -f $testDefaultParams.SiteName, $testDefaultParams.DomainName
                    )

                    { Test-TargetResource @testDefaultParams } | Should -Throw -ExpectedMessage $errorRecord
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADReadOnlyDomainControllerAccount\Set-TargetResource' -Tag 'Set' {
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
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                        IsGlobalCatalog             = $false
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                    $NoGlobalCatalog -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a read only domain controller account with DelegatedAdministratorAccountName' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName       = 'RODC01'
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                    $DelegatedAdministratorAccountName -eq 'contoso\delegatedAdminAccount'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a read only domain controller account with AllowPasswordReplicationAccountName' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName         = 'RODC01'
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        DomainName                          = 'present.com'
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = @('allowedAccount')
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                    $AllowPasswordReplicationAccountName -eq @('allowedAccount')
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a read only domain controller account with DenyPasswordReplicationAccountName' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName        = 'RODC01'
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        DomainName                         = 'present.com'
                        SiteName                           = 'PresentSite'
                        DenyPasswordReplicationAccountName = @('deniedAccount')
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                    $DenyPasswordReplicationAccountName -eq @('deniedAccount')
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the read only domain controller account should have a DNS installed' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                        InstallDns                  = $true
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                    $InstallDns -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the read only domain controller account should not have a DNS installed' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0


                    $testDefaultParams = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                        InstallDns                  = $false
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Add-ADDSReadOnlyDomainControllerAccount -ParameterFilter {
                    $InstallDns -eq $false
                } -Exactly -Times 1 -Scope It
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
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Move-ADDirectoryServer -ParameterFilter {
                    $Site.ToString() -eq 'PresentSite'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When specifying the IsGlobalCatalog parameter' {
            BeforeAll {
                Mock -CommandName Set-ADObject
                Mock -CommandName Get-DomainControllerObject {
                    return @{
                        NTDSSettingsObjectDN = 'CN=NTDS Settings,CN=ServerName,CN=Servers,CN=PresentSite,CN=Sites,CN=Configuration,DC=present,DC=com'
                    }
                }
            }

            Context 'When the read only domain controller account should be a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return $stubTargetResource = @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $false
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName = 'RODC01'
                            Credential                  = [System.Management.Automation.PSCredential]::Empty
                            DomainName                  = 'present.com'
                            SiteName                    = 'PresentSite'
                            IsGlobalCatalog             = $true
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -ParameterFilter {
                        $Replace['options'] -eq 1
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the read only domain controller account should not be a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return $stubTargetResource = @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $true
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName = 'RODC01'
                            Credential                  = [System.Management.Automation.PSCredential]::Empty
                            DomainName                  = 'present.com'
                            SiteName                    = 'PresentSite'
                            IsGlobalCatalog             = $false
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -ParameterFilter {
                        $Replace['options'] -eq 0
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the read only domain controller account should change state of Global Catalog, but fail to return a read only domain controller object' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return $stubTargetResource = @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $true
                        }
                    }

                    Mock -CommandName Get-DomainControllerObject
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName = 'RODC01'
                            Credential                  = [System.Management.Automation.PSCredential]::Empty
                            DomainName                  = 'present.com'
                            SiteName                    = 'PresentSite'
                            IsGlobalCatalog             = $false
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When DelegatedAdministratorAccountName is not compliant' {
            BeforeAll {
                Mock -CommandName Set-ADComputer
                Mock -CommandName Resolve-SecurityIdentifier -ParameterFilter { $SamAccountName -eq 'contoso\delegatedAdminAccount' } -MockWith { 'S-1-0-0' }
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                            = $true
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\PresentDelegatedAdminAccount'
                    }
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    $stubDomainController = New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController
                    $stubDomainController.ComputerObjectDN = (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADComputer)
                    return $stubDomainController
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName       = 'RODC01'
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Resolve-SecurityIdentifier -ParameterFilter {
                    $SamAccountName -eq 'contoso\delegatedAdminAccount'
                } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADComputer -ParameterFilter {
                    $ManagedBy -eq 'S-1-0-0'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When AllowPasswordReplicationAccountName is not compliant' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                              = $true
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = 'allowedAccount2'
                    }
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName         = 'RODC01'
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        DomainName                          = 'present.com'
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 1 -Scope It
            }
        }

        Context 'When DenyPasswordReplicationAccountName is not compliant' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                             = $true
                        SiteName                           = 'PresentSite'
                        DenyPasswordReplicationAccountName = 'deniedAccount2'
                    }
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName        = 'RODC01'
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        DomainName                         = 'present.com'
                        SiteName                           = 'PresentSite'
                        DenyPasswordReplicationAccountName = 'deniedAccount'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Remove-ADDomainControllerPasswordReplicationPolicy
            Mock -CommandName Add-ADDomainControllerPasswordReplicationPolicy
        }

        Context 'When the read only domain controller account is already in the correct site' {
            BeforeAll {
                Mock -CommandName Move-ADDirectoryServer
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure   = $true
                        SiteName = 'PresentSite'
                    }
                }

                Mock -CommandName Get-DomainControllerObject {
                    return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName = 'RODC01'
                        Credential                  = [System.Management.Automation.PSCredential]::Empty
                        DomainName                  = 'present.com'
                        SiteName                    = 'PresentSite'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Move-ADDirectoryServer -Exactly -Times 0 -Scope It
            }
        }

        Context 'When specifying the IsGlobalCatalog parameter' {
            BeforeAll {
                Mock -CommandName Set-ADObject
                Mock -CommandName Get-DomainControllerObject {
                    return @{
                        NTDSSettingsObjectDN = 'CN=NTDS Settings,CN=ServerName,CN=Servers,CN=PresentSite,CN=Sites,CN=Configuration,DC=present,DC=com'
                    }
                }
            }

            Context 'When the read only domain controller account already is a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $true
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName = 'RODC01'
                            Credential                  = [System.Management.Automation.PSCredential]::Empty
                            DomainName                  = 'present.com'
                            SiteName                    = 'PresentSite'
                            IsGlobalCatalog             = $true
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the read only domain controller account already is not a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $false
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName = 'RODC01'
                            Credential                  = [System.Management.Automation.PSCredential]::Empty
                            DomainName                  = 'present.com'
                            SiteName                    = 'PresentSite'
                            IsGlobalCatalog             = $false
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When DelegatedAdministratorAccountName is correct' {
            BeforeAll {
                Mock -CommandName Set-ADComputer
                Mock -CommandName Resolve-SecurityIdentifier -ParameterFilter {
                    $SamAccountName -eq 'contoso\delegatedAdminAccount'
                } -MockWith { 'S-1-0-0' }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    $stubDomainController = New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController
                    $stubDomainController.ComputerObjectDN = (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADComputer)
                    return $stubDomainController
                }

                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                            = $true
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName       = 'RODC01'
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Resolve-SecurityIdentifier -ParameterFilter {
                    $SamAccountName -eq 'contoso\delegatedAdminAccount'
                } -Exactly -Times 0 -Scope It

                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
            }
        }

        Context 'When AllowPasswordReplicationAccountName is correct' {
            BeforeAll {
                Mock -CommandName Get-DomainControllerObject -MockWith {
                    return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                }

                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Ensure                              = $true
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $testDefaultParams = @{
                        DomainControllerAccountName         = 'RODC01'
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        DomainName                          = 'present.com'
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
            }

            Context 'When DenyPasswordReplicationAccountName is correct' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure                             = $true
                            SiteName                           = 'PresentSite'
                            DenyPasswordReplicationAccountName = 'deniedAccount'
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            DomainControllerAccountName        = 'RODC01'
                            Credential                         = [System.Management.Automation.PSCredential]::Empty
                            DomainName                         = 'present.com'
                            SiteName                           = 'PresentSite'
                            DenyPasswordReplicationAccountName = 'deniedAccount'
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
                }
            }
        }
    }
}

Describe 'MSFT_ADReadOnlyDomainControllerAccount\Get-MembersToAddAndRemove' -Tag 'Helper' {
    Context 'When there is one desired member' {
        Context 'When there are no current members' {
            Context 'When proving a $null value for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers $null
                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }

            Context 'When proving an empty collection for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers @()
                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }
        }

        Context 'When there is one current member' {
            Context 'When proving a collection for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers @('OldMember')
                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                    }
                }
            }

            Context 'When proving a string value for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers 'OldMember'
                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                    }
                }
            }
        }

        Context 'When there is more than one current member' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers @('OldMember1', 'OldMember2')
                    $result.MembersToAdd | Should -HaveCount 1
                    $result.MembersToAdd[0].ToString() | Should -Be 'Member1'
                    $result.MembersToRemove | Should -HaveCount 2
                    $result.MembersToRemove[0].ToString() | Should -Be 'OldMember1'
                    $result.MembersToRemove[1].ToString() | Should -Be 'OldMember2'
                }
            }
        }
    }

    Context 'When there are no desired members' {
        Context 'When there are no current members' {
            Context 'When proving a $null value for DesiredMembers and CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers $null
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }

            Context 'When proving an empty collection for DesiredMembers and CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers @() -CurrentMembers @()
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }
        }

        Context 'When there is one current member' {
            Context 'When proving a collection for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers @('OldMember')
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                    }
                }
            }

            Context 'When proving a string value for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers 'OldMember'
                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be 'OldMember'
                    }
                }
            }
        }

        Context 'When there is more than one current member' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $result = Get-MembersToAddAndRemove -DesiredMembers $null -CurrentMembers @('OldMember1', 'OldMember2')
                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -HaveCount 2
                    $result.MembersToRemove[0].ToString() | Should -Be 'OldMember1'
                    $result.MembersToRemove[1].ToString() | Should -Be 'OldMember2'
                }
            }
        }
    }

    Context 'When the same members are present in desired members and current members' {
        Context 'When proving a collection for CurrentMembers' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $result = Get-MembersToAddAndRemove -DesiredMembers @('Member1') -CurrentMembers @('Member1')
                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -BeNullOrEmpty
                }
            }
        }

        Context 'When proving a string value for CurrentMembers' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers 'Member1'
                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When there are more desired members than current members' {
        Context 'When proving a collection for CurrentMembers' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $result = Get-MembersToAddAndRemove -DesiredMembers @('Member1', 'Member2') -CurrentMembers @('Member1')
                    $result.MembersToAdd | Should -HaveCount 1
                    $result.MembersToAdd[0].ToString() | Should -Be 'Member2'
                    $result.MembersToRemove | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When there are fewer desired members than current members' {
        Context 'When proving a string value for CurrentMembers' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $result = Get-MembersToAddAndRemove -DesiredMembers 'Member1' -CurrentMembers @('Member1', 'Member2')
                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -HaveCount 1
                    $result.MembersToRemove[0].ToString() | Should -Be 'Member2'
                }
            }
        }
    }
}
