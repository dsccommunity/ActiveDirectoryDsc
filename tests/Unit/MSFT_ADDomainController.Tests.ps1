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
    $script:dscResourceName = 'MSFT_ADDomainController'

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

Describe 'MSFT_ADDomainController\Get-TargetResource' -Tag 'Get' {
    Context 'When the domain could not be found' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-DomainObject -MockWith {
                return $null
            }
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Credential                    = [System.Management.Automation.PSCredential]::Empty
                    SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                    DomainName                    = 'present.com'
                }

                $errorRecord = Get-ObjectNotFoundRecord -Message ($script:localizedData.MissingDomain -f $mockParameters.DomainName)

                { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Assert-Module
            Mock -CommandName Get-DomainObject -MockWith { $true }
            Mock -CommandName Get-ItemProperty -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            } -MockWith {
                @{
                    'Database log files path' = 'C:\Windows\NTDS'
                    'DSA Working Directory'   = 'C:\Windows\NTDS'
                }
            }

            Mock -CommandName Get-ItemProperty -ParameterFilter {
                $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
            } -MockWith {
                @{
                    SysVol = 'C:\Windows\SYSVOL\sysvol'
                }
            }

            Mock -CommandName Get-ADDomainControllerPasswordReplicationPolicy
            Mock -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -MockWith { $true }
        }

        Context 'When the node is a Domain Controller with DNS installed' {
            BeforeAll {
                Mock -CommandName Get-DomainControllerObject {
                    [PSCustomObject] @{
                        Site            = 'PresentSite'
                        Domain          = 'present.com'
                        IsGlobalCatalog = $true
                        IsReadOnly      = $false
                    }
                }

                New-Item -Path 'TestDrive:\' -ItemType Directory -Name 'IFM'
            }

            It 'Should return the expected result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainName | Should -Be $mockParameters.DomainName
                    $result.InstallDns | Should -BeTrue
                    $result.UseExistingAccount | Should -BeFalse
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainControllerObject -ParameterFilter { $DomainName -eq 'present.com' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the node is a Domain Controller and no DNS should be installed' {
            BeforeAll {
                Mock -CommandName Get-DomainControllerObject {
                    [PSCustomObject] @{
                        Site            = 'PresentSite'
                        Domain          = 'present.com'
                        IsGlobalCatalog = $true
                        IsReadOnly      = $false
                    }
                }

                Mock -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -MockWith { $false }

                New-Item -Path 'TestDrive:\' -ItemType Directory -Name 'IFM'
            }

            It 'Should return the expected result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainName | Should -Be $mockParameters.DomainName
                    $result.InstallDns | Should -BeFalse
                    $result.UseExistingAccount | Should -BeFalse
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainControllerObject -ParameterFilter { $DomainName -eq 'present.com' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the node is a Read-Only Domain Controller' {
            BeforeAll {
                $mockDomainControllerDelegatedAdminObject = [PSCustomObject] @{
                    objectSid = 'S-1-0-0'
                }

                $mockDomainControllerComputerObject = [PSCustomObject] @{
                    ManagedBy = $mockDomainControllerDelegatedAdminObject
                }

                $mockDomainControllerObject = [PSCustomObject] @{
                    Site             = 'PresentSite'
                    Domain           = 'present.com'
                    IsGlobalCatalog  = $true
                    IsReadOnly       = $true
                    ComputerObjectDN = $mockDomainControllerComputerObject
                }

                Mock -CommandName Get-DomainControllerObject { $mockDomainControllerObject }
                Mock -CommandName Get-ADComputer { $mockDomainControllerComputerObject }
                Mock -CommandName Get-ADObject { $mockDomainControllerDelegatedAdminObject }
                Mock -CommandName Resolve-SamAccountName -ParameterFilter { $ObjectSid -eq 'S-1-0-0' } -MockWith {
                    'contoso\delegatedAdminAccount'
                }

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

                Mock -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -MockWith { $false }

                New-Item -Path 'TestDrive:\' -ItemType Directory -Name 'IFM'
            }

            It 'Should return the expected result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        UseExistingAccount            = $true
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainName | Should -Be $mockParameters.DomainName
                    $result.DatabasePath | Should -Be 'C:\Windows\NTDS'
                    $result.LogPath | Should -Be 'C:\Windows\NTDS'
                    $result.SysvolPath | Should -Be 'C:\Windows\SYSVOL'
                    $result.SiteName | Should -Be 'PresentSite'
                    $result.Ensure | Should -BeTrue
                    $result.IsGlobalCatalog | Should -BeTrue
                    $result.ReadOnlyReplica | Should -BeTrue
                    $result.DelegatedAdministratorAccountName | Should -Be 'contoso\delegatedAdminAccount'
                    $result.AllowPasswordReplicationAccountName | Should -HaveCount 1
                    $result.AllowPasswordReplicationAccountName | Should -Be 'allowedAccount'
                    $result.DenyPasswordReplicationAccountName | Should -Be 'deniedAccount'
                    $result.InstallDns | Should -BeFalse
                    $result.UseExistingAccount | Should -BeTrue
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainControllerObject -ParameterFilter { $DomainName -eq 'present.com' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADComputer -ParameterFilter { $Properties -eq 'ManagedBy' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADObject -ParameterFilter { $Properties -eq 'objectSid' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Resolve-SamAccountName -ParameterFilter { $ObjectSid -eq 'S-1-0-0' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied -eq $true } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the node should not be a Domain Controller' {
            BeforeAll {
                Mock -CommandName Get-DomainControllerObject
            }

            It 'Should return the expected result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.DomainName | Should -Be $mockParameters.DomainName
                    $result.DatabasePath | Should -BeNullOrEmpty
                    $result.LogPath | Should -BeNullOrEmpty
                    $result.SysvolPath | Should -BeNullOrEmpty
                    $result.SiteName | Should -BeNullOrEmpty
                    $result.Ensure | Should -BeFalse
                    $result.IsGlobalCatalog | Should -BeFalse
                    $result.NtdsSettingsObjectDn | Should -BeNullOrEmpty
                    $result.ReadOnlyReplica | Should -BeFalse
                    $result.DelegatedAdministratorAccountName | Should -BeNullOrEmpty
                    $result.AllowPasswordReplicationAccountName | Should -BeNullOrEmpty
                    $result.DenyPasswordReplicationAccountName | Should -BeNullOrEmpty
                    $result.FlexibleSingleMasterOperationRole | Should -BeNullOrEmpty
                    $result.InstallDns | Should -BeFalse
                    $result.UseExistingAccount | Should -BeFalse
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-DomainControllerObject -ParameterFilter { $DomainName -eq 'present.com' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Allowed -eq $true } -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ADDomainControllerPasswordReplicationPolicy -ParameterFilter { $Denied -eq $true } -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' } -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ItemProperty -ParameterFilter { $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' } -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-Service -ParameterFilter { $Name -eq 'dns' } -Exactly -Times 0 -Scope It
            }
        }
    }
}

Describe 'ADDomainController\Test-TargetResource' -Tag 'Test' {
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
                return @{
                    DomainName                          = 'present.com'
                    SiteName                            = 'PresentSite'
                    IsGlobalCatalog                     = $true
                    DelegatedAdministratorAccountName   = 'contoso\delegatedAdminAccount'
                    AllowPasswordReplicationAccountName = @('allowedAccount')
                    DenyPasswordReplicationAccountName  = @('deniedAccount')
                    FlexibleSingleMasterOperationRole   = @('DomainNamingMaster', 'RIDMaster')
                    ReadOnlyReplica                     = $true
                    Ensure                              = $true
                }
            }

            Mock -CommandName Test-ADReplicationSite -MockWith { $true }
        }

        Context 'When creating a domain controller with only mandatory parameters' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 0 -Scope It
            }
        }

        Context 'When property SiteName is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SiteName                      = 'PresentSite'
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
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        IsGlobalCatalog               = $true
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 0 -Scope It
            }
        }

        Context 'When property DelegatedAdministratorAccountName is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                   = $true
                        SiteName                          = 'PresentSite'
                        DomainName                        = 'present.com'
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
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                     = $true
                        SiteName                            = 'PresentSite'
                        DomainName                          = 'present.com'
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
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                    = $true
                        SiteName                           = 'PresentSite'
                        DomainName                         = 'present.com'
                        DenyPasswordReplicationAccountName = @('deniedAccount')
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When property FlexibleSingleMasterOperationRole is in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        FlexibleSingleMasterOperationRole = @('RIDMaster')
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }

        Context 'When property ReadOnlyReplica and SiteName are in desired state' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        ReadOnlyReplica               = $true
                        SiteName                      = 'PresentSite'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Test-ADReplicationSite -MockWith { $true }
        }

        Context 'When creating a domain controller with only mandatory parameters' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName = 'WrongDomainName'
                        Ensure     = $false
                    }
                }
            }

            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'WrongDomainName'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 0 -Scope It
            }
        }

        Context 'When properties are not in desired state' {
            Context 'When property SiteName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainName = 'present.com'
                            SiteName   = 'PresentSite'
                            Ensure     = $true
                        }
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            SiteName                      = 'NewSiteName'
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                }
            }

            Context 'When property IsGlobalCatalog is not in desired state' {
                Context 'When Domain Controller should be a Global Catalog' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                DomainName      = 'present.com'
                                IsGlobalCatalog = $false
                                Ensure          = $true
                            }
                        }
                    }

                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                    = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                                DomainName                    = 'present.com'
                                IsGlobalCatalog               = $true
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When Domain Controller should not be a Global Catalog' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            return @{
                                DomainName      = 'present.com'
                                IsGlobalCatalog = $true
                                Ensure          = $true
                            }
                        }
                    }

                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                    = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                                DomainName                    = 'present.com'
                                IsGlobalCatalog               = $false
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When property DelegatedAdministratorAccountName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainName                        = 'present.com'
                            SiteName                          = 'PresentSite'
                            DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                            ReadOnlyReplica                   = $true
                            Ensure                            = $true
                        }
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                        = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                            ReadOnlyReplica                   = $true
                            SiteName                          = 'PresentSite'
                            DomainName                        = 'present.com'
                            DelegatedAdministratorAccountName = 'contoso\NewDelegatedAdminAccount'
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                }
            }

            Context 'When property AllowPasswordReplicationAccountName is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainName                          = 'present.com'
                            SiteName                            = 'PresentSite'
                            AllowPasswordReplicationAccountName = @('allowedAccount', 'Member2')
                            ReadOnlyReplica                     = $true
                            Ensure                              = $true
                        }
                    }
                }

                Context 'When there are different members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                          = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                                ReadOnlyReplica                     = $true
                                SiteName                            = 'PresentSite'
                                DomainName                          = 'present.com'
                                AllowPasswordReplicationAccountName = @('NewMember1', 'NewMember2')
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist less members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                          = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                                ReadOnlyReplica                     = $true
                                SiteName                            = 'PresentSite'
                                DomainName                          = 'present.com'
                                AllowPasswordReplicationAccountName = @('allowedAccount', 'Member2', 'NewMember')
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist more members that the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                          = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                                ReadOnlyReplica                     = $true
                                SiteName                            = 'PresentSite'
                                DomainName                          = 'present.com'
                                AllowPasswordReplicationAccountName = @('allowedAccount')
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
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
                            DomainName                         = 'present.com'
                            SiteName                           = 'PresentSite'
                            DenyPasswordReplicationAccountName = @('deniedAccount', 'Member2')
                            ReadOnlyReplica                    = $true
                            Ensure                             = $true
                        }
                    }
                }

                Context 'When there are different members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                         = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                                ReadOnlyReplica                    = $true
                                SiteName                           = 'PresentSite'
                                DomainName                         = 'present.com'
                                DenyPasswordReplicationAccountName = @('NewMember1', 'NewMember2')
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist less members than the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                         = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                                ReadOnlyReplica                    = $true
                                SiteName                           = 'PresentSite'
                                DomainName                         = 'present.com'
                                DenyPasswordReplicationAccountName = @('deniedAccount', 'Member2', 'NewMember')
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When there exist more members that the desired state' {
                    It 'Should return $false' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Credential                         = [System.Management.Automation.PSCredential]::Empty
                                SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                                ReadOnlyReplica                    = $true
                                SiteName                           = 'PresentSite'
                                DomainName                         = 'present.com'
                                DenyPasswordReplicationAccountName = @('allowAccount')
                            }

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }

                        Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
                    }
                }
            }

            Context 'When property FlexibleSingleMasterOperationRole is not in desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            DomainName                         = 'present.com'
                            DenyPasswordReplicationAccountName = @('deniedAccount', 'Member2')
                            Ensure                             = $true
                            FlexibleSingleMasterOperationRole  = @('DomainNamingMaster')
                        }
                    }
                }

                It 'Should return $false' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                        = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                            DomainName                        = 'present.com'
                            FlexibleSingleMasterOperationRole = @('RIDMaster')
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When a specified site does not exist in the Active Directory' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName = 'present.com'
                        SiteName   = 'PresentSite'
                        Ensure     = $true
                    }
                }

                Mock -CommandName Test-ADReplicationSite -MockWith {
                    return $false
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SiteName                      = 'PresentSite'
                    }

                    $errorRecord = Get-ObjectNotFoundRecord -Message  (
                        $script:localizedData.FailedToFindSite -f $mockParameters.SiteName, $mockParameters.DomainName
                    )

                    { Test-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Test-ADReplicationSite -Exactly -Times 1 -Scope It
            }
        }

        Context 'When parameter DelegatedAdministratorAccountName is specified, but ReadOnlyReplica is not $true' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName                        = 'present.com'
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                        Ensure                            = $true
                    }
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message  ($script:localizedData.DelegatedAdministratorAccountNameNotRODC)

                    { Test-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 0 -Scope It
            }
        }

        Context 'When parameter AllowPasswordReplicationAccountName is specified, but ReadOnlyReplica is not $true' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName                          = 'present.com'
                        SiteName                            = 'PresentSite'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                        Ensure                              = $true
                    }
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                        DomainName                          = 'present.com'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message  ($script:localizedData.AllowPasswordReplicationAccountNameNotRODC)

                    { Test-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 0 -Scope It
            }
        }

        Context 'When parameter DenyPasswordReplicationAccountName is specified, but ReadOnlyReplica is not $true' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName                         = 'present.com'
                        SiteName                           = 'PresentSite'
                        DenyPasswordReplicationAccountName = 'deniedAccount'
                        Ensure                             = $true
                    }
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                        DomainName                         = 'present.com'
                        DenyPasswordReplicationAccountName = 'deniedAccount'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message  ($script:localizedData.DenyPasswordReplicationAccountNameNotRODC)

                    { Test-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 0 -Scope It
            }
        }

        Context 'When parameter ReadOnlyReplica is $true, but SiteName is not specified' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName      = 'present.com'
                        SiteName        = $null
                        ReadOnlyReplica = $false
                        Ensure          = $false
                    }
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        ReadOnlyReplica               = $true
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RODCMissingSite)

                    { Test-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 0 -Scope It
            }
        }

        Context 'When parameter ReadOnlyReplica is $true, but the node is already a writeable Domain Controller' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        DomainName      = 'present.com'
                        ReadOnlyReplica = $false
                        Ensure          = $true
                    }
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SiteName                      = 'PresentSite'
                        ReadOnlyReplica               = $true
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.CannotConvertToRODC

                    { Test-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'ADDomainController\Set-TargetResource' -Tag 'Set' {
    Context 'When the system is not in the desired state' {
        BeforeAll {
            Mock -CommandName Install-ADDSDomainController
            Mock -CommandName Remove-ADDomainControllerPasswordReplicationPolicy
            Mock -CommandName Add-ADDomainControllerPasswordReplicationPolicy
            Mock -CommandName Get-ADDomain -MockWith {
                return $true
            }

            Mock -CommandName Get-TargetResource -MockWith {
                return @{
                    Ensure = $false
                }
            }
        }

        Context 'When adding a domain controller to a specific site' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SiteName                      = 'PresentSite'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $SiteName -eq 'PresentSite' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller to a specific database path' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        DatabasePath                  = 'C:\Windows\NTDS'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $DatabasePath -eq 'C:\Windows\NTDS' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller to a specific SysVol path' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SysVolPath                    = 'C:\Windows\SYSVOL'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $SysVolPath -eq 'C:\Windows\SYSVOL' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller to a specific log path' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        LogPath                       = 'C:\Windows\NTDS'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $LogPath -eq 'C:\Windows\NTDS' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller that should not be a Global Catalog' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        IsGlobalCatalog               = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $NoGlobalCatalog -eq $true } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller using IFM' {
            BeforeAll {
                New-Item -Path 'TestDrive:\IFM' -ItemType 'Directory' -Force
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        InstallationMediaPath         = 'TestDrive:\IFM'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $InstallationMediaPath -eq 'TestDrive:\IFM' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'Throws if "DelegatedAdministratorAccountName" is specified but ReadOnlyReplica is not $true' {
            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.DelegatedAdministratorAccountNameNotRODC

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }

        Context 'Throws if "AllowPasswordReplicationAccountName" is specified but ReadOnlyReplica is not $true' {
            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                        DomainName                          = 'present.com'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.AllowPasswordReplicationAccountNameNotRODC

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }

        Context 'Throws if "DenyPasswordReplicationAccountName" is specified but ReadOnlyReplica is not $true' {
            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                        DomainName                         = 'present.com'
                        DenyPasswordReplicationAccountName = 'deniedAccount'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.DenyPasswordReplicationAccountNameNotRODC

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }

        Context 'Throws if "ReadOnlyReplica" is specified without Site' {
            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        ReadOnlyReplica               = $true
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.RODCMissingSite

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }

        Context 'When adding a domain controller with DelegatedAdministratorAccountName' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                   = $true
                        SiteName                          = 'PresentSite'
                        DomainName                        = 'present.com'
                        DelegatedAdministratorAccountName = 'contoso\NewDelegatedAdminAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $DelegatedAdministratorAccountName -eq 'contoso\NewDelegatedAdminAccount' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller with AllowPasswordReplicationAccountName' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                     = $true
                        SiteName                            = 'PresentSite'
                        DomainName                          = 'present.com'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $AllowPasswordReplicationAccountName -eq 'allowedAccount' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller with DenyPasswordReplicationAccountName' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                    = $true
                        SiteName                           = 'PresentSite'
                        DomainName                         = 'present.com'
                        DenyPasswordReplicationAccountName = 'deniedAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $DenyPasswordReplicationAccountName -eq 'deniedAccount' } -Exactly -Times 1
            }
        }

        Context 'When the domain controller should have a DNS installed' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica               = $true
                        SiteName                      = 'PresentSite'
                        DomainName                    = 'present.com'
                        InstallDns                    = $true
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $InstallDns -eq $true } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the domain controller should not have a DNS installed' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica               = $true
                        SiteName                      = 'PresentSite'
                        DomainName                    = 'present.com'
                        InstallDns                    = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $InstallDns -eq $false } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the read only domain controller should use an existing account' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        UseExistingAccount            = $true
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $UseExistingAccount -eq $true } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the read only domain controller should not use an existing account' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        UseExistingAccount            = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Install-ADDSDomainController -ParameterFilter { $UseExistingAccount -eq $false } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When a domain controller is in the wrong site' {
            BeforeAll {
                Mock -CommandName Move-ADDirectoryServer
                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure   = $true
                        SiteName = 'IncorrectSite'
                    }
                }

                <#
                    Without this line the local tests are crashing powershell.exe (both 5 and 6).
                    See test 'Should call the correct mocks to move the domain controller to the correct site'.
                #>
                Mock -CommandName Get-DomainControllerObject -MockWith {
                    return (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADDomainController)
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SiteName                      = 'PresentSite'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Move-ADDirectoryServer -ParameterFilter { $Site.ToString() -eq 'PresentSite' } -Exactly -Times 1 -Scope It
            }

            Context 'When the domain controller is in the wrong site, but SiteName is not specified' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $testDefaultParams = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Move-ADDirectoryServer  -Exactly -Times 0 -Scope It
                }
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

            Context 'When the domain controller should be a Global Catalog' {
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

                        $mockParameters = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            IsGlobalCatalog               = $true
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -ParameterFilter { $Replace['options'] -eq 1 } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the domain controller should not be a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $true
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            IsGlobalCatalog               = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -ParameterFilter { $Replace['options'] -eq 0 } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the domain controller should change state of Global Catalog, but fail to return a domain controller object' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
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

                        $mockParameters = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            IsGlobalCatalog               = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -Exactly -Times 0
                }
            }
        }

        Context 'When DelegatedAdministratorAccountName is not compliant' {
            BeforeAll {
                Mock -CommandName Set-ADComputer
                Mock -CommandName Resolve-SecurityIdentifier -ParameterFilter {
                    $SamAccountName -eq 'contoso\delegatedAdminAccount'
                } -MockWith { 'S-1-0-0' }

                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                            = $true
                        SiteName                          = 'PresentSite'
                        DelegatedAdministratorAccountName = 'contoso\PresentDelegatedAdminAccount'
                    }
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    [PSCustomObject] @{
                        IsReadOnly       = $true
                        Site             = 'PresentSite'
                        ComputerObjectDN = [PSCustomObject] @{}
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                   = $true
                        SiteName                          = 'PresentSite'
                        DomainName                        = 'present.com'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
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
                        AllowPasswordReplicationAccountName = 'allowedAccount2'
                        SiteName                            = 'PresentSite'
                    }
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    [PSCustomObject] @{
                        Site = 'PresentSite'
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                     = $true
                        SiteName                            = 'PresentSite'
                        DomainName                          = 'present.com'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
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
                        DenyPasswordReplicationAccountName = 'deniedAccount2'
                        SiteName                           = 'PresentSite'
                    }
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    [PSCustomObject] @{
                        Site = 'PresentSite'
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                         = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                    = $true
                        SiteName                           = 'PresentSite'
                        DomainName                         = 'present.com'
                        DenyPasswordReplicationAccountName = 'deniedAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller and the FlexibleSingleMasterOperationRole is set to ''RIDMaster''' {
            BeforeAll {
                Mock -CommandName Move-ADDirectoryServerOperationMasterRole
                Mock -CommandName Get-ADForest
                Mock -CommandName Get-ADDomain -MockWith {
                    return @{
                        RIDMaster = 'dc.contoso.com'
                    }
                }

                Mock -CommandName Get-DomainControllerObject {
                    [PSCustomObject] @{
                        OperationMasterRoles = @('DomainNamingMaster')
                    }
                }

                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                            = $true
                        FlexibleSingleMasterOperationRole = @('DomainNamingMaster')
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        FlexibleSingleMasterOperationRole = @('RIDMaster')
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADForest -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADDirectoryServerOperationMasterRole -Exactly -Times 1 -Scope It
            }
        }

        Context 'When adding a domain controller and the FlexibleSingleMasterOperationRole is set to ''SchemaMaster''' {
            BeforeAll {
                Mock -CommandName Move-ADDirectoryServerOperationMasterRole
                Mock -CommandName Get-ADDomain
                Mock -CommandName Get-ADForest -MockWith {
                    return @{
                        SchemaMaster = 'dc.contoso.com'
                    }
                }

                Mock -CommandName Get-DomainControllerObject {
                    [PSCustomObject] @{
                        OperationMasterRoles = @('DomainNamingMaster')
                    }
                }

                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                            = $true
                        FlexibleSingleMasterOperationRole = @('DomainNamingMaster')
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        DomainName                        = 'present.com'
                        FlexibleSingleMasterOperationRole = @('SchemaMaster')
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ADForest -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Move-ADDirectoryServerOperationMasterRole -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Remove-ADDomainControllerPasswordReplicationPolicy
            Mock -CommandName Add-ADDomainControllerPasswordReplicationPolicy
        }

        Context 'When a domain controller is in the correct site' {
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

                    $mockParameters = @{
                        Credential                    = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                        DomainName                    = 'present.com'
                        SiteName                      = 'PresentSite'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
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

            Context 'When the domain controller should be a Global Catalog' {
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
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            IsGlobalCatalog               = $true
                        }

                        { Set-TargetResource @testDefaultParams } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -ParameterFilter { $Replace['options'] -eq 1 } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the domain controller already is a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $true
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            IsGlobalCatalog               = $true
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the domain controller already are not a Global Catalog' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure          = $true
                            SiteName        = 'PresentSite'
                            IsGlobalCatalog = $false
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                    = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword = [System.Management.Automation.PSCredential]::Empty
                            DomainName                    = 'present.com'
                            IsGlobalCatalog               = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Set-ADObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When DelegatedAdministratorAccountName is correct' {
            BeforeAll {
                Mock -CommandName Set-ADComputer
                Mock -CommandName Resolve-SecurityIdentifier -ParameterFilter { $SamAccountName -eq 'contoso\delegatedAdminAccount' } -MockWith {
                    'S-1-0-0'
                }

                Mock -CommandName Get-DomainControllerObject -MockWith {
                    [PSCustomObject] @{
                        IsReadOnly       = $true
                        Site             = 'PresentSite'
                        ComputerObjectDN = [PSCustomObject] @{}
                    }
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

                    $mockParameters = @{
                        Credential                        = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword     = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                   = $true
                        SiteName                          = 'PresentSite'
                        DomainName                        = 'present.com'
                        DelegatedAdministratorAccountName = 'contoso\delegatedAdminAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Resolve-SecurityIdentifier -ParameterFilter { $SamAccountName -eq 'contoso\delegatedAdminAccount' } -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADComputer -Exactly -Times 0 -Scope It
            }
        }

        Context 'When Read-OnlyDomainController(RODC) Sync Accounts are compliant' {
            BeforeAll {
                Mock -CommandName Get-DomainControllerObject -MockWith {
                    [PSCustomObject] @{
                        Site = 'PresentSite'
                    }
                }

                Mock -CommandName Get-TargetResource -MockWith {
                    return @{
                        Ensure                              = $true
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                        SiteName                            = 'PresentSite'
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Credential                          = [System.Management.Automation.PSCredential]::Empty
                        SafeModeAdministratorPassword       = [System.Management.Automation.PSCredential]::Empty
                        ReadOnlyReplica                     = $true
                        SiteName                            = 'PresentSite'
                        DomainName                          = 'present.com'
                        AllowPasswordReplicationAccountName = 'allowedAccount'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
            }

            Context 'When DenyPasswordReplicationAccountName is correct' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        return @{
                            Ensure                             = $true
                            DenyPasswordReplicationAccountName = 'deniedAccount'
                            SiteName                           = 'PresentSite'
                        }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Credential                         = [System.Management.Automation.PSCredential]::Empty
                            SafeModeAdministratorPassword      = [System.Management.Automation.PSCredential]::Empty
                            ReadOnlyReplica                    = $true
                            SiteName                           = 'PresentSite'
                            DomainName                         = 'present.com'
                            DenyPasswordReplicationAccountName = 'deniedAccount'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Remove-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Add-ADDomainControllerPasswordReplicationPolicy -Exactly -Times 0 -Scope It
                }
            }
        }
    }
}

Describe 'MSFT_ADDomainController\Get-MembersToAddAndRemove' -Tag 'Helper' {
    Context 'When there is one desired member' {
        Context 'When there are no current members' {
            Context 'When proving a $null value for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DesiredMembers = 'Member1'
                            CurrentMembers = $null
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be $mockParameters.DesiredMembers
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }

            Context 'When proving an empty collection for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DesiredMembers = 'Member1'
                            CurrentMembers = @()
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be $mockParameters.DesiredMembers
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

                        $mockParameters = @{
                            DesiredMembers = 'Member1'
                            CurrentMembers = @('OldMember')
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be $mockParameters.DesiredMembers
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers[0]
                    }
                }
            }

            Context 'When proving a string value for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DesiredMembers = 'Member1'
                            CurrentMembers = 'OldMember'
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -HaveCount 1
                        $result.MembersToAdd[0].ToString() | Should -Be $mockParameters.DesiredMembers
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers
                    }
                }
            }
        }

        Context 'When there is more than one current member' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DesiredMembers = 'Member1'
                        CurrentMembers = @('OldMember1', 'OldMember2')
                    }

                    $result = Get-MembersToAddAndRemove @mockParameters

                    $result.MembersToAdd | Should -HaveCount 1
                    $result.MembersToAdd[0].ToString() | Should -Be $mockParameters.DesiredMembers
                    $result.MembersToRemove | Should -HaveCount 2
                    $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers[0]
                    $result.MembersToRemove[1].ToString() | Should -Be $mockParameters.CurrentMembers[1]
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

                        $mockParameters = @{
                            DesiredMembers = $null
                            CurrentMembers = $null
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -BeNullOrEmpty
                    }
                }
            }

            Context 'When proving an empty collection for DesiredMembers and CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DesiredMembers = @()
                            CurrentMembers = @()
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

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

                        $mockParameters = @{
                            DesiredMembers = $null
                            CurrentMembers = @('OldMember')
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers[0]
                    }
                }
            }

            Context 'When proving a string value for CurrentMembers' {
                It 'Should return the correct values' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DesiredMembers = $null
                            CurrentMembers = 'OldMember'
                        }

                        $result = Get-MembersToAddAndRemove @mockParameters

                        $result.MembersToAdd | Should -BeNullOrEmpty
                        $result.MembersToRemove | Should -HaveCount 1
                        $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers
                    }
                }
            }
        }

        Context 'When there is more than one current member' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DesiredMembers = $null
                        CurrentMembers = @('OldMember1', 'OldMember2')
                    }

                    $result = Get-MembersToAddAndRemove @mockParameters

                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -HaveCount 2
                    $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers[0]
                    $result.MembersToRemove[1].ToString() | Should -Be $mockParameters.CurrentMembers[1]
                }
            }
        }
    }

    Context 'When the same members are present in desired members and current members' {
        Context 'When proving a collection for CurrentMembers' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DesiredMembers = @('Member1')
                        CurrentMembers = @('Member1')
                    }

                    $result = Get-MembersToAddAndRemove @mockParameters

                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -BeNullOrEmpty
                }
            }
        }

        Context 'When proving a string value for CurrentMembers' {
            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DesiredMembers = 'Member1'
                        CurrentMembers = 'Member1'
                    }

                    $result = Get-MembersToAddAndRemove @mockParameters

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

                    $mockParameters = @{
                        DesiredMembers = @('Member1', 'Member2')
                        CurrentMembers = @('Member1')
                    }

                    $result = Get-MembersToAddAndRemove @mockParameters

                    $result.MembersToAdd | Should -HaveCount 1
                    $result.MembersToAdd[0].ToString() | Should -Be $mockParameters.DesiredMembers[1]
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

                    $mockParameters = @{
                        DesiredMembers = 'Member1'
                        CurrentMembers = @('Member1', 'Member2')
                    }

                    $result = Get-MembersToAddAndRemove @mockParameters

                    $result.MembersToAdd | Should -BeNullOrEmpty
                    $result.MembersToRemove | Should -HaveCount 1
                    $result.MembersToRemove[0].ToString() | Should -Be $mockParameters.CurrentMembers[1]
                }
            }
        }
    }
}
