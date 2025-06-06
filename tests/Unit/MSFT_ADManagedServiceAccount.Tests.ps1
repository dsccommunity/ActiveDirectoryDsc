# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'False positive on ManagedPasswordPrincipals')]
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
    $script:dscResourceName = 'MSFT_ADManagedServiceAccount'

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

Describe -Name 'MSFT_ADManagedServiceAccount\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
        Mock -CommandName Get-ADObjectParentDN
        Mock -CommandName Get-AdObject
    }

    Context 'When the resource is Present' {
        Context 'When the Resource is a StandAlone account' {
            BeforeAll {
                Mock -CommandName Get-ADServiceAccount -MockWith {
                    @{
                        CN                     = 'TestSMSACN'
                        Description            = 'Dummy StandAlone service account for unit testing'
                        DisplayName            = 'TestSMSA'
                        DistinguishedName      = 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                = $true
                        KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation   = $false
                        Name                   = 'TestSMSA'
                        ObjectClass            = 'msDS-ManagedServiceAccount'
                        ObjectGUID             = '91bffe90-4c84-4026-b1fc-d03671ff56ad'
                        SamAccountName         = 'TestSMSA'
                        SID                    = 'S-1-5-21-1409167834-891301383-2860967316-1144'
                        UserPrincipalName      = ''
                    }
                }

                Mock -CommandName Get-AdObjectParentDN -MockWith { 'CN=Managed Service Accounts,DC=contoso,DC=com' }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestSMSA'
                        AccountType        = 'Standalone'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.Ensure | Should -Be 'Present'
                    $result.ServiceAccountName | Should -Be $mockParameters.ServiceAccountName
                    $result.AccountType | Should -Be $mockParameters.AccountType
                    $result.CommonName | Should -Be 'TestSMSACN'
                    $result.DistinguishedName | Should -Be 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                    $result.Description | Should -Be 'Dummy StandAlone service account for unit testing'
                    $result.DisplayName | Should -Be 'TestSMSA'
                    $result.Enabled | Should -BeTrue
                    $result.KerberosEncryptionType | Should -Be 'RC4', 'AES128', 'AES256'
                    $result.TrustedForDelegation | Should -BeFalse
                    $result.ManagedPasswordPrincipals | Should -Be @()
                    $result.MembershipAttribute | Should -Be 'SamAccountName'
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADServiceAccount -ParameterFilter { $Identity -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-AdObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ADObjectParentDN -ParameterFilter { $DN -eq 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the Resource is a Group account' {
            BeforeAll {
                Mock -CommandName Get-ADServiceAccount -MockWith {
                    @{
                        CN                                         = 'TestGMSACN'
                        Description                                = 'Dummy group service account for unit testing'
                        DisplayName                                = 'TestGMSA'
                        DistinguishedName                          = 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                                    = $true
                        KerberosEncryptionType                     = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation                       = $true
                        Name                                       = 'TestGMSA'
                        ObjectClass                                = 'msDS-GroupManagedServiceAccount'
                        ObjectGUID                                 = '91bffe90-4c84-4026-b1fc-d03671ff56ae'
                        PrincipalsAllowedToRetrieveManagedPassword = 'User1', 'Node1$'
                        SamAccountName                             = 'TestGMSA'
                        SID                                        = 'S-1-5-21-1409167834-891301383-2860967316-1145'
                        UserPrincipalName                          = ''
                    }
                }

                Mock -CommandName Get-ADObject -ParameterFilter { $Identity -eq 'Node1$' } -MockWith {
                    @{
                        DistinguishedName = 'CN=Node1,CN=Computers,DC=contoso,DC=com'
                        Name              = 'Node1'
                        ObjectClass       = 'computer'
                        ObjectGUID        = '91bffe90-4c84-4026-b1fc-d03671ff56ac'
                        ObjectSID         = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName    = 'Node1$'
                    }
                }

                Mock -CommandName Get-ADObject -ParameterFilter { $Identity -eq 'User1' } -MockWith {
                    @{
                        DistinguishedName = 'CN=User1,CN=Users,DC=contoso,DC=com'
                        Name              = 'User1'
                        ObjectClass       = 'user'
                        ObjectGUID        = '91bffe90-4c84-4026-b1fc-d03671ff56ab'
                        ObjectSid         = 'S-1-5-21-1409167834-891301383-2860967316-1142'
                        SamAccountName    = 'User1'
                    }
                }

                Mock -CommandName Get-AdObjectParentDN -MockWith { 'CN=Managed Service Accounts,DC=contoso,DC=com' }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestGMSA'
                        AccountType        = 'Group'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.Ensure | Should -Be 'Present'
                    $result.ServiceAccountName = $mockParameters.ServiceAccountName
                    $result.AccountType = $mockParameters.AccountType
                    $result.CommonName = 'TestGMSACN'
                    $result.DistinguishedName = 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                    $result.Description = 'Dummy group service account for unit testing'
                    $result.DisplayName = 'TestGMSA'
                    $result.Enabled = $true
                    $result.KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                    $result.TrustedForDelegation = $true
                    $result.ManagedPasswordPrincipals = 'User1', 'Node1$'
                    $result.MembershipAttribute = 'SamAccountName'
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADServiceAccount -ParameterFilter { $Identity -eq 'TestGMSA' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-AdObject -ParameterFilter { $Identity -eq 'User1' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-AdObject -ParameterFilter { $Identity -eq 'Node1$' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADObjectParentDN -ParameterFilter { $DN -eq 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When Get-AdServiceAccount throws an unexpected error' {
            BeforeAll {
                Mock -CommandName Get-ADServiceAccount -MockWith { throw 'UnexpectedError' }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestSMSA'
                        AccountType        = 'Standalone'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RetrievingManagedServiceAccountError -f $mockParameters.ServiceAccountName)

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $error.Message
                }
            }
        }

        Context 'When the group service account member property contains an unknown principal' {
            BeforeAll {
                Mock -CommandName Get-ADServiceAccount -MockWith {
                    @{
                        CN                                         = 'TestGMSACN'
                        Description                                = 'Dummy group service account for unit testing'
                        DisplayName                                = 'TestGMSA'
                        DistinguishedName                          = 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                                    = $true
                        KerberosEncryptionType                     = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation                       = $true
                        Name                                       = 'TestGMSA'
                        ObjectClass                                = 'msDS-GroupManagedServiceAccount'
                        ObjectGUID                                 = '91bffe90-4c84-4026-b1fc-d03671ff56ae'
                        PrincipalsAllowedtoRetrieveManagedPassword = 'S-1-5-21-1409167834-891301383-2860967316-1142', 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        SamAccountName                             = 'TestGMSA'
                        SID                                        = 'S-1-5-21-1409167834-891301383-2860967316-1145'
                        UserPrincipalName                          = ''
                    }
                }

                Mock -CommandName Get-ADObject -MockWith {
                    throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                }
            }


            It 'Should return the correct ManagedPasswordPrincipals property`' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestGMSA'
                        AccountType        = 'Group'
                    }

                    $result = Get-TargetResource @mockParameters
                    $result.ManagedPasswordPrincipals | Should -Be 'S-1-5-21-1409167834-891301383-2860967316-1142', 'S-1-5-21-1409167834-891301383-2860967316-1143'
                }
            }
        }

        Context 'When Get-AdObject throws an unexpected error' {
            BeforeAll {
                Mock -CommandName Get-ADServiceAccount -MockWith {
                    @{
                        CN                                         = 'TestGMSACN'
                        Description                                = 'Dummy group service account for unit testing'
                        DisplayName                                = 'TestGMSA'
                        DistinguishedName                          = 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Enabled                                    = $true
                        KerberosEncryptionType                     = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation                       = $true
                        Name                                       = 'TestGMSA'
                        ObjectClass                                = 'msDS-GroupManagedServiceAccount'
                        ObjectGUID                                 = '91bffe90-4c84-4026-b1fc-d03671ff56ae'
                        PrincipalsAllowedToRetrieveManagedPassword = 'User1', 'Node1$'
                        SamAccountName                             = 'TestGMSA'
                        SID                                        = 'S-1-5-21-1409167834-891301383-2860967316-1145'
                        UserPrincipalName                          = ''
                    }
                }

                Mock -CommandName Get-ADObject -MockWith { throw 'UnexpectedError' }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestGMSA'
                        AccountType        = 'Group'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RetrievingManagedPasswordPrincipalsError -f 'User1')

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }
            }
        }
    }

    Context 'When the resource is Absent' {
        Context 'When the Resource is a StandAlone account' {
            BeforeAll {
                Mock -CommandName Get-AdServiceAccount -MockWith {
                    throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestSMSA'
                        AccountType        = 'Standalone'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.ServiceAccountName | Should -Be $mockParameters.ServiceAccountName
                    $result.AccountType | Should -Be $mockParameters.AccountType
                    $result.CommonName | Should -BeNullOrEmpty
                    $result.DistinguishedName | Should -BeNullOrEmpty
                    $result.Description | Should -BeNullOrEmpty
                    $result.DisplayName | Should -BeNullOrEmpty
                    $result.Enabled | Should -BeFalse
                    $result.ManagedPasswordPrincipals | Should -Be @()
                    $result.MembershipAttribute | Should -Be 'SamAccountName'
                    $result.KerberosEncryptionType | Should -Be @()
                    $result.TrustedForDelegation | Should -BeNullOrEmpty
                    $result.Ensure | Should -Be 'Absent'
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADServiceAccount -ParameterFilter { $Identity -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-AdObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the Resource is a Group account' {
            BeforeAll {
                Mock -CommandName Get-AdServiceAccount -MockWith {
                    throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName = 'TestGMSA'
                        AccountType        = 'Group'
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.ServiceAccountName | Should -Be $mockParameters.ServiceAccountName
                    $result.AccountType | Should -Be $mockParameters.AccountType
                    $result.CommonName | Should -BeNullOrEmpty
                    $result.DistinguishedName | Should -BeNullOrEmpty
                    $result.Description | Should -BeNullOrEmpty
                    $result.DisplayName | Should -BeNullOrEmpty
                    $result.Enabled | Should -BeFalse
                    $result.ManagedPasswordPrincipals | Should -Be @()
                    $result.MembershipAttribute | Should -Be 'SamAccountName'
                    $result.KerberosEncryptionType | Should -Be @()
                    $result.TrustedForDelegation | Should -BeNullOrEmpty
                    $result.Ensure | Should -Be 'Absent'
                }

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1
                Should -Invoke -CommandName Get-ADServiceAccount -ParameterFilter { $Identity -eq 'TestGMSA' } -Exactly -Times 1
                Should -Invoke -CommandName Get-AdObject -Exactly -Times 0
            }
        }
    }
}

Describe -Name 'MSFT_ADManagedServiceAccount\Test-TargetResource' -Tag 'Test' {
    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    ServiceAccountName        = 'TestSMSA'
                    DistinguishedName         = 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                    Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                    CommonName                = 'TestSMSACN'
                    Description               = 'Dummy StandAlone service account for unit testing'
                    DisplayName               = 'TestSMSA'
                    AccountType               = 'Standalone'
                    Ensure                    = 'Present'
                    Enabled                   = $true
                    ManagedPasswordPrincipals = @()
                    MembershipAttribute       = 'SamAccountName'
                    Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                         (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainController          = 'MockDC'
                    KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                    TrustedForDelegation      = $false
                }
            }
        }

        Context 'When the Resource should be Present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'CommonName'
                        Value    = 'Changed commonName'
                    }
                    @{
                        Property = 'Description'
                        Value    = 'Changed description'
                    }
                    @{
                        Property = 'DisplayName'
                        Value    = 'Changed displayname'
                    }
                    @{
                        Property = 'KerberosEncryptionType'
                        Value    = 'AES128', 'AES256'
                    }
                    @{
                        Property = 'TrustedForDelegation'
                        Value    = $true
                    }
                    @{
                        Property = 'ManagedPasswordPrincipals'
                        Value    = 'User1'
                    }
                )
            }
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName        = 'TestSMSA'
                        AccountType               = 'Standalone'
                        CommonName                = 'TestSMSACN'
                        Description               = 'Dummy StandAlone service account for unit testing'
                        DisplayName               = 'TestSMSA'
                        KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation      = $false
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        Ensure                    = 'Present'
                    }

                    { Test-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $ServiceAccountName -eq 'TestSMSA'
                } -Exactly -times 1 -Scope It
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName        = 'TestSMSA'
                            AccountType               = 'Standalone'
                            CommonName                = 'TestSMSACN'
                            Description               = 'Dummy StandAlone service account for unit testing'
                            DisplayName               = 'TestSMSA'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                            ManagedPasswordPrincipals = @()
                            MembershipAttribute       = 'SamAccountName'
                            Ensure                    = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            Context 'When <Property> resource property is not in the desired state' -ForEach $testCases {
                It 'Should return $false' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName        = 'TestSMSA'
                            AccountType               = 'Standalone'
                            CommonName                = 'TestSMSACN'
                            Description               = 'Dummy StandAlone service account for unit testing'
                            DisplayName               = 'TestSMSA'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                            ManagedPasswordPrincipals = @()
                            MembershipAttribute       = 'SamAccountName'
                            Ensure                    = 'Present'
                        }

                        $mockParameters.$Property = $Value

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName        = 'TestSMSA'
                        AccountType               = 'Standalone'
                        CommonName                = 'TestSMSACN'
                        Description               = 'Dummy StandAlone service account for unit testing'
                        DisplayName               = 'TestSMSA'
                        KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation      = $false
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        Ensure                    = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $ServiceAccountName -eq 'TestSMSA'
                } -Exactly -times 1 -Scope It
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    ServiceAccountName        = 'TestSMSA'
                    DistinguishedName         = $null
                    Path                      = $null
                    CN                        = $null
                    Description               = $null
                    DisplayName               = $null
                    AccountType               = $null
                    Ensure                    = 'Absent'
                    Enabled                   = $false
                    ManagedPasswordPrincipals = @()
                    MembershipAttribute       = 'SamAccountName'
                    KerberosEncryptionType    = @()
                    TrustedForDelegation      = $null
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName        = 'TestSMSA'
                        AccountType               = 'Standalone'
                        CommonName                = 'TestSMSACN'
                        Description               = 'Dummy StandAlone service account for unit testing'
                        DisplayName               = 'TestSMSA'
                        KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation      = $false
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        Ensure                    = 'Present'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -times 1 -Scope It
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName        = 'TestSMSA'
                        AccountType               = 'Standalone'
                        CommonName                = 'TestSMSACN'
                        Description               = 'Dummy StandAlone service account for unit testing'
                        DisplayName               = 'TestSMSA'
                        KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation      = $false
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        Ensure                    = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe -Name 'MSFT_ADManagedServiceAccount\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName New-ADServiceAccount
        Mock -CommandName Remove-ADServiceAccount
        Mock -CommandName Move-ADObject
        Mock -CommandName Rename-ADObject
        Mock -CommandName Set-ADServiceAccount
        Mock -CommandName Get-DomainName -MockWith { 'contoso.com' }
        Mock -CommandName Get-ADDomain -MockWith {
            @{
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }
    }

    Context 'When the Resource should be Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    ServiceAccountName        = 'TestSMSA'
                    DistinguishedName         = 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                    Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                    CommonName                = 'TestSMSACN'
                    Description               = 'Dummy StandAlone service account for unit testing'
                    DisplayName               = 'TestSMSA'
                    AccountType               = 'Standalone'
                    Ensure                    = 'Present'
                    Enabled                   = $true
                    ManagedPasswordPrincipals = @()
                    MembershipAttribute       = 'SamAccountName'
                    Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                    DomainController          = 'MockDC'
                    KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                    TrustedForDelegation      = $false
                }
            }
        }

        Context 'When the Resource is Present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'CommonName'
                        Value    = 'Changed commonName'
                    }
                    @{
                        Property = 'Description'
                        Value    = 'Changed description'
                    }
                    @{
                        Property = 'DisplayName'
                        Value    = 'Changed displayname'
                    }
                    @{
                        Property = 'KerberosEncryptionType'
                        Value    = 'AES128', 'AES256'
                    }
                    @{
                        Property = 'TrustedForDelegation'
                        Value    = $true
                    }
                    @{
                        Property = 'ManagedPasswordPrincipals'
                        Value    = 'User1'
                    }
                )
            }

            Context 'When <Property> has changed' -ForEach $testCases {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            ServiceAccountName        = 'TestGMSA'
                            DistinguishedName         = 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestGMSACN'
                            Description               = 'Dummy group service account for unit testing'
                            DisplayName               = 'TestGMSA'
                            AccountType               = 'Group'
                            Ensure                    = 'Present'
                            Enabled                   = $true
                            ManagedPasswordPrincipals = 'User1', 'Node1$'
                            MembershipAttribute       = 'SamAccountName'
                            Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                            DomainController          = 'MockDC'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                        }
                    }
                }

                It 'Should call the correct mocks' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName        = 'TestGMSA'
                            MembershipAttribute       = 'SamAccountName'
                            AccountType               = 'Group'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestGMSACN'
                            Description               = 'Dummy group service account for unit testing'
                            Ensure                    = 'Present'
                            ManagedPasswordPrincipals = 'User1', 'Node1$'
                            DisplayName               = 'TestGMSA'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $true
                        }

                        $mockParameters.$Property = $Value

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestGMSA' } -Scope It -Exactly -Times 1
                    Should -Invoke -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                    Should -Invoke -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0

                    if ($Property -eq 'CommonName')
                    {
                        Should -Invoke -CommandName Rename-ADObject -Scope It -Exactly -Times 1
                    }
                    else
                    {
                        Should -Invoke -CommandName Rename-ADObject -Scope It -Exactly -Times 0
                    }

                    Should -Invoke -CommandName Move-ADObject -Scope It -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADServiceAccount -ParameterFilter { $Identity -eq 'TestGMSA' } -Scope It -Exactly -Times 1
                    Should -Invoke -CommandName Get-DomainName -Scope It -Exactly -Times 0
                    Should -Invoke -CommandName Get-ADDomain -Scope It -Exactly -Times 0
                }
            }

            Context 'When ''Set-AdServiceAccount'' throws an exception' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            ServiceAccountName        = 'TestGMSA'
                            DistinguishedName         = 'CN=TestGMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestGMSACN'
                            Description               = 'Dummy group service account for unit testing'
                            DisplayName               = 'TestGMSA'
                            AccountType               = 'Group'
                            Ensure                    = 'Present'
                            Enabled                   = $true
                            ManagedPasswordPrincipals = 'User1', 'Node1$'
                            MembershipAttribute       = 'SamAccountName'
                            Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                            DomainController          = 'MockDC'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                        }
                    }

                    Mock -CommandName Set-ADServiceAccount -MockWith { throw }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName        = 'TestGMSA'
                            MembershipAttribute       = 'SamAccountName'
                            AccountType               = 'Group'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestGMSACN'
                            Description               = 'Changed description'
                            Ensure                    = 'Present'
                            ManagedPasswordPrincipals = 'User1', 'Node1$'
                            DisplayName               = 'TestGMSA'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message (
                            $script:localizedData.SettingManagedServiceAccountError -f
                            $mockParameters.AccountType,
                            $mockParameters.ServiceAccountName
                        )

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }
                }
            }

            Context 'When the Resource has a changed AccountType' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            ServiceAccountName        = 'TestSMSA'
                            DistinguishedName         = 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestSMSACN'
                            Description               = 'Dummy StandAlone service account for unit testing'
                            DisplayName               = 'TestSMSA'
                            AccountType               = 'Standalone'
                            Ensure                    = 'Present'
                            Enabled                   = $true
                            ManagedPasswordPrincipals = @()
                            MembershipAttribute       = 'SamAccountName'
                            Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                            DomainController          = 'MockDC'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                        }
                    }
                }

                It 'Should call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName     = 'TestSMSA'
                            AccountType            = 'Group'
                            Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName             = 'TestSMSACN'
                            Description            = 'Dummy StandAlone service account for unit testing'
                            Ensure                 = 'Present'
                            DisplayName            = 'TestSMSA'
                            KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation   = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADServiceAccount -ParameterFilter { $Name -eq 'TestSMSACN' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADServiceAccount -ParameterFilter { $Identity -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Get-DomainName -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
                }

                Context 'When ''Remove-AdServiceAccount'' throws an exception' {
                    BeforeAll {
                        Mock -CommandName Remove-ADServiceAccount -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                ServiceAccountName     = 'TestSMSA'
                                AccountType            = 'Group'
                                Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                                CommonName             = 'TestSMSACN'
                                Description            = 'Dummy StandAlone service account for unit testing'
                                Ensure                 = 'Present'
                                DisplayName            = 'TestSMSA'
                                KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                                TrustedForDelegation   = $false
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message (
                                $script:localizedData.RemovingManagedServiceAccountError -f
                                $mockParameters.AccountType,
                                $mockParameters.ServiceAccountName
                            )

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }

            Context 'When the Resource has a changed Path' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            ServiceAccountName        = 'TestSMSA'
                            DistinguishedName         = 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestSMSACN'
                            Description               = 'Dummy StandAlone service account for unit testing'
                            DisplayName               = 'TestSMSA'
                            AccountType               = 'Standalone'
                            Ensure                    = 'Present'
                            Enabled                   = $true
                            ManagedPasswordPrincipals = @()
                            MembershipAttribute       = 'SamAccountName'
                            Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                            DomainController          = 'MockDC'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $false
                        }
                    }
                }

                It 'Should call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName     = 'TestSMSA'
                            AccountType            = 'Standalone'
                            Path                   = 'OU=Service Accounts,DC=contoso,DC=com'
                            CommonName             = 'TestSMSACN'
                            Description            = 'Dummy StandAlone service account for unit testing'
                            Ensure                 = 'Present'
                            DisplayName            = 'TestSMSA'
                            KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation   = $false
                        }

                        Set-TargetResource @mockParameters
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -ParameterFilter { $Identity -eq 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-DomainName -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
                }

                Context 'When ''Move-AdObject'' throws an exception' {
                    BeforeAll {
                        Mock -CommandName Move-AdObject -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                ServiceAccountName     = 'TestSMSA'
                                AccountType            = 'Standalone'
                                Path                   = 'OU=Service Accounts,DC=contoso,DC=com'
                                CommonName             = 'TestSMSACN'
                                Description            = 'Dummy StandAlone service account for unit testing'
                                Ensure                 = 'Present'
                                DisplayName            = 'TestSMSA'
                                KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                                TrustedForDelegation   = $false
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message (
                                $script:localizedData.MovingManagedServiceAccountError -f
                                $mockParameters.AccountType,
                                $mockParameters.ServiceAccountName,
                                'CN=Managed Service Accounts,DC=contoso,DC=com',
                                $mockParameters.Path
                            )

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }
        }

        Context 'When the Resource is Absent' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        ServiceAccountName        = 'TestSMSA'
                        DistinguishedName         = $null
                        Path                      = $null
                        CN                        = $null
                        Description               = $null
                        DisplayName               = $null
                        AccountType               = $null
                        Ensure                    = 'Absent'
                        Enabled                   = $false
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        KerberosEncryptionType    = @()
                        TrustedForDelegation      = $null
                    }
                }
            }

            Context 'When the resource is a Standalone Account' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName     = 'TestSMSA'
                            AccountType            = 'Standalone'
                            Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName             = 'TestSMSACN'
                            Description            = 'Dummy StandAlone service account for unit testing'
                            Ensure                 = 'Present'
                            DisplayName            = 'TestSMSA'
                            KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation   = $false
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADServiceAccount -ParameterFilter { $Name -eq 'TestSMSACN' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-DomainName -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
                }

                Context 'When "New-AdServiceAccount" throws an unexpected exception' {
                    BeforeAll {
                        Mock -CommandName New-AdServiceAccount -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                ServiceAccountName     = 'TestSMSA'
                                AccountType            = 'Standalone'
                                Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                                CommonName             = 'TestSMSACN'
                                Description            = 'Dummy StandAlone service account for unit testing'
                                Ensure                 = 'Present'
                                DisplayName            = 'TestSMSA'
                                KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                                TrustedForDelegation   = $false
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message (
                                $script:localizedData.AddingManagedServiceAccountError -f
                                $mockParameters.AccountType,
                                $mockParameters.ServiceAccountName,
                                $mockParameters.Path
                            )

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }

                    Context 'When the Path property has not been specified' {
                        It 'Should throw the correct exception' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    ServiceAccountName     = 'TestSMSA'
                                    AccountType            = 'Standalone'
                                    CommonName             = 'TestSMSACN'
                                    Description            = 'Dummy StandAlone service account for unit testing'
                                    Ensure                 = 'Present'
                                    DisplayName            = 'TestSMSA'
                                    KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                                    TrustedForDelegation   = $false
                                }

                                $errorRecord = Get-InvalidOperationRecord -Message (
                                    $script:localizedData.AddingManagedServiceAccountError -f
                                    $mockParameters.AccountType,
                                    $mockParameters.ServiceAccountName,
                                    'CN=Managed Service Accounts,DC=contoso,DC=com'
                                )


                                { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                            }

                            Should -Invoke -CommandName Get-ADDomain -Scope It -Exactly -Times 1
                        }

                        Context 'when "Get-ADDomain" throws an exception' {
                            BeforeAll {
                                Mock -CommandName Get-ADDomain -MockWith { throw 'UnexpectedError' }
                            }

                            It 'Should throw the correct exception' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        ServiceAccountName     = 'TestSMSA'
                                        AccountType            = 'Standalone'
                                        CommonName             = 'TestSMSACN'
                                        Description            = 'Dummy StandAlone service account for unit testing'
                                        Ensure                 = 'Present'
                                        DisplayName            = 'TestSMSA'
                                        KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                                        TrustedForDelegation   = $false
                                    }

                                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.GettingADDomainError)

                                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                                }
                            }
                        }
                    }
                }
            }

            Context 'When the resource is a Group Account' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName        = 'TestGMSA'
                            MembershipAttribute       = 'SamAccountName'
                            AccountType               = 'Group'
                            Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName                = 'TestGMSACN'
                            Description               = 'Dummy group service account for unit testing'
                            Ensure                    = 'Present'
                            ManagedPasswordPrincipals = 'User1', 'Node1$'
                            DisplayName               = 'TestGMSA'
                            KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation      = $true
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestGMSA' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADServiceAccount -ParameterFilter { $Name -eq 'TestGMSACN' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Get-DomainName -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADServiceAccount -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
                }

                Context 'When "New-AdServiceAccount" throws an "ADException KDS key not found" exception' {
                    BeforeAll {
                        $mockADException = [Microsoft.ActiveDirectory.Management.ADException]::new()
                        $mockADException.ErrorCode = -2146893811

                        Mock -CommandName New-AdServiceAccount -MockWith { throw $mockADException }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $setTargetResourceParametersGroup = @{
                                ServiceAccountName        = 'TestGMSA'
                                MembershipAttribute       = 'SamAccountName'
                                AccountType               = 'Group'
                                Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                                CommonName                = 'TestGMSACN'
                                Description               = 'Dummy group service account for unit testing'
                                Ensure                    = 'Present'
                                ManagedPasswordPrincipals = 'User1', 'Node1$'
                                DisplayName               = 'TestGMSA'
                                KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                                TrustedForDelegation      = $true
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message (
                                $script:localizedData.KdsRootKeyNotFoundError -f $setTargetResourceParametersGroup.ServiceAccountName
                            )

                            { Set-TargetResource @setTargetResourceParametersGroup } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }

                Context 'When "New-AdServiceAccount" throws an unknown "ADException" exception' {
                    BeforeAll {
                        Mock -CommandName New-AdServiceAccount -MockWith {
                            throw [Microsoft.ActiveDirectory.Management.ADException]::new()
                        }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                ServiceAccountName        = 'TestGMSA'
                                MembershipAttribute       = 'SamAccountName'
                                AccountType               = 'Group'
                                Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                                CommonName                = 'TestGMSACN'
                                Description               = 'Dummy group service account for unit testing'
                                Ensure                    = 'Present'
                                ManagedPasswordPrincipals = 'User1', 'Node1$'
                                DisplayName               = 'TestGMSA'
                                KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                                TrustedForDelegation      = $true
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message (
                                $script:localizedData.AddingManagedServiceAccountError -f
                                $mockParameters.AccountType,
                                $mockParameters.ServiceAccountName,
                                $mockParameters.Path
                            )

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }
        }
    }

    Context 'When the Resource should be Absent' {
        Context 'When the Resource is Present' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        ServiceAccountName        = 'TestSMSA'
                        DistinguishedName         = 'CN=TestSMSACN,CN=Managed Service Accounts,DC=contoso,DC=com'
                        Path                      = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                        CommonName                = 'TestSMSACN'
                        Description               = 'Dummy StandAlone service account for unit testing'
                        DisplayName               = 'TestSMSA'
                        AccountType               = 'Standalone'
                        Ensure                    = 'Present'
                        Enabled                   = $true
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        Credential                = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                        DomainController          = 'MockDC'
                        KerberosEncryptionType    = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation      = $false
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName     = 'TestSMSA'
                        AccountType            = 'Standalone'
                        Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                        CommonName             = 'TestSMSACN'
                        Description            = 'Dummy StandAlone service account for unit testing'
                        Ensure                 = 'Absent'
                        DisplayName            = 'TestSMSA'
                        KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation   = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADServiceAccount -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADServiceAccount -ParameterFilter { $Identity -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADServiceAccount -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-DomainName -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
            }

            Context 'When ''Remove-AdServiceAccount'' throws an exception' {
                BeforeAll {
                    Mock -CommandName Remove-ADServiceAccount -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            ServiceAccountName     = 'TestSMSA'
                            AccountType            = 'Standalone'
                            Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                            CommonName             = 'TestSMSACN'
                            Description            = 'Dummy StandAlone service account for unit testing'
                            Ensure                 = 'Absent'
                            DisplayName            = 'TestSMSA'
                            KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                            TrustedForDelegation   = $false
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message (
                            $script:localizedData.RemovingManagedServiceAccountError -f
                            $mockParameters.AccountType,
                            $mockParameters.ServiceAccountName
                        )

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }
                }
            }
        }

        Context 'When the Resource is Absent' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        ServiceAccountName        = 'TestSMSA'
                        DistinguishedName         = $null
                        Path                      = $null
                        CN                        = $null
                        Description               = $null
                        DisplayName               = $null
                        AccountType               = $null
                        Ensure                    = 'Absent'
                        Enabled                   = $false
                        ManagedPasswordPrincipals = @()
                        MembershipAttribute       = 'SamAccountName'
                        KerberosEncryptionType    = @()
                        TrustedForDelegation      = $null
                    }
                }
            }

            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        ServiceAccountName     = 'TestSMSA'
                        AccountType            = 'Standalone'
                        Path                   = 'CN=Managed Service Accounts,DC=contoso,DC=com'
                        CommonName             = 'TestSMSACN'
                        Description            = 'Dummy StandAlone service account for unit testing'
                        Ensure                 = 'Absent'
                        DisplayName            = 'TestSMSA'
                        KerberosEncryptionType = 'RC4', 'AES128', 'AES256'
                        TrustedForDelegation   = $false
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $ServiceAccountName -eq 'TestSMSA' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADServiceAccount -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADServiceAccount -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADServiceAccount -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-DomainName -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-ADDomain -Exactly -Times 0 -Scope It
            }
        }
    }
}
