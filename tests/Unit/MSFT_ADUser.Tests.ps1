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
    $script:dscResourceName = 'MSFT_ADUser'

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

Describe 'MSFT_ADUser\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the resource is present' {
        BeforeAll {
            Mock -CommandName Get-ADUser -MockWith {
                @{
                    samAccountName                    = 'TestUser'
                    cn                                = 'TestUser'
                    UserPrincipalName                 = 'testuser@contoso.com'
                    DisplayName                       = 'Test User'
                    distinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                    GivenName                         = 'Test'
                    Initials                          = 'T'
                    sn                                = 'User'
                    Description                       = 'This is the test user'
                    StreetAddress                     = '1 Highway Road'
                    PostOfficeBox                     = 'PO Box 1'
                    l                                 = 'Cityville'
                    St                                = 'State'
                    PostalCode                        = 'AA1 1AA'
                    c                                 = 'US'
                    Department                        = 'IT'
                    Division                          = 'Global'
                    Company                           = 'Contoso'
                    physicalDeliveryOfficeName        = 'Office 1'
                    title                             = 'Test'
                    mail                              = 'testuser@contoso.com'
                    EmployeeID                        = 'ID1'
                    EmployeeNumber                    = '1'
                    HomeDirectory                     = '\\fs01\users\testuser'
                    HomeDrive                         = 'H:'
                    wWWHomePage                       = 'www.contoso.com/users/testuser'
                    ProfilePath                       = 'profilepath'
                    scriptPath                        = 'logonscript.ps1'
                    info                              = 'This is a test user'
                    telephoneNumber                   = '+1 12345'
                    mobile                            = '+1 23456'
                    facsimileTelephoneNumber          = '+1 34567'
                    Pager                             = '+1 45678'
                    IPPhone                           = '12345'
                    HomePhone                         = '+1 56789'
                    Enabled                           = $true
                    Manager                           = 'John Doe'
                    userWorkstations                  = 'PC01,PC02'
                    O                                 = 'Contoso'
                    middleName                        = 'User1'
                    ThumbnailPhoto                    = [System.Byte[]] (
                        255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                    )
                    PasswordNeverExpires              = $false
                    CannotChangePassword              = $false
                    pwdLastSet                        = 0
                    TrustedForDelegation              = $false
                    AccountNotDelegated               = $true
                    AllowReversiblePasswordEncryption = $false
                    CompoundIdentitySupported         = $false
                    PasswordNotRequired               = $false
                    SmartcardLogonRequired            = $false
                    ServicePrincipalName              = @('spn/a', 'spn/b')
                    ProxyAddresses                    = @('testuser1@fabrikam.com', 'testuser2@fabrikam.com')
                    AdminDescription                  = 'User_'
                    'msDS-PhoneticDisplayName'        = 'Test User Phonetic'
                    PreferredLanguage                 = 'en-US'
                    displayNamePrintable              = 'Test User Simple'
                }
            }
        }

        BeforeDiscovery {
            $testCases = @(
                @{
                    Property = 'DomainName'
                    Value    = 'contoso.com'
                }
                @{
                    Property = 'UserName'
                    Value    = 'TestUser'
                }
                @{
                    Property = 'Path'
                    Value    = 'CN=Users,DC=contoso,DC=com'
                }
                @{
                    Property = 'DistinguishedName'
                    Value    = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                }
                @{
                    Property = 'DisplayName'
                    Value    = 'Test User'
                }
                @{
                    Property = 'Initials'
                    Value    = 'T'
                }
                @{
                    Property = 'Enabled'
                    Value    = $true
                }
                @{
                    Property = 'GivenName'
                    Value    = 'Test'
                }
                @{
                    Property = 'CommonName'
                    Value    = 'TestUser'
                }
                @{
                    Property = 'Description'
                    Value    = 'This is the test user'
                }
                @{
                    Property = 'Surname'
                    Value    = 'User'
                }
                @{
                    Property = 'StreetAddress'
                    Value    = '1 Highway Road'
                }
                @{
                    Property = 'POBox'
                    Value    = 'PO Box 1'
                }
                @{
                    Property = 'City'
                    Value    = 'Cityville'
                }
                @{
                    Property = 'State'
                    Value    = 'State'
                }
                @{
                    Property = 'UserPrincipalName'
                    Value    = 'testuser@contoso.com'
                }
                @{
                    Property = 'ServicePrincipalNames'
                    Value    = 'spn/a', 'spn/b'
                }
                @{
                    Property = 'ThumbnailPhoto'
                    Value    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                }
                @{
                    Property = 'ThumbnailPhotoHash'
                    Value    = 'D8719F18D789F449CBD14B5798BE79F7'
                }
                @{
                    Property = 'PostalCode'
                    Value    = 'AA1 1AA'
                }
                @{
                    Property = 'Country'
                    Value    = 'US'
                }
                @{
                    Property = 'Department'
                    Value    = 'IT'
                }
                @{
                    Property = 'Division'
                    Value    = 'Global'
                }
                @{
                    Property = 'Company'
                    Value    = 'Contoso'
                }
                @{
                    Property = 'Office'
                    Value    = 'Office 1'
                }
                @{
                    Property = 'JobTitle'
                    Value    = 'Test'
                }
                @{
                    Property = 'EmailAddress'
                    Value    = 'testuser@contoso.com'
                }
                @{
                    Property = 'EmployeeID'
                    Value    = 'ID1'
                }
                @{
                    Property = 'EmployeeNumber'
                    Value    = '1'
                }
                @{
                    Property = 'HomeDirectory'
                    Value    = '\\fs01\users\testuser'
                }
                @{
                    Property = 'HomeDrive'
                    Value    = 'H:'
                }
                @{
                    Property = 'HomePage'
                    Value    = 'www.contoso.com/users/testuser'
                }
                @{
                    Property = 'ProfilePath'
                    Value    = 'profilepath'
                }
                @{
                    Property = 'LogonScript'
                    Value    = 'logonscript.ps1'
                }
                @{
                    Property = 'Notes'
                    Value    = 'This is a test user'
                }
                @{
                    Property = 'OfficePhone'
                    Value    = '+1 12345'
                }
                @{
                    Property = 'MobilePhone'
                    Value    = '+1 23456'
                }
                @{
                    Property = 'Fax'
                    Value    = '+1 34567'
                }
                @{
                    Property = 'Pager'
                    Value    = '+1 45678'
                }
                @{
                    Property = 'IPPhone'
                    Value    = '12345'
                }
                @{
                    Property = 'HomePhone'
                    Value    = '+1 56789'
                }
                @{
                    Property = 'Manager'
                    Value    = 'John Doe'
                }
                @{
                    Property = 'LogonWorkstations'
                    Value    = 'PC01,PC02'
                }
                @{
                    Property = 'Organization'
                    Value    = 'Contoso'
                }
                @{
                    Property = 'OtherName'
                    Value    = 'User1'
                }
                @{
                    Property = 'PasswordNeverExpires'
                    Value    = $false
                }
                @{
                    Property = 'CannotChangePassword'
                    Value    = $false
                }
                @{
                    Property = 'ChangePasswordAtLogon'
                    Value    = $true
                }
                @{
                    Property = 'TrustedForDelegation'
                    Value    = $false
                }
                @{
                    Property = 'AccountNotDelegated'
                    Value    = $true
                }
                @{
                    Property = 'AllowReversiblePasswordEncryption'
                    Value    = $false
                }
                @{
                    Property = 'CompoundIdentitySupported'
                    Value    = $false
                }
                @{
                    Property = 'PasswordNotRequired'
                    Value    = $false
                }
                @{
                    Property = 'SmartcardLogonRequired'
                    Value    = $false
                }
                @{
                    Property = 'ProxyAddresses'
                    Value    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
                }
                @{
                    Property = 'AdminDescription'
                    Value    = 'User_'
                }
                @{
                    Property = 'PhoneticDisplayName'
                    Value    = 'Test User Phonetic'
                }
                @{
                    Property = 'PreferredLanguage'
                    Value    = 'en-US'
                }
                @{
                    Property = 'SimpleDisplayName'
                    Value    = 'Test User Simple'
                }
                @{
                    Property = 'Ensure'
                    Value    = 'Present'
                }
            )
        }

        It 'Should call the expected mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainName = 'contoso.com'
                    UserName   = 'TestUser'
                }

                $script:targetResource = Get-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
        }

        It 'Should return the correct value for property <Property>' -TestCases $testCases {
            InModuleScope -Parameters $_ -ScriptBlock {
                Set-StrictMode -Version 1.0

                $script:targetResource.$Property | Should -Be $Value
            }
        }


        Context 'When the ''ChangePassswordAtLogon'' parameter is false' {
            BeforeAll {
                Mock -CommandName Get-ADUser -MockWith {
                    @{
                        samAccountName                    = 'TestUser'
                        cn                                = 'TestUser'
                        UserPrincipalName                 = 'testuser@contoso.com'
                        DisplayName                       = 'Test User'
                        distinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                        GivenName                         = 'Test'
                        Initials                          = 'T'
                        sn                                = 'User'
                        Description                       = 'This is the test user'
                        StreetAddress                     = '1 Highway Road'
                        PostOfficeBox                     = 'PO Box 1'
                        l                                 = 'Cityville'
                        St                                = 'State'
                        PostalCode                        = 'AA1 1AA'
                        c                                 = 'US'
                        Department                        = 'IT'
                        Division                          = 'Global'
                        Company                           = 'Contoso'
                        physicalDeliveryOfficeName        = 'Office 1'
                        title                             = 'Test'
                        mail                              = 'testuser@contoso.com'
                        EmployeeID                        = 'ID1'
                        EmployeeNumber                    = '1'
                        HomeDirectory                     = '\\fs01\users\testuser'
                        HomeDrive                         = 'H:'
                        wWWHomePage                       = 'www.contoso.com/users/testuser'
                        ProfilePath                       = 'profilepath'
                        scriptPath                        = 'logonscript.ps1'
                        info                              = 'This is a test user'
                        telephoneNumber                   = '+1 12345'
                        mobile                            = '+1 23456'
                        facsimileTelephoneNumber          = '+1 34567'
                        Pager                             = '+1 45678'
                        IPPhone                           = '12345'
                        HomePhone                         = '+1 56789'
                        Enabled                           = $true
                        Manager                           = 'John Doe'
                        userWorkstations                  = 'PC01,PC02'
                        O                                 = 'Contoso'
                        middleName                        = 'User1'
                        ThumbnailPhoto                    = [System.Byte[]] (
                            255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                        )
                        PasswordNeverExpires              = $false
                        CannotChangePassword              = $false
                        pwdLastSet                        = 12345678
                        TrustedForDelegation              = $false
                        AccountNotDelegated               = $true
                        AllowReversiblePasswordEncryption = $false
                        CompoundIdentitySupported         = $false
                        PasswordNotRequired               = $false
                        SmartcardLogonRequired            = $false
                        ServicePrincipalName              = @('spn/a', 'spn/b')
                        ProxyAddresses                    = @('testuser1@fabrikam.com', 'testuser2@fabrikam.com')
                        AdminDescription                  = 'User_'
                        'msDS-PhoneticDisplayName'        = 'Test User Phonetic'
                        PreferredLanguage                 = 'en-US'
                        displayNamePrintable              = 'Test User Simple'
                    }
                }
            }

            It 'Should return the correct property' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                    }

                    $targetResource = Get-TargetResource @mockParameters

                    $targetResource.ChangePasswordAtLogon | Should -BeFalse
                }

                Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the ''ThumbnailPhoto'' parameter is empty' {
            BeforeAll {
                Mock -CommandName Get-ADUser -MockWith {
                    @{
                        samAccountName                    = 'TestUser'
                        cn                                = 'TestUser'
                        UserPrincipalName                 = 'testuser@contoso.com'
                        DisplayName                       = 'Test User'
                        distinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                        GivenName                         = 'Test'
                        Initials                          = 'T'
                        sn                                = 'User'
                        Description                       = 'This is the test user'
                        StreetAddress                     = '1 Highway Road'
                        PostOfficeBox                     = 'PO Box 1'
                        l                                 = 'Cityville'
                        St                                = 'State'
                        PostalCode                        = 'AA1 1AA'
                        c                                 = 'US'
                        Department                        = 'IT'
                        Division                          = 'Global'
                        Company                           = 'Contoso'
                        physicalDeliveryOfficeName        = 'Office 1'
                        title                             = 'Test'
                        mail                              = 'testuser@contoso.com'
                        EmployeeID                        = 'ID1'
                        EmployeeNumber                    = '1'
                        HomeDirectory                     = '\\fs01\users\testuser'
                        HomeDrive                         = 'H:'
                        wWWHomePage                       = 'www.contoso.com/users/testuser'
                        ProfilePath                       = 'profilepath'
                        scriptPath                        = 'logonscript.ps1'
                        info                              = 'This is a test user'
                        telephoneNumber                   = '+1 12345'
                        mobile                            = '+1 23456'
                        facsimileTelephoneNumber          = '+1 34567'
                        Pager                             = '+1 45678'
                        IPPhone                           = '12345'
                        HomePhone                         = '+1 56789'
                        Enabled                           = $true
                        Manager                           = 'John Doe'
                        userWorkstations                  = 'PC01,PC02'
                        O                                 = 'Contoso'
                        middleName                        = 'User1'
                        ThumbnailPhoto                    = ''
                        PasswordNeverExpires              = $false
                        CannotChangePassword              = $false
                        pwdLastSet                        = 0
                        TrustedForDelegation              = $false
                        AccountNotDelegated               = $true
                        AllowReversiblePasswordEncryption = $false
                        CompoundIdentitySupported         = $false
                        PasswordNotRequired               = $false
                        SmartcardLogonRequired            = $false
                        ServicePrincipalName              = @('spn/a', 'spn/b')
                        ProxyAddresses                    = @('testuser1@fabrikam.com', 'testuser2@fabrikam.com')
                        AdminDescription                  = 'User_'
                        'msDS-PhoneticDisplayName'        = 'Test User Phonetic'
                        PreferredLanguage                 = 'en-US'
                        displayNamePrintable              = 'Test User Simple'
                    }
                }
            }

            It 'Should return the correct property' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                    }
                    $targetResource = Get-TargetResource @mockParameters

                    $targetResource.ThumbnailPhoto | Should -BeNullOrEmpty
                    $targetResource.ThumbnailPhotoHash | Should -BeNullOrEmpty
                }

                Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the resource is absent' {
        BeforeAll {
            Mock -CommandName Get-ADUser -MockWith {
                throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainName = 'contoso.com'
                    UserName   = 'TestUser'
                }

                $targetResource = Get-TargetResource @mockParameters

                $targetResource.DomainName | Should -Be 'contoso.com'
                $targetResource.UserName | Should -Be 'TestUser'
                $targetResource.Path | Should -BeNullOrEmpty
                $targetResource.DistinguishedName | Should -BeNullOrEmpty
                $targetResource.DisplayName | Should -BeNullOrEmpty
                $targetResource.Initials | Should -BeNullOrEmpty
                $targetResource.Enabled | Should -BeNullOrEmpty
                $targetResource.GivenName | Should -BeNullOrEmpty
                $targetResource.CommonName | Should -BeNullOrEmpty
                $targetResource.Password | Should -BeNullOrEmpty
                $targetResource.Description | Should -BeNullOrEmpty
                $targetResource.Surname | Should -BeNullOrEmpty
                $targetResource.StreetAddress | Should -BeNullOrEmpty
                $targetResource.POBox | Should -BeNullOrEmpty
                $targetResource.City | Should -BeNullOrEmpty
                $targetResource.State | Should -BeNullOrEmpty
                $targetResource.UserPrincipalName | Should -BeNullOrEmpty
                $targetResource.ServicePrincipalNames | Should -BeNullOrEmpty
                $targetResource.ThumbnailPhoto | Should -BeNullOrEmpty
                $targetResource.ThumbnailPhotoHash | Should -BeNullOrEmpty
                $targetResource.PostalCode | Should -BeNullOrEmpty
                $targetResource.Country | Should -BeNullOrEmpty
                $targetResource.Department | Should -BeNullOrEmpty
                $targetResource.Division | Should -BeNullOrEmpty
                $targetResource.Company | Should -BeNullOrEmpty
                $targetResource.Office | Should -BeNullOrEmpty
                $targetResource.JobTitle | Should -BeNullOrEmpty
                $targetResource.EmailAddress | Should -BeNullOrEmpty
                $targetResource.EmployeeID | Should -BeNullOrEmpty
                $targetResource.EmployeeNumber | Should -BeNullOrEmpty
                $targetResource.HomeDirectory | Should -BeNullOrEmpty
                $targetResource.HomeDrive | Should -BeNullOrEmpty
                $targetResource.HomePage | Should -BeNullOrEmpty
                $targetResource.ProfilePath | Should -BeNullOrEmpty
                $targetResource.LogonScript | Should -BeNullOrEmpty
                $targetResource.Notes | Should -BeNullOrEmpty
                $targetResource.OfficePhone | Should -BeNullOrEmpty
                $targetResource.MobilePhone | Should -BeNullOrEmpty
                $targetResource.Fax | Should -BeNullOrEmpty
                $targetResource.Pager | Should -BeNullOrEmpty
                $targetResource.IPPhone | Should -BeNullOrEmpty
                $targetResource.HomePhone | Should -BeNullOrEmpty
                $targetResource.Manager | Should -BeNullOrEmpty
                $targetResource.LogonWorkstations | Should -BeNullOrEmpty
                $targetResource.Organization | Should -BeNullOrEmpty
                $targetResource.OtherName | Should -BeNullOrEmpty
                $targetResource.PasswordNeverExpires | Should -BeNullOrEmpty
                $targetResource.CannotChangePassword | Should -BeNullOrEmpty
                $targetResource.ChangePasswordAtLogon | Should -BeNullOrEmpty
                $targetResource.TrustedForDelegation | Should -BeNullOrEmpty
                $targetResource.AccountNotDelegated | Should -BeNullOrEmpty
                $targetResource.AllowReversiblePasswordEncryption | Should -BeNullOrEmpty
                $targetResource.CompoundIdentitySupported | Should -BeNullOrEmpty
                $targetResource.PasswordNotRequired | Should -BeNullOrEmpty
                $targetResource.SmartcardLogonRequired | Should -BeNullOrEmpty
                $targetResource.ProxyAddresses | Should -BeNullOrEmpty
                $targetResource.AdminDescription | Should -BeNullOrEmpty
                $targetResource.PhoneticDisplayName | Should -BeNullOrEmpty
                $targetResource.PreferredLanguage | Should -BeNullOrEmpty
                $targetResource.SimpleDisplayName | Should -BeNullOrEmpty
                $targetResource.Ensure | Should -Be 'Absent'
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Get-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1
        }
    }

    Context 'When Get-ADUser returns an unknown error' {
        BeforeAll {
            Mock -CommandName Get-ADUser -MockWith { throw }
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainName = 'contoso.com'
                    UserName   = 'TestUser'
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RetrievingADUserError -f
                    $mockParameters.UserName, $mockParameters.DomainName)

                { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
            }
        }
    }

    Context 'When the ''DomainController'' parameter is specified' {
        BeforeAll {
            Mock -CommandName Get-ADUser -MockWith {
                @{
                    samAccountName                    = 'TestUser'
                    cn                                = 'TestUser'
                    UserPrincipalName                 = 'testuser@contoso.com'
                    DisplayName                       = 'Test User'
                    distinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                    GivenName                         = 'Test'
                    Initials                          = 'T'
                    sn                                = 'User'
                    Description                       = 'This is the test user'
                    StreetAddress                     = '1 Highway Road'
                    PostOfficeBox                     = 'PO Box 1'
                    l                                 = 'Cityville'
                    St                                = 'State'
                    PostalCode                        = 'AA1 1AA'
                    c                                 = 'US'
                    Department                        = 'IT'
                    Division                          = 'Global'
                    Company                           = 'Contoso'
                    physicalDeliveryOfficeName        = 'Office 1'
                    title                             = 'Test'
                    mail                              = 'testuser@contoso.com'
                    EmployeeID                        = 'ID1'
                    EmployeeNumber                    = '1'
                    HomeDirectory                     = '\\fs01\users\testuser'
                    HomeDrive                         = 'H:'
                    wWWHomePage                       = 'www.contoso.com/users/testuser'
                    ProfilePath                       = 'profilepath'
                    scriptPath                        = 'logonscript.ps1'
                    info                              = 'This is a test user'
                    telephoneNumber                   = '+1 12345'
                    mobile                            = '+1 23456'
                    facsimileTelephoneNumber          = '+1 34567'
                    Pager                             = '+1 45678'
                    IPPhone                           = '12345'
                    HomePhone                         = '+1 56789'
                    Enabled                           = $true
                    Manager                           = 'John Doe'
                    userWorkstations                  = 'PC01,PC02'
                    O                                 = 'Contoso'
                    middleName                        = 'User1'
                    ThumbnailPhoto                    = [System.Byte[]] (
                        255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                    )
                    PasswordNeverExpires              = $false
                    CannotChangePassword              = $false
                    pwdLastSet                        = 0
                    TrustedForDelegation              = $false
                    AccountNotDelegated               = $true
                    AllowReversiblePasswordEncryption = $false
                    CompoundIdentitySupported         = $false
                    PasswordNotRequired               = $false
                    SmartcardLogonRequired            = $false
                    ServicePrincipalName              = @('spn/a', 'spn/b')
                    ProxyAddresses                    = @('testuser1@fabrikam.com', 'testuser2@fabrikam.com')
                    AdminDescription                  = 'User_'
                    'msDS-PhoneticDisplayName'        = 'Test User Phonetic'
                    PreferredLanguage                 = 'en-US'
                    displayNamePrintable              = 'Test User Simple'
                }
            }
        }

        It 'Should call the expected mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainName       = 'contoso.com'
                    UserName         = 'TestUser'
                    DomainController = 'TESTDC'
                }

                Get-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADUser -ParameterFilter { $Server -eq 'TESTDC' } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the ''Credential'' parameter is specified' {
        BeforeAll {
            Mock -CommandName Get-ADUser -MockWith {
                @{
                    samAccountName                    = 'TestUser'
                    cn                                = 'TestUser'
                    UserPrincipalName                 = 'testuser@contoso.com'
                    DisplayName                       = 'Test User'
                    distinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                    GivenName                         = 'Test'
                    Initials                          = 'T'
                    sn                                = 'User'
                    Description                       = 'This is the test user'
                    StreetAddress                     = '1 Highway Road'
                    PostOfficeBox                     = 'PO Box 1'
                    l                                 = 'Cityville'
                    St                                = 'State'
                    PostalCode                        = 'AA1 1AA'
                    c                                 = 'US'
                    Department                        = 'IT'
                    Division                          = 'Global'
                    Company                           = 'Contoso'
                    physicalDeliveryOfficeName        = 'Office 1'
                    title                             = 'Test'
                    mail                              = 'testuser@contoso.com'
                    EmployeeID                        = 'ID1'
                    EmployeeNumber                    = '1'
                    HomeDirectory                     = '\\fs01\users\testuser'
                    HomeDrive                         = 'H:'
                    wWWHomePage                       = 'www.contoso.com/users/testuser'
                    ProfilePath                       = 'profilepath'
                    scriptPath                        = 'logonscript.ps1'
                    info                              = 'This is a test user'
                    telephoneNumber                   = '+1 12345'
                    mobile                            = '+1 23456'
                    facsimileTelephoneNumber          = '+1 34567'
                    Pager                             = '+1 45678'
                    IPPhone                           = '12345'
                    HomePhone                         = '+1 56789'
                    Enabled                           = $true
                    Manager                           = 'John Doe'
                    userWorkstations                  = 'PC01,PC02'
                    O                                 = 'Contoso'
                    middleName                        = 'User1'
                    ThumbnailPhoto                    = [System.Byte[]] (
                        255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                    )
                    PasswordNeverExpires              = $false
                    CannotChangePassword              = $false
                    pwdLastSet                        = 0
                    TrustedForDelegation              = $false
                    AccountNotDelegated               = $true
                    AllowReversiblePasswordEncryption = $false
                    CompoundIdentitySupported         = $false
                    PasswordNotRequired               = $false
                    SmartcardLogonRequired            = $false
                    ServicePrincipalName              = @('spn/a', 'spn/b')
                    ProxyAddresses                    = @('testuser1@fabrikam.com', 'testuser2@fabrikam.com')
                    AdminDescription                  = 'User_'
                    'msDS-PhoneticDisplayName'        = 'Test User Phonetic'
                    PreferredLanguage                 = 'en-US'
                    displayNamePrintable              = 'Test User Simple'
                }
            }
        }

        It 'Should call the expected mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    DomainName = 'contoso.com'
                    UserName   = 'TestUser'
                    Credential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                }

                Get-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADUser -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADUser\Test-TargetResource' -Tag 'Test' {
    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                        = 'contoso.com'
                    UserName                          = 'TestUser'
                    Path                              = 'CN=Users,DC=contoso,DC=com'
                    DistinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                    DisplayName                       = 'Test User'
                    Initials                          = 'T'
                    Enabled                           = $true
                    GivenName                         = 'Test'
                    CommonName                        = 'TestUser'
                    Password                          = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                    Description                       = 'This is the test user'
                    Surname                           = 'User'
                    StreetAddress                     = '1 Highway Road'
                    POBox                             = 'PO Box 1'
                    City                              = 'Cityville'
                    State                             = 'State'
                    UserPrincipalName                 = 'testuser@contoso.com'
                    ServicePrincipalNames             = 'spn/a', 'spn/b'
                    ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                    ThumbnailPhotoHash                = 'D8719F18D789F449CBD14B5798BE79F7'
                    PostalCode                        = 'AA1 1AA'
                    Country                           = 'US'
                    Department                        = 'IT'
                    Division                          = 'Global'
                    Company                           = 'Contoso'
                    Office                            = 'Office 1'
                    JobTitle                          = 'Test'
                    EmailAddress                      = 'testuser@contoso.com'
                    EmployeeID                        = 'ID1'
                    EmployeeNumber                    = '1'
                    HomeDirectory                     = '\\fs01\users\testuser'
                    HomeDrive                         = 'H:'
                    HomePage                          = 'www.contoso.com/users/testuser'
                    ProfilePath                       = 'profilepath'
                    LogonScript                       = 'logonscript.ps1'
                    Notes                             = 'This is a test user'
                    OfficePhone                       = '+1 12345'
                    MobilePhone                       = '+1 23456'
                    Fax                               = '+1 34567'
                    Pager                             = '+1 45678'
                    IPPhone                           = '12345'
                    HomePhone                         = '+1 56789'
                    Manager                           = 'John Doe'
                    LogonWorkstations                 = 'PC01,PC02'
                    Organization                      = 'Contoso'
                    OtherName                         = 'User1'
                    PasswordNeverExpires              = $false
                    CannotChangePassword              = $false
                    ChangePasswordAtLogon             = $true
                    TrustedForDelegation              = $false
                    AccountNotDelegated               = $true
                    AllowReversiblePasswordEncryption = $false
                    CompoundIdentitySupported         = $false
                    PasswordNotRequired               = $false
                    SmartcardLogonRequired            = $false
                    ProxyAddresses                    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
                    AdminDescription                  = 'User_'
                    PhoneticDisplayName               = 'Test User Phonetic'
                    PreferredLanguage                 = 'en-US'
                    SimpleDisplayName                 = 'Test User Simple'
                    Ensure                            = 'Present'
                }
            }

            Mock -CommandName Test-Password
        }

        Context 'When the Resource should be Present' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                        Ensure     = 'Present'
                    }

                    { Test-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
            }

            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'Path'
                        Value    = 'OU=Staff,DC=contoso,DC=com'
                    }
                    @{
                        Property = 'DisplayName'
                        Value    = 'Test User Changed'
                    }
                    @{
                        Property = 'Initials'
                        Value    = 'S'
                    }
                    @{
                        Property = 'Enabled'
                        Value    = $false
                    }
                    @{
                        Property = 'GivenName'
                        Value    = 'Test Changed'
                    }
                    @{
                        Property = 'CommonName'
                        Value    = 'Common Changed'
                    }
                    @{
                        Property = 'Description'
                        Value    = 'This is the test user changed'
                    }
                    @{
                        Property = 'Surname'
                        Value    = 'User Changed'
                    }
                    @{
                        Property = 'StreetAddress'
                        Value    = '1 Highway Road Changed'
                    }
                    @{
                        Property = 'POBox'
                        Value    = 'PO Box 1 Changed'
                    }
                    @{
                        Property = 'City'
                        Value    = 'Cityville Changed'
                    }
                    @{
                        Property = 'State'
                        Value    = 'State Changed'
                    }
                    @{
                        Property = 'ServicePrincipalNames'
                        Value    = 'spn/c', 'spn/d'
                    }
                    @{
                        Property = 'ThumbnailPhoto'
                        Value    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhq'
                    }
                    @{
                        Property = 'PostalCode'
                        Value    = 'AA1 1AA Changed'
                    }
                    @{
                        Property = 'Country'
                        Value    = 'GB'
                    }
                    @{
                        Property = 'Department'
                        Value    = 'IT Changed'
                    }
                    @{
                        Property = 'Division'
                        Value    = 'Global Changed'
                    }
                    @{
                        Property = 'Company'
                        Value    = 'Contoso Changed'
                    }
                    @{
                        Property = 'Office'
                        Value    = 'Office 1 Changed'
                    }
                    @{
                        Property = 'JobTitle'
                        Value    = 'Test Changed'
                    }
                    @{
                        Property = 'EmailAddress'
                        Value    = 'testuserchanged@contoso.com'
                    }
                    @{
                        Property = 'EmployeeID'
                        Value    = 'ID1 Changed'
                    }
                    @{
                        Property = 'EmployeeNumber'
                        Value    = '2'
                    }
                    @{
                        Property = 'HomeDirectory'
                        Value    = '\\fs01\users\testuserchanged'
                    }
                    @{
                        Property = 'HomeDrive'
                        Value    = 'I:'
                    }
                    @{
                        Property = 'HomePage'
                        Value    = 'www.contoso.com/users/testuserchanged'
                    }
                    @{
                        Property = 'ProfilePath'
                        Value    = 'changed profile path'
                    }
                    @{
                        Property = 'LogonScript'
                        Value    = 'logonscript-changed.ps1'
                    }
                    @{
                        Property = 'Notes'
                        Value    = 'This is a test user changed'
                    }
                    @{
                        Property = 'OfficePhone'
                        Value    = '+1 123456'
                    }
                    @{
                        Property = 'MobilePhone'
                        Value    = '+1 234567'
                    }
                    @{
                        Property = 'Fax'
                        Value    = '+1 345678'
                    }
                    @{
                        Property = 'Pager'
                        Value    = '+1 456789'
                    }
                    @{
                        Property = 'IPPhone'
                        Value    = '123456'
                    }
                    @{
                        Property = 'HomePhone'
                        Value    = '+1 567890'
                    }
                    @{
                        Property = 'Manager'
                        Value    = 'John Doe Changed'
                    }
                    @{
                        Property = 'LogonWorkstations'
                        Value    = 'PC03,PC04'
                    }
                    @{
                        Property = 'Organization'
                        Value    = 'Contoso Changed'
                    }
                    @{
                        Property = 'OtherName'
                        Value    = 'User1 Changed'
                    }
                    @{
                        Property = 'PasswordNeverExpires'
                        Value    = $true
                    }
                    @{
                        Property = 'CannotChangePassword'
                        Value    = $true
                    }
                    @{
                        Property = 'ChangePasswordAtLogon'
                        Value    = $false
                    }
                    @{
                        Property = 'TrustedForDelegation'
                        Value    = $true
                    }
                    @{
                        Property = 'AccountNotDelegated'
                        Value    = $false
                    }
                    @{
                        Property = 'AllowReversiblePasswordEncryption'
                        Value    = $true
                    }
                    @{
                        Property = 'CompoundIdentitySupported'
                        Value    = $true
                    }
                    @{
                        Property = 'PasswordNotRequired'
                        Value    = $true
                    }
                    @{
                        Property = 'SmartcardLogonRequired'
                        Value    = $true
                    }
                    @{
                        Property = 'ProxyAddresses'
                        Value    = 'testuser3@fabrikam.com', 'testuser4@fabrikam.com'
                    }
                    @{
                        Property = 'AdminDescription'
                        Value    = 'User_ Changed'
                    }
                    @{
                        Property = 'PhoneticDisplayName'
                        Value    = 'Test User Phonetic Changed'
                    }
                    @{
                        Property = 'PreferredLanguage'
                        Value    = 'en-GB'
                    }
                    @{
                        Property = 'SimpleDisplayName'
                        Value    = 'Test User Simple Changed'
                    }
                )
            }

            Context 'When the property ''<Property>'' is not in the desired state' -ForEach $testCases {
                It 'Should return $false' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                        }

                        $mockParameters.$Property = $Value

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }
                }


                if ($Value -isnot [Boolean])
                {
                    if ($Value -isnot [Array])
                    {
                        Context 'When the ''<Property>'' parameter should be null' {
                            It 'Should return $false' {
                                InModuleScope -Parameters $_ -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName = 'contoso.com'
                                        UserName   = 'TestUser'
                                        Ensure     = 'Present'
                                    }

                                    $mockParameters.$Property = $null

                                    Test-TargetResource @mockParameters | Should -BeFalse
                                }
                            }
                        }
                    }

                    Context 'When the ''<Property>'' parameter should be empty' {
                        It 'Should return $false' {
                            InModuleScope -Parameters $_ -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                }

                                $mockParameters.$Property = ''

                                Test-TargetResource @mockParameters | Should -BeFalse
                            }
                        }
                    }
                }

                if ($Value -is [Array])
                {
                    Context 'When the ''<Property>'' parameter should be an empty array' {
                        It 'Should return $false' {
                            InModuleScope -Parameters $_ -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                }

                                $mockParameters.$Property = @()

                                Test-TargetResource @mockParameters | Should -BeFalse
                            }
                        }
                    }
                }
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return the desired result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            Context 'When the ''DomainController'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName       = 'contoso.com'
                            UserName         = 'TestUser'
                            Ensure           = 'Present'
                            DomainController = 'TESTDC'
                        }

                        { Test-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''Credential'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                            Credential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                        }

                        { Test-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''Password'' parameter is specified' {
                Context 'When the specified Password has changed' {
                    BeforeAll {
                        Mock -CommandName Test-Password -MockWith { $false }
                    }

                    Context 'When the ''PasswordNeverResets'' parameter is False' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName          = 'contoso.com'
                                    UserName            = 'TestUser'
                                    Ensure              = 'Present'
                                    Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordNeverResets = $false
                                }

                                Test-TargetResource @mockParameters | Should -BeFalse
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''PasswordNeverResets'' parameter is True' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName          = 'contoso.com'
                                    UserName            = 'TestUser'
                                    Ensure              = 'Present'
                                    Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordNeverResets = $true
                                }

                                Test-TargetResource @mockParameters | Should -BeTrue
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the ''Credential'' parameter is specified' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                    Credential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    Password   = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                Test-TargetResource @mockParameters | Should -BeFalse
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $null -ne $Credential
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''PasswordAuthentication'' parameter is specified as ''Default''' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName             = 'contoso.com'
                                    UserName               = 'TestUser'
                                    Ensure                 = 'Present'
                                    PasswordAuthentication = 'Default'
                                    Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                Test-TargetResource @mockParameters | Should -BeFalse
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $PasswordAuthentication -eq 'Default'
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''PasswordAuthentication'' parameter is specified as ''Negotiate''' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName             = 'contoso.com'
                                    UserName               = 'TestUser'
                                    Ensure                 = 'Present'
                                    PasswordAuthentication = 'Negotiate'
                                    Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                Test-TargetResource @mockParameters | Should -BeFalse
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $null -ne $PasswordAuthentication
                            } -Exactly -Times 1 -Scope It
                        }
                    }
                }

                Context 'When the specified Password has not changed' {
                    BeforeAll {
                        Mock -CommandName Test-Password -MockWith { $true }
                    }

                    Context 'When the ''PasswordNeverResets'' parameter is False' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName          = 'contoso.com'
                                    UserName            = 'TestUser'
                                    Ensure              = 'Present'
                                    Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordNeverResets = $false
                                }

                                Test-TargetResource @mockParameters | Should -BeTrue
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''PasswordNeverResets'' parameter is True' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName          = 'contoso.com'
                                    UserName            = 'TestUser'
                                    Ensure              = 'Present'
                                    Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordNeverResets = $true
                                }

                                Test-TargetResource @mockParameters | Should -BeTrue
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the ''Credential'' parameter is specified' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                    Credential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    Password   = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                Test-TargetResource @mockParameters | Should -BeTrue
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $null -ne $Credential
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''PasswordAuthentication'' parameter is specified as ''Default''' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName             = 'contoso.com'
                                    UserName               = 'TestUser'
                                    Ensure                 = 'Present'
                                    PasswordAuthentication = 'Default'
                                    Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                Test-TargetResource @mockParameters | Should -BeTrue
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $PasswordAuthentication -eq 'Default'
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''PasswordAuthentication'' parameter is specified as ''Negotiate''' {
                        It 'Should return the desired result' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName             = 'contoso.com'
                                    UserName               = 'TestUser'
                                    Ensure                 = 'Present'
                                    PasswordAuthentication = 'Negotiate'
                                    Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                Test-TargetResource @mockParameters | Should -BeTrue
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $PasswordAuthentication -eq 'Negotiate'
                            } -Exactly -Times 1 -Scope It
                        }
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return the desired result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                        Ensure     = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName = 'contoso.com'
                    UserName   = 'TestUser'
                    Ensure     = 'Absent'
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should return the desired result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                        Ensure     = 'Present'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
            }

            Context 'When ChangePasswordAtLogon is true and does not match the AD Account property' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            DomainName                        = 'contoso.com'
                            UserName                          = 'TestUser'
                            Path                              = 'CN=Users,DC=contoso,DC=com'
                            DistinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                            DisplayName                       = 'Test User'
                            Initials                          = 'T'
                            Enabled                           = $true
                            GivenName                         = 'Test'
                            CommonName                        = 'TestUser'
                            Password                          = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                            Description                       = 'This is the test user'
                            Surname                           = 'User'
                            StreetAddress                     = '1 Highway Road'
                            POBox                             = 'PO Box 1'
                            City                              = 'Cityville'
                            State                             = 'State'
                            UserPrincipalName                 = 'testuser@contoso.com'
                            ServicePrincipalNames             = 'spn/a', 'spn/b'
                            ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                            ThumbnailPhotoHash                = 'D8719F18D789F449CBD14B5798BE79F7'
                            PostalCode                        = 'AA1 1AA'
                            Country                           = 'US'
                            Department                        = 'IT'
                            Division                          = 'Global'
                            Company                           = 'Contoso'
                            Office                            = 'Office 1'
                            JobTitle                          = 'Test'
                            EmailAddress                      = 'testuser@contoso.com'
                            EmployeeID                        = 'ID1'
                            EmployeeNumber                    = '1'
                            HomeDirectory                     = '\\fs01\users\testuser'
                            HomeDrive                         = 'H:'
                            HomePage                          = 'www.contoso.com/users/testuser'
                            ProfilePath                       = 'profilepath'
                            LogonScript                       = 'logonscript.ps1'
                            Notes                             = 'This is a test user'
                            OfficePhone                       = '+1 12345'
                            MobilePhone                       = '+1 23456'
                            Fax                               = '+1 34567'
                            Pager                             = '+1 45678'
                            IPPhone                           = '12345'
                            HomePhone                         = '+1 56789'
                            Manager                           = 'John Doe'
                            LogonWorkstations                 = 'PC01,PC02'
                            Organization                      = 'Contoso'
                            OtherName                         = 'User1'
                            PasswordNeverExpires              = $false
                            CannotChangePassword              = $false
                            ChangePasswordAtLogon             = $false
                            TrustedForDelegation              = $false
                            AccountNotDelegated               = $true
                            AllowReversiblePasswordEncryption = $false
                            CompoundIdentitySupported         = $false
                            PasswordNotRequired               = $false
                            SmartcardLogonRequired            = $false
                            ProxyAddresses                    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
                            AdminDescription                  = 'User_'
                            PhoneticDisplayName               = 'Test User Phonetic'
                            PreferredLanguage                 = 'en-US'
                            SimpleDisplayName                 = 'Test User Simple'
                            Ensure                            = 'Absent'
                        }
                    }
                }

                It 'Should return the desired result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName            = 'contoso.com'
                            UserName              = 'TestUser'
                            Ensure                = 'Present'
                            ChangePasswordAtLogon = $true
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return the desired result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                        Ensure     = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADUser\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName Set-ADUser
        Mock -CommandName Move-ADObject
        Mock -CommandName Rename-ADObject
        Mock -CommandName Set-ADAccountPassword
        Mock -CommandName Test-Password
        Mock -CommandName Remove-ADUser
        Mock -CommandName New-ADUser
        Mock -CommandName Restore-ADCommonObject
    }

    Context 'When the resource is present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                        = 'contoso.com'
                    UserName                          = 'TestUser'
                    Path                              = 'CN=Users,DC=contoso,DC=com'
                    DistinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                    DisplayName                       = 'Test User'
                    Initials                          = 'T'
                    Enabled                           = $true
                    GivenName                         = 'Test'
                    CommonName                        = 'TestUser'
                    Password                          = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                    Description                       = 'This is the test user'
                    Surname                           = 'User'
                    StreetAddress                     = '1 Highway Road'
                    POBox                             = 'PO Box 1'
                    City                              = 'Cityville'
                    State                             = 'State'
                    UserPrincipalName                 = 'testuser@contoso.com'
                    ServicePrincipalNames             = 'spn/a', 'spn/b'
                    ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                    ThumbnailPhotoHash                = 'D8719F18D789F449CBD14B5798BE79F7'
                    PostalCode                        = 'AA1 1AA'
                    Country                           = 'US'
                    Department                        = 'IT'
                    Division                          = 'Global'
                    Company                           = 'Contoso'
                    Office                            = 'Office 1'
                    JobTitle                          = 'Test'
                    EmailAddress                      = 'testuser@contoso.com'
                    EmployeeID                        = 'ID1'
                    EmployeeNumber                    = '1'
                    HomeDirectory                     = '\\fs01\users\testuser'
                    HomeDrive                         = 'H:'
                    HomePage                          = 'www.contoso.com/users/testuser'
                    ProfilePath                       = 'profilepath'
                    LogonScript                       = 'logonscript.ps1'
                    Notes                             = 'This is a test user'
                    OfficePhone                       = '+1 12345'
                    MobilePhone                       = '+1 23456'
                    Fax                               = '+1 34567'
                    Pager                             = '+1 45678'
                    IPPhone                           = '12345'
                    HomePhone                         = '+1 56789'
                    Manager                           = 'John Doe'
                    LogonWorkstations                 = 'PC01,PC02'
                    Organization                      = 'Contoso'
                    OtherName                         = 'User1'
                    PasswordNeverExpires              = $false
                    CannotChangePassword              = $false
                    ChangePasswordAtLogon             = $true
                    TrustedForDelegation              = $false
                    AccountNotDelegated               = $true
                    AllowReversiblePasswordEncryption = $false
                    CompoundIdentitySupported         = $false
                    PasswordNotRequired               = $false
                    SmartcardLogonRequired            = $false
                    ProxyAddresses                    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
                    AdminDescription                  = 'User_'
                    PhoneticDisplayName               = 'Test User Phonetic'
                    PreferredLanguage                 = 'en-US'
                    SimpleDisplayName                 = 'Test User Simple'
                    Ensure                            = 'Present'
                }
            }
        }

        Context 'When the resource should be present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'DisplayName'
                        Value    = 'Test User Changed'
                    }
                    @{
                        Property = 'Initials'
                        Value    = 'S'
                    }
                    @{
                        Property = 'Enabled'
                        Value    = $false
                    }
                    @{
                        Property = 'GivenName'
                        Value    = 'Test Changed'
                    }
                    @{
                        Property = 'Description'
                        Value    = 'This is the test user changed'
                    }
                    @{
                        Property = 'Surname'
                        Value    = 'User Changed'
                    }
                    @{
                        Property = 'StreetAddress'
                        Value    = '1 Highway Road Changed'
                    }
                    @{
                        Property = 'POBox'
                        Value    = 'PO Box 1 Changed'
                    }
                    @{
                        Property = 'City'
                        Value    = 'Cityville Changed'
                    }
                    @{
                        Property = 'State'
                        Value    = 'State Changed'
                    }
                    @{
                        Property = 'ServicePrincipalNames'
                        Value    = 'spn/c', 'spn/d'
                    }
                    @{
                        Property = 'ThumbnailPhoto'
                        Value    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhq'
                    }
                    @{
                        Property = 'PostalCode'
                        Value    = 'AA1 1AA Changed'
                    }
                    @{
                        Property = 'Country'
                        Value    = 'GB'
                    }
                    @{
                        Property = 'Department'
                        Value    = 'IT Changed'
                    }
                    @{
                        Property = 'Division'
                        Value    = 'Global Changed'
                    }
                    @{
                        Property = 'Company'
                        Value    = 'Contoso Changed'
                    }
                    @{
                        Property = 'Office'
                        Value    = 'Office 1 Changed'
                    }
                    @{
                        Property = 'JobTitle'
                        Value    = 'Test Changed'
                    }
                    @{
                        Property = 'EmailAddress'
                        Value    = 'testuserchanged@contoso.com'
                    }
                    @{
                        Property = 'EmployeeID'
                        Value    = 'ID1 Changed'
                    }
                    @{
                        Property = 'EmployeeNumber'
                        Value    = '2'
                    }
                    @{
                        Property = 'HomeDirectory'
                        Value    = '\\fs01\users\testuserchanged'
                    }
                    @{
                        Property = 'HomeDrive'
                        Value    = 'I:'
                    }
                    @{
                        Property = 'HomePage'
                        Value    = 'www.contoso.com/users/testuserchanged'
                    }
                    @{
                        Property = 'ProfilePath'
                        Value    = 'changed profile path'
                    }
                    @{
                        Property = 'LogonScript'
                        Value    = 'logonscript-changed.ps1'
                    }
                    @{
                        Property = 'Notes'
                        Value    = 'This is a test user changed'
                    }
                    @{
                        Property = 'OfficePhone'
                        Value    = '+1 123456'
                    }
                    @{
                        Property = 'MobilePhone'
                        Value    = '+1 234567'
                    }
                    @{
                        Property = 'Fax'
                        Value    = '+1 345678'
                    }
                    @{
                        Property = 'Pager'
                        Value    = '+1 456789'
                    }
                    @{
                        Property = 'IPPhone'
                        Value    = '123456'
                    }
                    @{
                        Property = 'HomePhone'
                        Value    = '+1 567890'
                    }
                    @{
                        Property = 'Manager'
                        Value    = 'John Doe Changed'
                    }
                    @{
                        Property = 'LogonWorkstations'
                        Value    = 'PC03,PC04'
                    }
                    @{
                        Property = 'Organization'
                        Value    = 'Contoso Changed'
                    }
                    @{
                        Property = 'OtherName'
                        Value    = 'User1 Changed'
                    }
                    @{
                        Property = 'PasswordNeverExpires'
                        Value    = $true
                    }
                    @{
                        Property = 'CannotChangePassword'
                        Value    = $true
                    }
                    @{
                        Property = 'TrustedForDelegation'
                        Value    = $true
                    }
                    @{
                        Property = 'AccountNotDelegated'
                        Value    = $false
                    }
                    @{
                        Property = 'AllowReversiblePasswordEncryption'
                        Value    = $true
                    }
                    @{
                        Property = 'CompoundIdentitySupported'
                        Value    = $true
                    }
                    @{
                        Property = 'PasswordNotRequired'
                        Value    = $true
                    }
                    @{
                        Property = 'SmartcardLogonRequired'
                        Value    = $true
                    }
                    @{
                        Property = 'ProxyAddresses'
                        Value    = 'testuser3@fabrikam.com', 'testuser4@fabrikam.com'
                    }
                    @{
                        Property = 'AdminDescription'
                        Value    = 'User_ Changed'
                    }
                    @{
                        Property = 'PhoneticDisplayName'
                        Value    = 'Test User Phonetic Changed'
                    }
                    @{
                        Property = 'PreferredLanguage'
                        Value    = 'en-GB'
                    }
                    @{
                        Property = 'SimpleDisplayName'
                        Value    = 'Test User Simple Changed'
                    }
                )
            }

            Context 'When the <Property> parameter has changed' -ForEach $testCases {
                It 'Should call the correct mocks' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                        }

                        $mockParameters.$Property = $Value

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $UserName -eq 'TestUser'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADUser -ParameterFilter {
                        $Identity -eq 'TestUser'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }


                if ($Value -isnot [Boolean])
                {
                    if ($Value -isnot [Array])
                    {
                        Context 'When the <Property> parameter should be null' {
                            It 'Should call the correct mocks' {
                                InModuleScope -Parameters $_ -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName = 'contoso.com'
                                        UserName   = 'TestUser'
                                        Ensure     = 'Present'
                                    }

                                    $mockParameters.$Property = $null

                                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                                }

                                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Set-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                            }
                        }
                    }

                    Context 'When the <Property> parameter should be empty' {
                        It 'Should call the correct mocks' {
                            InModuleScope -Parameters $_ -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                }

                                $mockParameters.$Property = ''

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }
                }

                if ($Value -is [Array])
                {
                    Context 'When the <Property> parameter should be an empty array' {
                        It 'Should call the correct mocks' {
                            InModuleScope -Parameters $_ -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                }

                                $mockParameters.$Property = @()

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }
                }
            }

            Context 'When the ''Path'' property has changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                            Path       = 'OU=Changed,DC=contoso,DC=com'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Move-ADObject -ParameterFilter { $TargetPath -eq 'OU=Changed,DC=contoso,DC=com' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''CommonName'' property has changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                            CommonName = 'Test Common Name'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -ParameterFilter { $NewName -eq 'Test Common Name' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''DomainController'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName       = 'contoso.com'
                            UserName         = 'TestUser'
                            Ensure           = 'Present'
                            DomainController = 'TESTDC'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''Password'' parameter is specified' {
                Context 'When the specified Password has changed' {
                    BeforeAll {
                        Mock -CommandName Test-Password -MockWith { $false }
                    }

                    Context 'When the ''PasswordNeverResets'' parameter is False' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName          = 'contoso.com'
                                    UserName            = 'TestUser'
                                    Ensure              = 'Present'
                                    Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordNeverResets = $false
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADAccountPassword -ParameterFilter { $null -ne $NewPassword } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password
                            } -Exactly -Times 1 -Scope It

                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the ''PasswordNeverResets'' parameter is True' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName          = 'contoso.com'
                                    UserName            = 'TestUser'
                                    Ensure              = 'Present'
                                    Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordNeverResets = $true
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the ''Credential'' parameter is specified' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName = 'contoso.com'
                                    UserName   = 'TestUser'
                                    Ensure     = 'Present'
                                    Password   = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    Credential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $null -ne $Credential
                            } -Exactly -Times 1 -Scope It

                            Should -Invoke -CommandName Set-ADAccountPassword -ParameterFilter { $null -ne $NewPassword } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the ''PasswordAuthentication'' parameter is specified as ''Default''' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName             = 'contoso.com'
                                    UserName               = 'TestUser'
                                    Ensure                 = 'Present'
                                    Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordAuthentication = 'Default'
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $PasswordAuthentication -eq 'Default'
                            } -Exactly -Times 1 -Scope It

                            Should -Invoke -CommandName Set-ADAccountPassword -ParameterFilter { $null -ne $NewPassword } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the ''PasswordAuthentication'' parameter is specified as ''Negotiate''' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Negotiate'
                        }

                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    DomainName             = 'contoso.com'
                                    UserName               = 'TestUser'
                                    Ensure                 = 'Present'
                                    Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    PasswordAuthentication = 'Negotiate'
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Test-Password -ParameterFilter {
                                $UserName -eq 'TestUser' -and
                                $null -ne $Password -and
                                $PasswordAuthentication -eq 'Negotiate'
                            } -Exactly -Times 1 -Scope It

                            Should -Invoke -CommandName Set-ADAccountPassword -ParameterFilter { $null -ne $NewPassword } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        }
                    }

                    Context 'When the specified Password has not changed' {
                        BeforeAll {
                            Mock -CommandName Test-Password -MockWith { $true }
                        }

                        Context 'When the ''PasswordNeverResets'' parameter is False' {
                            It 'Should call the expected mocks' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName          = 'contoso.com'
                                        UserName            = 'TestUser'
                                        Ensure              = 'Present'
                                        Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                        PasswordNeverResets = $false
                                    }

                                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                                }

                                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Test-Password -ParameterFilter {
                                    $UserName -eq 'TestUser' -and
                                    $null -ne $Password
                                } -Exactly -Times 1 -Scope It

                                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                            }
                        }

                        Context 'When the ''PasswordNeverResets'' parameter is True' {
                            It 'Should call the expected mocks' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName          = 'contoso.com'
                                        UserName            = 'TestUser'
                                        Ensure              = 'Present'
                                        Password            = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                        PasswordNeverResets = $true
                                    }

                                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                                }

                                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                            }
                        }

                        Context 'When the ''Credential'' parameter are specified' {
                            It 'Should call the expected mocks' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName = 'contoso.com'
                                        UserName   = 'TestUser'
                                        Ensure     = 'Present'
                                        Password   = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                        Credential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                    }

                                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                                }

                                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Test-Password -ParameterFilter {
                                    $UserName -eq 'TestUser' -and
                                    $null -ne $Password -and
                                    $null -ne $Credential
                                } -Exactly -Times 1 -Scope It

                                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                            }
                        }

                        Context 'When the ''PasswordAuthentication'' parameter is specified as ''Default''' {
                            It 'Should call the expected mocks' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName             = 'contoso.com'
                                        UserName               = 'TestUser'
                                        Ensure                 = 'Present'
                                        Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                        PasswordAuthentication = 'Default'
                                    }

                                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                                }


                                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Test-Password -ParameterFilter {
                                    $UserName -eq 'TestUser' -and
                                    $null -ne $Password -and
                                    $PasswordAuthentication -eq 'Default'
                                } -Exactly -Times 1 -Scope It

                                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                            }
                        }

                        Context 'When the ''PasswordAuthentication'' parameter is specified as ''Negotiate''' {
                            It 'Should call the expected mocks' {
                                InModuleScope -ScriptBlock {
                                    Set-StrictMode -Version 1.0

                                    $mockParameters = @{
                                        DomainName             = 'contoso.com'
                                        UserName               = 'TestUser'
                                        Ensure                 = 'Present'
                                        Password               = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                                        PasswordAuthentication = 'Negotiate'
                                    }

                                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                                }

                                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                                Should -Invoke -CommandName Test-Password -ParameterFilter {
                                    $UserName -eq 'TestUser' -and
                                    $null -ne $Password -and
                                    $PasswordAuthentication -eq 'Negotiate'
                                } -Exactly -Times 1 -Scope It

                                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                            }
                        }
                    }
                }
            }

            Context 'When ''ChangePasswordAtLogon'' is true' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            DomainName                        = 'contoso.com'
                            UserName                          = 'TestUser'
                            Path                              = 'CN=Users,DC=contoso,DC=com'
                            DistinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                            DisplayName                       = 'Test User'
                            Initials                          = 'T'
                            Enabled                           = $true
                            GivenName                         = 'Test'
                            CommonName                        = 'TestUser'
                            Password                          = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                            Description                       = 'This is the test user'
                            Surname                           = 'User'
                            StreetAddress                     = '1 Highway Road'
                            POBox                             = 'PO Box 1'
                            City                              = 'Cityville'
                            State                             = 'State'
                            UserPrincipalName                 = 'testuser@contoso.com'
                            ServicePrincipalNames             = 'spn/a', 'spn/b'
                            ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                            ThumbnailPhotoHash                = 'D8719F18D789F449CBD14B5798BE79F7'
                            PostalCode                        = 'AA1 1AA'
                            Country                           = 'US'
                            Department                        = 'IT'
                            Division                          = 'Global'
                            Company                           = 'Contoso'
                            Office                            = 'Office 1'
                            JobTitle                          = 'Test'
                            EmailAddress                      = 'testuser@contoso.com'
                            EmployeeID                        = 'ID1'
                            EmployeeNumber                    = '1'
                            HomeDirectory                     = '\\fs01\users\testuser'
                            HomeDrive                         = 'H:'
                            HomePage                          = 'www.contoso.com/users/testuser'
                            ProfilePath                       = 'profilepath'
                            LogonScript                       = 'logonscript.ps1'
                            Notes                             = 'This is a test user'
                            OfficePhone                       = '+1 12345'
                            MobilePhone                       = '+1 23456'
                            Fax                               = '+1 34567'
                            Pager                             = '+1 45678'
                            IPPhone                           = '12345'
                            HomePhone                         = '+1 56789'
                            Manager                           = 'John Doe'
                            LogonWorkstations                 = 'PC01,PC02'
                            Organization                      = 'Contoso'
                            OtherName                         = 'User1'
                            PasswordNeverExpires              = $false
                            CannotChangePassword              = $false
                            ChangePasswordAtLogon             = $false
                            TrustedForDelegation              = $false
                            AccountNotDelegated               = $true
                            AllowReversiblePasswordEncryption = $false
                            CompoundIdentitySupported         = $false
                            PasswordNotRequired               = $false
                            SmartcardLogonRequired            = $false
                            ProxyAddresses                    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
                            AdminDescription                  = 'User_'
                            PhoneticDisplayName               = 'Test User Phonetic'
                            PreferredLanguage                 = 'en-US'
                            SimpleDisplayName                 = 'Test User Simple'
                            Ensure                            = 'Present'
                        }
                    }
                }

                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName            = 'contoso.com'
                            UserName              = 'TestUser'
                            Ensure                = 'Present'
                            ChangePasswordAtLogon = $true
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the resource should be absent' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                        Ensure     = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-ADUser -ParameterFilter { $Identity -eq 'TestUser' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the resource is absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    DomainName                        = 'contoso.com'
                    UserName                          = 'TestUser'
                    Path                              = 'CN=Users,DC=contoso,DC=com'
                    DistinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                    DisplayName                       = 'Test User'
                    Initials                          = 'T'
                    Enabled                           = $true
                    GivenName                         = 'Test'
                    CommonName                        = 'TestUser'
                    Password                          = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                    Description                       = 'This is the test user'
                    Surname                           = 'User'
                    StreetAddress                     = '1 Highway Road'
                    POBox                             = 'PO Box 1'
                    City                              = 'Cityville'
                    State                             = 'State'
                    UserPrincipalName                 = 'testuser@contoso.com'
                    ServicePrincipalNames             = 'spn/a', 'spn/b'
                    ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                    ThumbnailPhotoHash                = 'D8719F18D789F449CBD14B5798BE79F7'
                    PostalCode                        = 'AA1 1AA'
                    Country                           = 'US'
                    Department                        = 'IT'
                    Division                          = 'Global'
                    Company                           = 'Contoso'
                    Office                            = 'Office 1'
                    JobTitle                          = 'Test'
                    EmailAddress                      = 'testuser@contoso.com'
                    EmployeeID                        = 'ID1'
                    EmployeeNumber                    = '1'
                    HomeDirectory                     = '\\fs01\users\testuser'
                    HomeDrive                         = 'H:'
                    HomePage                          = 'www.contoso.com/users/testuser'
                    ProfilePath                       = 'profilepath'
                    LogonScript                       = 'logonscript.ps1'
                    Notes                             = 'This is a test user'
                    OfficePhone                       = '+1 12345'
                    MobilePhone                       = '+1 23456'
                    Fax                               = '+1 34567'
                    Pager                             = '+1 45678'
                    IPPhone                           = '12345'
                    HomePhone                         = '+1 56789'
                    Manager                           = 'John Doe'
                    LogonWorkstations                 = 'PC01,PC02'
                    Organization                      = 'Contoso'
                    OtherName                         = 'User1'
                    PasswordNeverExpires              = $false
                    CannotChangePassword              = $false
                    ChangePasswordAtLogon             = $true
                    TrustedForDelegation              = $false
                    AccountNotDelegated               = $true
                    AllowReversiblePasswordEncryption = $false
                    CompoundIdentitySupported         = $false
                    PasswordNotRequired               = $false
                    SmartcardLogonRequired            = $false
                    ProxyAddresses                    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
                    AdminDescription                  = 'User_'
                    PhoneticDisplayName               = 'Test User Phonetic'
                    PreferredLanguage                 = 'en-US'
                    SimpleDisplayName                 = 'Test User Simple'
                    Ensure                            = 'Absent'
                }
            }
        }

        Context 'When the resource should be present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'DisplayName'
                        Value    = 'Test User Changed'
                    }
                    @{
                        Property = 'Initials'
                        Value    = 'S'
                    }
                    @{
                        Property = 'Enabled'
                        Value    = $false
                    }
                    @{
                        Property = 'GivenName'
                        Value    = 'Test Changed'
                    }
                    @{
                        Property = 'Description'
                        Value    = 'This is the test user changed'
                    }
                    @{
                        Property = 'Surname'
                        Value    = 'User Changed'
                    }
                    @{
                        Property = 'StreetAddress'
                        Value    = '1 Highway Road Changed'
                    }
                    @{
                        Property = 'POBox'
                        Value    = 'PO Box 1 Changed'
                    }
                    @{
                        Property = 'City'
                        Value    = 'Cityville Changed'
                    }
                    @{
                        Property = 'State'
                        Value    = 'State Changed'
                    }
                    @{
                        Property = 'ServicePrincipalNames'
                        Value    = 'spn/c', 'spn/d'
                    }
                    @{
                        Property = 'ThumbnailPhoto'
                        Value    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhq'
                    }
                    @{
                        Property = 'PostalCode'
                        Value    = 'AA1 1AA Changed'
                    }
                    @{
                        Property = 'Country'
                        Value    = 'GB'
                    }
                    @{
                        Property = 'Department'
                        Value    = 'IT Changed'
                    }
                    @{
                        Property = 'Division'
                        Value    = 'Global Changed'
                    }
                    @{
                        Property = 'Company'
                        Value    = 'Contoso Changed'
                    }
                    @{
                        Property = 'Office'
                        Value    = 'Office 1 Changed'
                    }
                    @{
                        Property = 'JobTitle'
                        Value    = 'Test Changed'
                    }
                    @{
                        Property = 'EmailAddress'
                        Value    = 'testuserchanged@contoso.com'
                    }
                    @{
                        Property = 'EmployeeID'
                        Value    = 'ID1 Changed'
                    }
                    @{
                        Property = 'EmployeeNumber'
                        Value    = '2'
                    }
                    @{
                        Property = 'HomeDirectory'
                        Value    = '\\fs01\users\testuserchanged'
                    }
                    @{
                        Property = 'HomeDrive'
                        Value    = 'I:'
                    }
                    @{
                        Property = 'HomePage'
                        Value    = 'www.contoso.com/users/testuserchanged'
                    }
                    @{
                        Property = 'ProfilePath'
                        Value    = 'changed profile path'
                    }
                    @{
                        Property = 'LogonScript'
                        Value    = 'logonscript-changed.ps1'
                    }
                    @{
                        Property = 'Notes'
                        Value    = 'This is a test user changed'
                    }
                    @{
                        Property = 'OfficePhone'
                        Value    = '+1 123456'
                    }
                    @{
                        Property = 'MobilePhone'
                        Value    = '+1 234567'
                    }
                    @{
                        Property = 'Fax'
                        Value    = '+1 345678'
                    }
                    @{
                        Property = 'Pager'
                        Value    = '+1 456789'
                    }
                    @{
                        Property = 'IPPhone'
                        Value    = '123456'
                    }
                    @{
                        Property = 'HomePhone'
                        Value    = '+1 567890'
                    }
                    @{
                        Property = 'Manager'
                        Value    = 'John Doe Changed'
                    }
                    @{
                        Property = 'LogonWorkstations'
                        Value    = 'PC03,PC04'
                    }
                    @{
                        Property = 'Organization'
                        Value    = 'Contoso Changed'
                    }
                    @{
                        Property = 'OtherName'
                        Value    = 'User1 Changed'
                    }
                    @{
                        Property = 'PasswordNeverExpires'
                        Value    = $true
                    }
                    @{
                        Property = 'CannotChangePassword'
                        Value    = $true
                    }
                    @{
                        Property = 'TrustedForDelegation'
                        Value    = $true
                    }
                    @{
                        Property = 'AccountNotDelegated'
                        Value    = $false
                    }
                    @{
                        Property = 'AllowReversiblePasswordEncryption'
                        Value    = $true
                    }
                    @{
                        Property = 'CompoundIdentitySupported'
                        Value    = $true
                    }
                    @{
                        Property = 'PasswordNotRequired'
                        Value    = $true
                    }
                    @{
                        Property = 'SmartcardLogonRequired'
                        Value    = $true
                    }
                    @{
                        Property = 'ProxyAddresses'
                        Value    = 'testuser3@fabrikam.com', 'testuser4@fabrikam.com'
                    }
                    @{
                        Property = 'AdminDescription'
                        Value    = 'User_ Changed'
                    }
                    @{
                        Property = 'PhoneticDisplayName'
                        Value    = 'Test User Phonetic Changed'
                    }
                    @{
                        Property = 'PreferredLanguage'
                        Value    = 'en-GB'
                    }
                    @{
                        Property = 'SimpleDisplayName'
                        Value    = 'Test User Simple Changed'
                    }
                )
            }

            Context 'When the <Property> parameter is specified' -ForEach $testCases {
                It 'Should call the correct mocks' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                        }

                        $mockParameters.$Property = $Value

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADUser -ParameterFilter { $Name -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the CommonName does not match the UserName' {
                BeforeAll {
                    Mock -CommandName New-ADUser -MockWith {
                        @{
                            DistinguishedName = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
                        }
                    }
                }

                It 'Should call the correct mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                            CommonName = 'Common Changed'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADUser -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -ParameterFilter { $NewName -eq 'Common Changed' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''Password'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            DomainName = 'contoso.com'
                            UserName   = 'TestUser'
                            Ensure     = 'Present'
                            Password   = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADUser -ParameterFilter { $null -ne $AccountPassword } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''RestoreFromRecycleBin'' parameter is specified' {
                Context 'When the user is found in the recycle bin' {
                    BeforeAll {
                        Mock -CommandName Restore-ADCommonObject -MockWith {
                            @{ ObjectClass = 'user' }
                        }
                    }

                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                DomainName            = 'contoso.com'
                                UserName              = 'TestUser'
                                Ensure                = 'Present'
                                RestoreFromRecycleBin = $true
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When the user is not found in the recycle bin' {
                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                DomainName            = 'contoso.com'
                                UserName              = 'TestUser'
                                Ensure                = 'Present'
                                RestoreFromRecycleBin = $true
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName New-ADUser -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When the user cannot be restored from the recycle bin' {
                    BeforeAll {
                        Mock -CommandName Restore-ADCommonObject -MockWith { throw }
                    }

                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                DomainName            = 'contoso.com'
                                UserName              = 'TestUser'
                                Ensure                = 'Present'
                                RestoreFromRecycleBin = $true
                            }

                            { Set-TargetResource @mockParameters } | Should -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                    }
                }
            }
        }

        Context 'When the resource should be absent' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        DomainName = 'contoso.com'
                        UserName   = 'TestUser'
                        Ensure     = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $UserName -eq 'TestUser' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADUser -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADUser -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADUser -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Test-Password -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADAccountPassword -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Rename-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADUser\Assert-Parameters' -Tag 'Helper' {
    Context 'When both parameters PasswordNeverExpires and CannotChangePassword are specified' {
        It 'Should not throw ' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    PasswordNeverExpires = $true
                    CannotChangePassword = $true
                }

                { Assert-Parameters @mockParameters } | Should -Not -Throw
            }
        }
    }

    Context 'When the parameter Enabled is set to $false and the parameter Password is also specified' {
        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Password = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
                    Enabled  = $false
                }

                $errorRecord = Get-InvalidArgumentRecord -Message ($script:localizedData.PasswordParameterConflictError -f
                    'Enabled', $false, 'Password') -ArgumentName 'Password'

                { Assert-Parameters @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
            }
        }
    }

    Context 'When the parameter TrustedForDelegation is specified' {
        It 'Should not throw' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    TrustedForDelegation = $true
                }

                { Assert-Parameters @mockParameters } | Should -Not -Throw
            }
        }
    }

    Context 'When both parameters PasswordNeverExpires and ChangePasswordAtLogon are specified' {
        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    PasswordNeverExpires  = $true
                    ChangePasswordAtLogon = $true
                }

                $errorRecord = Get-InvalidArgumentRecord -Message $script:localizedData.ChangePasswordParameterConflictError -ArgumentName 'ChangePasswordAtLogon, PasswordNeverExpires'

                { Assert-Parameters @mockParameters } |
                    Should -Throw -ExpectedMessage $errorRecord.Message
            }
        }
    }
}

Describe 'MSFT_ADUser\Get-MD5HashString' -Tag 'Helper' {
    It 'Should return the correct hash' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $mockParameters = @{
                Bytes = [System.Byte[]] (
                    255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                )
            }

            Get-MD5HashString @mockParameters | Should -Be 'D8719F18D789F449CBD14B5798BE79F7'
        }
    }
}

Describe 'MSFT_ADUser\Get-ThumbnailByteArray' -Tag 'Helper' {
    Context 'When providing a Base64-encoded string' {
        It 'Should return the correct byte array' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockThumbnailBytes = [System.Byte[]] (
                    255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                )

                $mockParameters = @{
                    ThumbnailPhoto = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                }

                Get-ThumbnailByteArray @mockParameters | Should -Be $mockThumbnailBytes
            }
        }
    }

    Context 'When providing a file path to a jpeg image' {
        It 'Should return the correct byte array' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockThumbnailPhotoPath = Join-Path $PSScriptRoot -ChildPath '..\TestHelpers\DSC_Logo_96.jpg'

                $mockThumbnailBytes = [System.Byte[]] (
                    255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
                )

                $(Get-ThumbnailByteArray -ThumbnailPhoto $mockThumbnailPhotoPath)[0..($mockThumbnailBytes.Count - 1)] |
                    Should -Be $mockThumbnailBytes
            }
        }
    }

    Context 'When providing the wrong file path to a jpeg image' {
        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    ThumbnailPhoto = (Join-Path $TestDrive -ChildPath 'WrongFile.jpg')
                }

                $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.ThumbnailPhotoNotAFile

                { Get-ThumbnailByteArray @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
            }
        }
    }
}

Describe 'MSFT_ADUser\Compare-ThumbnailPhoto' -Tag 'Helper' {
    Context 'When current and desired thumbnail photo are the same' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $compareThumbnailPhotoParameters = @{
                    DesiredThumbnailPhoto     = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                    CurrentThumbnailPhotoHash = 'D8719F18D789F449CBD14B5798BE79F7'
                }

                Compare-ThumbnailPhoto @compareThumbnailPhotoParameters | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When there is no current thumbnail photo, and there should be no thumbnail photo' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $compareThumbnailPhotoParameters = @{
                    DesiredThumbnailPhoto     = ''
                    CurrentThumbnailPhotoHash = $null
                }

                Compare-ThumbnailPhoto @compareThumbnailPhotoParameters | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When the current thumbnail photo is not the desired thumbnail photo' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $compareThumbnailPhotoParameters = @{
                    DesiredThumbnailPhoto     = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhq'
                    CurrentThumbnailPhotoHash = 'D8719F18D789F449CBD14B5798BE79F7'
                }

                $compareThumbnailPhotoResult = Compare-ThumbnailPhoto @compareThumbnailPhotoParameters

                $compareThumbnailPhotoResult | Should -BeOfType [System.Collections.Hashtable]
                $compareThumbnailPhotoResult.CurrentThumbnailPhotoHash | Should -Be 'D8719F18D789F449CBD14B5798BE79F7'
                $compareThumbnailPhotoResult.DesiredThumbnailPhotoHash | Should -Be '473CA6636A51A3B2953FD5A7D859020F'
            }
        }
    }

    Context 'When there is no current thumbnail photo, but there should be a thumbnail photo' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $compareThumbnailPhotoParameters = @{
                    DesiredThumbnailPhoto     = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
                    CurrentThumbnailPhotoHash = $null
                }

                $compareThumbnailPhotoResult = Compare-ThumbnailPhoto @compareThumbnailPhotoParameters
                $compareThumbnailPhotoResult | Should -BeOfType [System.Collections.Hashtable]
                $compareThumbnailPhotoResult.CurrentThumbnailPhotoHash | Should -BeNullOrEmpty
                $compareThumbnailPhotoResult.DesiredThumbnailPhotoHash | Should -Be 'D8719F18D789F449CBD14B5798BE79F7'
            }
        }
    }

    Context 'When there is a current thumbnail photo, but there should be no thumbnail photo' {
        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $compareThumbnailPhotoParameters = @{
                    DesiredThumbnailPhoto     = ''
                    CurrentThumbnailPhotoHash = 'D8719F18D789F449CBD14B5798BE79F7'
                }

                $compareThumbnailPhotoResult = Compare-ThumbnailPhoto @compareThumbnailPhotoParameters

                $compareThumbnailPhotoResult | Should -BeOfType [System.Collections.Hashtable]
                $compareThumbnailPhotoResult.CurrentThumbnailPhotoHash | Should -Be 'D8719F18D789F449CBD14B5798BE79F7'
                $compareThumbnailPhotoResult.DesiredThumbnailPhotoHash | Should -BeNullOrEmpty
            }
        }
    }
}
