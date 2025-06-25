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

# $testDomainController = 'TESTDC'
# $testPassword = ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force
# $testCredential = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
# $testChangedPassword = ConvertTo-SecureString -String 'P@ssW0rd2' -AsPlainText -Force
# $testChangedCredential = [System.Management.Automation.PSCredential]::new('user', $testChangedPassword)
# $mockThumbnailPhotoHash = 'D8719F18D789F449CBD14B5798BE79F7'
# $mockThumbnailPhotoBase64 = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
# $mockThumbnailPhotoByteArray = [System.Byte[]] (
#     255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
# )
# $mockChangedThumbnailPhotoHash = '473CA6636A51A3B2953FD5A7D859020F'
# $mockChangedThumbnailPhotoBase64 = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhq'

# $mockPath = 'CN=Users,DC=contoso,DC=com'
# $UserName = 'TestUser'

# $mockResource = @{
#     DomainName                        = 'contoso.com'
#     UserName                          = 'TestUser'
#     Path                              = 'CN=Users,DC=contoso,DC=com'
#     DistinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
#     DisplayName                       = 'Test User'
#     Initials                          = 'T'
#     Enabled                           = $true
#     GivenName                         = 'Test'
#     CommonName                        = 'TestUser'
#     Password                          = [System.Management.Automation.PSCredential]::new('user', $(ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force))
#     Description                       = 'This is the test user'
#     Surname                           = 'User'
#     StreetAddress                     = '1 Highway Road'
#     POBox                             = 'PO Box 1'
#     City                              = 'Cityville'
#     State                             = 'State'
#     UserPrincipalName                 = 'testuser@contoso.com'
#     ServicePrincipalNames             = 'spn/a', 'spn/b'
#     ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhp'
#     ThumbnailPhotoHash                = 'D8719F18D789F449CBD14B5798BE79F7'
#     PostalCode                        = 'AA1 1AA'
#     Country                           = 'US'
#     Department                        = 'IT'
#     Division                          = 'Global'
#     Company                           = 'Contoso'
#     Office                            = 'Office 1'
#     JobTitle                          = 'Test'
#     EmailAddress                      = 'testuser@contoso.com'
#     EmployeeID                        = 'ID1'
#     EmployeeNumber                    = '1'
#     HomeDirectory                     = '\\fs01\users\testuser'
#     HomeDrive                         = 'H:'
#     HomePage                          = 'www.contoso.com/users/testuser'
#     ProfilePath                       = 'profilepath'
#     LogonScript                       = 'logonscript.ps1'
#     Notes                             = 'This is a test user'
#     OfficePhone                       = '+1 12345'
#     MobilePhone                       = '+1 23456'
#     Fax                               = '+1 34567'
#     Pager                             = '+1 45678'
#     IPPhone                           = '12345'
#     HomePhone                         = '+1 56789'
#     Manager                           = 'John Doe'
#     LogonWorkstations                 = 'PC01,PC02'
#     Organization                      = 'Contoso'
#     OtherName                         = 'User1'
#     PasswordNeverExpires              = $false
#     CannotChangePassword              = $false
#     ChangePasswordAtLogon             = $true
#     TrustedForDelegation              = $false
#     AccountNotDelegated               = $true
#     AllowReversiblePasswordEncryption = $false
#     CompoundIdentitySupported         = $false
#     PasswordNotRequired               = $false
#     SmartcardLogonRequired            = $false
#     ProxyAddresses                    = 'testuser1@fabrikam.com', 'testuser2@fabrikam.com'
#     AdminDescription                  = 'User_'
#     PhoneticDisplayName               = 'Test User Phonetic'
#     PreferredLanguage                 = 'en-US'
#     SimpleDisplayName                 = 'Test User Simple'
#     Ensure                            = 'Present'
# }

# $mockAbsentResource = @{
# DomainName                        = 'contoso.com'
# UserName                          = 'TestUser'
# Path                              = $null
# DistinguishedName                 = $null
# DisplayName                       = $null
# Initials                          = $null
# Enabled                           = $null
# GivenName                         = $null
# CommonName                        = $null
# Password                          = $null
# Description                       = $null
# Surname                           = $null
# StreetAddress                     = $null
# POBox                             = $null
# City                              = $null
# State                             = $null
# UserPrincipalName                 = $null
# ServicePrincipalNames             = $null
# ThumbnailPhoto                    = $null
# ThumbnailPhotoHash                = $null
# PostalCode                        = $null
# Country                           = $null
# Department                        = $null
# Division                          = $null
# Company                           = $null
# Office                            = $null
# JobTitle                          = $null
# EmailAddress                      = $null
# EmployeeID                        = $null
# EmployeeNumber                    = $null
# HomeDirectory                     = $null
# HomeDrive                         = $null
# HomePage                          = $null
# ProfilePath                       = $null
# LogonScript                       = $null
# Notes                             = $null
# OfficePhone                       = $null
# MobilePhone                       = $null
# Fax                               = $null
# Pager                             = $null
# IPPhone                           = $null
# HomePhone                         = $null
# Manager                           = $null
# LogonWorkstations                 = $null
# Organization                      = $null
# OtherName                         = $null
# PasswordNeverExpires              = $null
# CannotChangePassword              = $null
# ChangePasswordAtLogon             = $null
# TrustedForDelegation              = $null
# AccountNotDelegated               = $null
# AllowReversiblePasswordEncryption = $null
# CompoundIdentitySupported         = $null
# PasswordNotRequired               = $null
# SmartcardLogonRequired            = $null
# ProxyAddresses                    = $null
# AdminDescription                  = $null
# PhoneticDisplayName               = $null
# PreferredLanguage                 = $null
# SimpleDisplayName                 = $null
# Ensure                            = 'Absent'
# }

# $mockChangedResource = @{
#     Path                              = 'OU=Staff,DC=contoso,DC=com'
#     DisplayName                       = 'Test User Changed'
#     Initials                          = 'S'
#     Enabled                           = $false
#     GivenName                         = 'Test Changed'
#     CommonName                        = 'Common Changed'
#     Description                       = 'This is the test user changed'
#     Surname                           = 'User Changed'
#     StreetAddress                     = '1 Highway Road Changed'
#     POBox                             = 'PO Box 1 Changed'
#     City                              = 'Cityville Changed'
#     State                             = 'State Changed'
#     ServicePrincipalNames             = 'spn/c', 'spn/d'
#     ThumbnailPhoto                    = '/9j/4AAQSkZJRgABAQEAYABgAAD/4QBmRXhq'
#     PostalCode                        = 'AA1 1AA Changed'
#     Country                           = 'GB'
#     Department                        = 'IT Changed'
#     Division                          = 'Global Changed'
#     Company                           = 'Contoso Changed'
#     Office                            = 'Office 1 Changed'
#     JobTitle                          = 'Test Changed'
#     EmailAddress                      = 'testuserchanged@contoso.com'
#     EmployeeID                        = 'ID1 Changed'
#     EmployeeNumber                    = '2'
#     HomeDirectory                     = '\\fs01\users\testuserchanged'
#     HomeDrive                         = 'I:'
#     HomePage                          = 'www.contoso.com/users/testuserchanged'
#     ProfilePath                       = 'changed profile path'
#     LogonScript                       = 'logonscript-changed.ps1'
#     Notes                             = 'This is a test user changed'
#     OfficePhone                       = '+1 123456'
#     MobilePhone                       = '+1 234567'
#     Fax                               = '+1 345678'
#     Pager                             = '+1 456789'
#     IPPhone                           = '123456'
#     HomePhone                         = '+1 567890'
#     Manager                           = 'John Doe Changed'
#     LogonWorkstations                 = 'PC03,PC04'
#     Organization                      = 'Contoso Changed'
#     OtherName                         = 'User1 Changed'
#     PasswordNeverExpires              = $true
#     CannotChangePassword              = $true
#     ChangePasswordAtLogon             = $false
#     TrustedForDelegation              = $true
#     AccountNotDelegated               = $false
#     AllowReversiblePasswordEncryption = $true
#     CompoundIdentitySupported         = $true
#     PasswordNotRequired               = $true
#     SmartcardLogonRequired            = $true
#     ProxyAddresses                    = 'testuser3@fabrikam.com', 'testuser4@fabrikam.com'
#     AdminDescription                  = 'User_ Changed'
#     PhoneticDisplayName               = 'Test User Phonetic Changed'
#     PreferredLanguage                 = 'en-GB'
#     SimpleDisplayName                 = 'Test User Simple Changed'
# }

# $mockGetADUserResult = @{
#     samAccountName                    = 'TestUser'
#     cn                                = 'TestUser'
#     UserPrincipalName                 = 'testuser@contoso.com'
#     DisplayName                       = 'Test User'
#     distinguishedName                 = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
#     GivenName                         = 'Test'
#     Initials                          = 'T'
#     sn                                = 'User'
#     Description                       = 'This is the test user'
#     StreetAddress                     = '1 Highway Road'
#     PostOfficeBox                     = 'PO Box 1'
#     l                                 = 'Cityville'
#     St                                = 'State'
#     PostalCode                        = 'AA1 1AA'
#     c                                 = 'US'
#     Department                        = 'IT'
#     Division                          = 'Global'
#     Company                           = 'Contoso'
#     physicalDeliveryOfficeName        = 'Office 1'
#     title                             = 'Test'
#     mail                              = 'testuser@contoso.com'
#     EmployeeID                        = 'ID1'
#     EmployeeNumber                    = '1'
#     HomeDirectory                     = '\\fs01\users\testuser'
#     HomeDrive                         = 'H:'
#     wWWHomePage                       = 'www.contoso.com/users/testuser'
#     ProfilePath                       = 'profilepath'
#     scriptPath                        = 'logonscript.ps1'
#     info                              = 'This is a test user'
#     telephoneNumber                   = '+1 12345'
#     mobile                            = '+1 23456'
#     facsimileTelephoneNumber          = '+1 34567'
#     Pager                             = '+1 45678'
#     IPPhone                           = '12345'
#     HomePhone                         = '+1 56789'
#     Enabled                           = $true
#     Manager                           = 'John Doe'
#     userWorkstations                  = 'PC01,PC02'
#     O                                 = 'Contoso'
#     middleName                        = 'User1'
#     ThumbnailPhoto                    = [System.Byte[]] (
#         255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 1, 0, 96, 0, 96, 0, 0, 255, 225, 0, 102, 69, 120, 105
#     )
#     PasswordNeverExpires              = $false
#     CannotChangePassword              = $false
#     pwdLastSet                        = 0
#     TrustedForDelegation              = $false
#     AccountNotDelegated               = $true
#     AllowReversiblePasswordEncryption = $false
#     CompoundIdentitySupported         = $false
#     PasswordNotRequired               = $false
#     SmartcardLogonRequired            = $false
#     ServicePrincipalName              = @('spn/a', 'spn/b')
#     ProxyAddresses                    = @('testuser1@fabrikam.com', 'testuser2@fabrikam.com')
#     AdminDescription                  = 'User_'
#     'msDS-PhoneticDisplayName'        = 'Test User Phonetic'
#     PreferredLanguage                 = 'en-US'
#     displayNamePrintable              = 'Test User Simple'
# }

# $mockGetTargetResourceResult = $mockResource.Clone()

# $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
# $mockGetTargetResourcePresentResult.Ensure = 'Present'

# $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
# $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

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


        Context 'When the "ChangePassswordAtLogon" parameter is false' {
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

        Context 'When the "ThumbnailPhoto" parameter is empty' {
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

    Context 'When the "DomainController" parameter is specified' {
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

    Context 'When the "Credential" parameter is specified' {
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

Describe 'MSFT_ADUser\Test-TargetResource' -Tag 'Test' -Skip:$true {
    BeforeAll {
        $testTargetResourceParams = @{
            DomainName = $mockResource.DomainName
            UserName   = $mockResource.UserName
        }

        $testTargetResourcePresentParams = $testTargetResourceParams.Clone()
        $testTargetResourcePresentParams.Ensure = 'Present'

        $testTargetResourceAbsentParams = $testTargetResourceParams.Clone()
        $testTargetResourceAbsentParams.Ensure = 'Absent'
    }

    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
            Mock -CommandName Test-Password
        }

        Context 'When the Resource should be Present' {
            It 'Should not throw' {
                { Test-TargetResource @testTargetResourcePresentParams } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Should -Invoke -CommandName Get-TargetResource `
                    -ParameterFilter { $UserName -eq $testTargetResourcePresentParams.UserName } `
                    -Exactly -Times 1
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When the '$property' property is not in the desired state" {
                    BeforeAll {
                        $testTargetResourceNotInDesiredStateParams = $testTargetResourcePresentParams.Clone()
                        $testTargetResourceNotInDesiredStateParams.$property = $mockChangedResource.$property
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceNotInDesiredStateParams | Should -Be $false
                    }
                }

                if ($mockChangedResource.$property -isnot [Boolean])
                {
                    if ($mockChangedResource.$property -isnot [Array])
                    {
                        Context "When the '$property' parameter should be null" {
                            BeforeAll {
                                $testTargetResourceNullParams = $testTargetResourcePresentParams.Clone()
                                $testTargetResourceNullParams.$property = $null
                            }

                            It 'Should return $false' {
                                Test-TargetResource @testTargetResourceNullParams | Should -Be $false
                            }
                        }
                    }

                    Context "When the '$property' parameter should be empty" {
                        BeforeAll {
                            $testTargetResourceEmptyParams = $testTargetResourcePresentParams.Clone()
                            $testTargetResourceEmptyParams.$property = ''
                        }

                        It 'Should return $false' {
                            Test-TargetResource @testTargetResourceEmptyParams | Should -Be $false
                        }
                    }
                }

                if ($mockChangedResource.$property -is [Array])
                {
                    Context "When the '$property' parameter should be an empty array" {
                        BeforeAll {
                            $testTargetResourceEmptyArrayParams = $testTargetResourcePresentParams.Clone()
                            $testTargetResourceEmptyArrayParams.$property = @()
                        }

                        It 'Should return $false' {
                            Test-TargetResource @testTargetResourceEmptyArrayParams | Should -Be $false
                        }
                    }
                }
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return the desired result' {
                    Test-TargetResource @testTargetResourcePresentParams | Should -Be $true
                }
            }

            Context 'When the "DomainController" parameter is specified' {
                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourcePresentParams `
                            -DomainController 'TESTDC' } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { $DomainController -eq 'TESTDC' } `
                        -Exactly -Times 1
                }
            }

            Context 'When the "Credential" parameter is specified' {
                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourcePresentParams `
                            -Credential $testCredential } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { $Credential -eq $testCredential } `
                        -Exactly -Times 1
                }
            }

            Context 'When the "Password" parameter is specified' {
                Context 'When the specified Password has changed' {
                    BeforeAll {
                        Mock -CommandName Test-Password -MockWith { $false }
                    }

                    Context 'When the "PasswordNeverResets" parameter is False' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordNeverResets $false | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "PasswordNeverResets" parameter is True' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordNeverResets $true | Should -BeTrue
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the "Credential" parameter is specified' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Credential $testCredential `
                                -Password $testCredential | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $Credential -eq $testCredential } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "PasswordAuthentication" parameter is specified as "Default"' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Default'
                        }

                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordAuthentication $testPasswordAuthentication | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $PasswordAuthentication -eq $testPasswordAuthentication } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "PasswordAuthentication" parameter is specified as "Negotiate"' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Negotiate'
                        }

                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordAuthentication $testPasswordAuthentication | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $PasswordAuthentication -eq $testPasswordAuthentication } `
                                -Exactly -Times 1
                        }
                    }
                }

                Context 'When the specified Password has not changed' {
                    BeforeAll {
                        Mock -CommandName Test-Password -MockWith { $true }
                    }

                    Context 'When the "PasswordNeverResets" parameter is False' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordNeverResets $false | Should -BeTrue
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "PasswordNeverResets" parameter is True' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordNeverResets $true | Should -BeTrue
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the "Credential" parameter is specified' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Credential $testCredential `
                                -Password $testCredential | Should -BeTrue
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $Credential -eq $testCredential } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "PasswordAuthentication" parameter is specified as "Default"' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Default'
                        }

                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordAuthentication $testPasswordAuthentication | Should -BeTrue
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $PasswordAuthentication -eq $testPasswordAuthentication } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the "PasswordAuthentication" parameter is specified as "Negotiate"' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Negotiate'
                        }

                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParams `
                                -Password $testCredential `
                                -PasswordAuthentication $testPasswordAuthentication | Should -BeTrue
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $testTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $PasswordAuthentication -eq $testPasswordAuthentication } `
                                -Exactly -Times 1
                        }
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return the desired result' {
                Test-TargetResource @testTargetResourceAbsentParams | Should -BeFalse
            }

            It 'Should call the expected mocks' {
                Should -Invoke -CommandName Get-TargetResource `
                    -ParameterFilter { $UserName -eq $testTargetResourceAbsentParams.UserName } `
                    -Exactly -Times 1
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith { $testTargetResourceAbsentParams }
        }

        Context 'When the Resource should be Present' {
            It 'Should return the desired result' {
                Test-TargetResource @testTargetResourcePresentParams | Should -BeFalse
            }

            It 'Should call the expected mocks' {
                Should -Invoke -CommandName Get-TargetResource `
                    -ParameterFilter { $UserName -eq $testTargetResourceAbsentParams.UserName } `
                    -Exactly -Times 1
            }

            Context 'When ChangePasswordAtLogon is true and does not match the AD Account property' {
                BeforeAll {
                    $mockGetTargetResourceAbsentPasswordTrueResult = `
                        $mockGetTargetResourceAbsentResult.Clone()
                    $mockGetTargetResourceAbsentPasswordTrueResult['ChangePasswordAtLogon'] = $false

                    Mock -CommandName Get-TargetResource `
                        -MockWith { $mockGetTargetResourceAbsentPasswordTrueResult }
                }

                It 'Should return the desired result' {
                    Test-TargetResource @testTargetResourcePresentParams -ChangePasswordAtLogon $true |
                        Should -BeFalse
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return the desired result' {
                Test-TargetResource @testTargetResourceAbsentParams | Should -BeTrue
            }

            It 'Should call the expected mocks' {
                Should -Invoke -CommandName Get-TargetResource `
                    -ParameterFilter { $UserName -eq $testTargetResourceAbsentParams.UserName } `
                    -Exactly -Times 1
            }
        }
    }
}

Describe 'MSFT_ADUser\Set-TargetResource' -Tag 'Set' -Skip:$true {
    BeforeAll {
        $setTargetResourceParams = @{
            DomainName = $mockResource.DomainName
            UserName   = $mockResource.UserName
        }

        $setTargetResourcePresentParams = $setTargetResourceParams.Clone()
        $setTargetResourcePresentParams['Ensure'] = 'Present'

        $setTargetResourceAbsentParams = $setTargetResourceParams.Clone()
        $setTargetResourceAbsentParams['Ensure'] = 'Absent'

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
            $mockChangedSetResource = $mockChangedResource.Clone()
            $mockChangedSetResource.Remove('Path')
            $mockChangedSetResource.Remove('CommonName')
            $mockChangedSetResource.Remove('ChangePasswordAtLogon')

            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
        }

        Context 'When the resource should be present' {
            foreach ($property in $mockChangedSetResource.Keys)
            {
                Context "When the '$property' parameter has changed" {
                    BeforeAll {
                        $setTargetResourceParamsChangedProperty = $setTargetResourcePresentParams.Clone()
                        $setTargetResourceParamsChangedProperty.$property = $mockChangedSetResource.$property
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParamsChangedProperty } |
                            Should -Not -Throw
                    }

                    It 'Should call the correct mocks' {
                        Should -Invoke -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourceParamsChangedProperty.Name } `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Set-ADUser `
                            -ParameterFilter { $TargetName -eq $setTargetResourceParamsChangedProperty.Name } `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Move-ADObject `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Rename-ADObject `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Set-ADAccountPassword `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Test-Password `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Remove-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName New-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Restore-ADCommonObject `
                            -Exactly -Times 0
                    }
                }

                if ($mockChangedSetResource.$property -isnot [Boolean])
                {
                    if ($mockChangedSetResource.$property -isnot [Array])
                    {
                        Context "When the '$property' parameter should be null" {
                            BeforeAll {
                                $setTargetResourceNullParams = $setTargetResourcePresentParams.Clone()
                                $setTargetResourceNullParams.$property = $null
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourceNullParams } | Should -Not -Throw
                            }

                            It 'Should call the correct mocks' {
                                Should -Invoke -CommandName Get-TargetResource `
                                    -ParameterFilter { `
                                        $Name -eq $setTargetResourceParamsChangedProperty.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Set-ADUser `
                                    -ParameterFilter { `
                                        $TargetName -eq $setTargetResourceParamsChangedProperty.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Move-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Rename-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Set-ADAccountPassword `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Test-Password `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Remove-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName New-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Restore-ADCommonObject `
                                    -Exactly -Times 0
                            }
                        }
                    }

                    Context "When the '$property' parameter should be empty" {
                        BeforeAll {
                            $setTargetResourceEmptyParams = $setTargetResourcePresentParams.Clone()
                            $setTargetResourceEmptyParams.$property = ''
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceEmptyParams } | Should -Not -Throw
                        }

                        It 'Should call the correct mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $setTargetResourceParamsChangedProperty.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADUser `
                                -ParameterFilter { `
                                    $TargetName -eq $setTargetResourceParamsChangedProperty.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }
                }

                if ($mockChangedSetResource.$property -is [Array])
                {
                    Context "When the $property parameter should be an empty array" {
                        BeforeAll {
                            $setTargetResourceEmptyArrayParams = $setTargetResourcePresentParams.Clone()
                            $setTargetResourceEmptyArrayParams.$property = @()
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceEmptyArrayParams } | Should -Not -Throw
                        }

                        It 'Should call the correct mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $setTargetResourceParamsChangedProperty.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADUser `
                                -ParameterFilter { `
                                    $TargetName -eq $setTargetResourceParamsChangedProperty.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }
                }
            }

            Context 'When the "Path" property has changed' {
                BeforeAll {
                    $changedTargetPath = 'OU=Changed,DC=contoso,DC=com'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourcePresentParams `
                            -Path $changedTargetPath } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $Name -eq $setTargetResourcePresentParams.Name } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName Move-ADObject `
                        -ParameterFilter { $TargetPath -eq $changedTargetPath } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName Set-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Rename-ADObject `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADAccountPassword `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Test-Password `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Remove-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName New-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Restore-ADCommonObject `
                        -Exactly -Times 0
                }
            }

            Context 'When the "CommonName" property has changed' {
                BeforeAll {
                    $testCommonName = 'Test Common Name'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourcePresentParams -CommonName $testCommonName } |
                        Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $Name -eq $setTargetResourcePresentParams.Name } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName Rename-ADObject `
                        -ParameterFilter { $NewName -eq $testCommonName } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName Move-ADObject `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADAccountPassword `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Test-Password `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Remove-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName New-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Restore-ADCommonObject `
                        -Exactly -Times 0
                }
            }

            Context 'When the "DomainController" parameter is specified' {
                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourcePresentParams `
                            -DomainController 'TESTDC' } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { $DomainController -eq 'TESTDC' } `
                        -Exactly -Times 1
                }
            }

            Context 'When the "Password" parameter is specified' {
                Context 'When the specified Password has changed' {
                    BeforeAll {
                        Mock -CommandName Test-Password -MockWith { $false }
                    }

                    Context 'When the "PasswordNeverResets" parameter is False' {

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParams `
                                    -Password $testCredential `
                                    -PasswordNeverResets $false } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -ParameterFilter { $NewPassword -eq $testCredential.Password } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the "PasswordNeverResets" parameter is True' {
                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParams `
                                    -Password $testCredential `
                                    -PasswordNeverResets $true } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the "Credential" parameter is specified' {
                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParams `
                                    -Password $testCredential `
                                    -Credential $testCredential } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $Credential -eq $testCredential } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -ParameterFilter { $NewPassword -eq $testCredential.Password } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the "PasswordAuthentication" parameter is specified as "Default"' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Default'
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParams `
                                    -Password $testCredential `
                                    -PasswordAuthentication $testPasswordAuthentication } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $PasswordAuthentication -eq $testPasswordAuthentication } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -ParameterFilter { $NewPassword -eq $testCredential.Password } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the "PasswordAuthentication" parameter is specified as "Negotiate"' {
                        BeforeAll {
                            $testPasswordAuthentication = 'Negotiate'
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParams `
                                    -Password $testCredential `
                                    -PasswordAuthentication $testPasswordAuthentication } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Test-Password `
                                -ParameterFilter { `
                                    $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                    $Password -eq $testCredential -and `
                                    $PasswordAuthentication -eq $testPasswordAuthentication } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -ParameterFilter { $NewPassword -eq $testCredential.Password } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }

                    Context 'When the specified Password has not changed' {
                        BeforeAll {
                            Mock -CommandName Test-Password -MockWith { $true }
                        }

                        Context 'When the "PasswordNeverResets" parameter is False' {

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentParams `
                                        -Password $testCredential `
                                        -PasswordNeverResets $false } | Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Should -Invoke -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Test-Password `
                                    -ParameterFilter { `
                                        $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                        $Password -eq $testCredential } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Set-ADAccountPassword `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Rename-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Move-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Set-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Remove-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName New-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Restore-ADCommonObject `
                                    -Exactly -Times 0
                            }
                        }

                        Context 'When the "PasswordNeverResets" parameter is True' {
                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentParams `
                                        -Password $testCredential `
                                        -PasswordNeverResets $true } | Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Should -Invoke -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Set-ADAccountPassword `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Rename-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Move-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Set-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Test-Password `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Remove-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName New-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Restore-ADCommonObject `
                                    -Exactly -Times 0
                            }
                        }

                        Context 'When the "Credential" parameter are specified' {
                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentParams `
                                        -Password $testCredential `
                                        -Credential $testCredential } | Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Should -Invoke -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Test-Password `
                                    -ParameterFilter { `
                                        $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                        $Password -eq $testCredential -and `
                                        $Credential -eq $testCredential } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Set-ADAccountPassword `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Rename-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Move-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Set-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Remove-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName New-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Restore-ADCommonObject `
                                    -Exactly -Times 0
                            }
                        }

                        Context 'When the "PasswordAuthentication" parameter is specified as "Default"' {
                            BeforeAll {
                                $testPasswordAuthentication = 'Default'
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentParams `
                                        -Password $testCredential `
                                        -PasswordAuthentication $testPasswordAuthentication } |
                                    Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Should -Invoke -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Test-Password `
                                    -ParameterFilter { `
                                        $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                        $Password -eq $testCredential -and `
                                        $PasswordAuthentication -eq $testPasswordAuthentication } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Set-ADAccountPassword `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Rename-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Move-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Set-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Remove-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName New-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Restore-ADCommonObject `
                                    -Exactly -Times 0
                            }
                        }

                        Context 'When the "PasswordAuthentication" parameter is specified as "Negotiate"' {
                            BeforeAll {
                                $testPasswordAuthentication = 'Negotiate'
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentParams `
                                        -Password $testCredential `
                                        -PasswordAuthentication $testPasswordAuthentication } |
                                    Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Should -Invoke -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentParams.Name } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Test-Password `
                                    -ParameterFilter { `
                                        $UserName -eq $setTargetResourcePresentParams.UserName -and `
                                        $Password -eq $testCredential -and `
                                        $PasswordAuthentication -eq $testPasswordAuthentication } `
                                    -Exactly -Times 1
                                Should -Invoke -CommandName Set-ADAccountPassword `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Rename-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Move-ADObject `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Set-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Remove-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName New-ADUser `
                                    -Exactly -Times 0
                                Should -Invoke -CommandName Restore-ADCommonObject `
                                    -Exactly -Times 0
                            }
                        }
                    }
                }
            }

            Context 'When "ChangePasswordAtLogon" is true' {
                BeforeAll {
                    $mockGetTargetResourcePresentBoolTrueResult = $mockGetTargetResourcePresentResult.Clone()
                    $mockGetTargetResourcePresentBoolTrueResult['ChangePasswordAtLogon'] = $false
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentBoolTrueResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourcePresentParams -ChangePasswordAtLogon:$true } |
                        Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $Name -eq $setTargetResourcePresentParams.Name } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName Set-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Test-Password `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADAccountPassword `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Rename-ADObject `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Move-ADObject `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Remove-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName New-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Restore-ADCommonObject `
                        -Exactly -Times 0
                }
            }
        }

        Context 'When the resource should be absent' {
            It 'Should not throw' {
                { Set-TargetResource @setTargetResourceAbsentParams } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Should -Invoke -CommandName Get-TargetResource `
                    -ParameterFilter { `
                        $Name -eq $setTargetResourceAbsentParams.Name } `
                    -Exactly -Times 1
                Should -Invoke -CommandName Remove-ADUser `
                    -ParameterFilter { $Identity -eq $setTargetResourceAbsentParams.UserName } `
                    -Exactly -Times 1
                Should -Invoke -CommandName Set-ADUser `
                    -Exactly -Times 0
                Should -Invoke -CommandName Test-Password `
                    -Exactly -Times 0
                Should -Invoke -CommandName Set-ADAccountPassword `
                    -Exactly -Times 0
                Should -Invoke -CommandName Rename-ADObject `
                    -Exactly -Times 0
                Should -Invoke -CommandName Move-ADObject `
                    -Exactly -Times 0
                Should -Invoke -CommandName New-ADUser `
                    -Exactly -Times 0
                Should -Invoke -CommandName Restore-ADCommonObject `
                    -Exactly -Times 0
            }
        }
    }

    Context 'When the resource is absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
        }

        Context 'When the resource should be present' {
            foreach ($property in $mockChangedResource.Keys)
            {
                if ($property -eq 'CommonName')
                {
                    Context 'When the CommonName does not match the UserName' {
                        BeforeAll {
                            $setTargetResourceNewParams = $setTargetResourcePresentParams.Clone()
                            $setTargetResourceNewParams.CommonName = $mockChangedResource.CommonName
                            $mockNewAdUserResult = @{
                                DistinguishedName = $mockResource.DistinguishedName
                            }

                            Mock -CommandName New-ADUser -MockWith { $mockNewAdUserResult }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceNewParams } |
                                Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $setTargetResourceNewParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName New-ADUser `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Rename-ADObject `
                                -ParameterFilter { $NewName -eq $setTargetResourceNewParams.CommonName } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }
                }
                else
                {
                    Context "When the '$property' parameter is specified" {
                        BeforeAll {
                            $setTargetResourceNewParams = $setTargetResourcePresentParams.Clone()
                            $setTargetResourceNewParams.$property = $mockChangedResource.$property
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceNewParams } | Should -Not -Throw
                        }

                        It 'Should call the correct mocks' {
                            Should -Invoke -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $setTargetResourceNewParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName New-ADUser `
                                -ParameterFilter { $TargetName -eq $setTargetResourceNewParams.Name } `
                                -Exactly -Times 1
                            Should -Invoke -CommandName Set-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Move-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Rename-ADObject `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Set-ADAccountPassword `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Test-Password `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Remove-ADUser `
                                -Exactly -Times 0
                            Should -Invoke -CommandName Restore-ADCommonObject `
                                -Exactly -Times 0
                        }
                    }
                }
            }

            Context 'When the Password parameter is specified' {
                BeforeAll {
                    $setTargetResourceNewParams = $setTargetResourcePresentParams.Clone()
                    $setTargetResourceNewParams.Password = $mockResource.Password
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceNewParams } | Should -Not -Throw
                }

                It 'Should call the correct mocks' {
                    Should -Invoke -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $Name -eq $setTargetResourceNewParams.Name } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName New-ADUser `
                        -ParameterFilter { $AccountPassword -eq $setTargetResourceNewParams.Password.Password } `
                        -Exactly -Times 1
                    Should -Invoke -CommandName Set-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Move-ADObject `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Rename-ADObject `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Set-ADAccountPassword `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Test-Password `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Remove-ADUser `
                        -Exactly -Times 0
                    Should -Invoke -CommandName Restore-ADCommonObject `
                        -Exactly -Times 0
                }
            }

            Context 'When the "RestoreFromRecycleBin" parameter is specified' {

                Context 'When the user is found in the recycle bin' {
                    BeforeAll {
                        Mock -CommandName Restore-ADCommonObject `
                            -MockWith { @{ ObjectClass = 'user' } }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParams `
                                -RestoreFromRecycleBin $true } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Should -Invoke -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourcePresentParams.Name } `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Restore-ADCommonObject `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Set-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName New-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Remove-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Test-Password `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Set-ADAccountPassword `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Rename-ADObject `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Move-ADObject `
                            -Exactly -Times 0
                    }
                }

                Context 'When the user is not found in the recycle bin' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParams `
                                -RestoreFromRecycleBin $true } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Should -Invoke -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourcePresentParams.Name } `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Restore-ADCommonObject `
                            -Exactly -Times 1
                        Should -Invoke -CommandName New-ADUser `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Set-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Remove-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Test-Password `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Set-ADAccountPassword `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Rename-ADObject `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Move-ADObject `
                            -Exactly -Times 0
                    }
                }

                Context 'When the user cannot be restored from the recylce bin' {
                    BeforeAll {
                        Mock -CommandName Restore-ADCommonObject -MockWith { throw }
                    }

                    It 'Should throw the correct exception' {
                        { Set-TargetResource @setTargetResourcePresentParams `
                                -RestoreFromRecycleBin $true } | Should -Throw
                    }

                    It 'Should call the expected mocks' {
                        Should -Invoke -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourcePresentParams.Name } `
                            -Exactly -Times 1
                        Should -Invoke -CommandName Restore-ADCommonObject `
                            -Exactly -Times 1
                        Should -Invoke -CommandName New-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Set-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Remove-ADUser `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Test-Password `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Set-ADAccountPassword `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Rename-ADObject `
                            -Exactly -Times 0
                        Should -Invoke -CommandName Move-ADObject `
                            -Exactly -Times 0
                    }
                }
            }
        }

        Context 'When the resource should be absent' {
            It 'Should not throw' {
                { Set-TargetResource @setTargetResourceAbsentParams } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Should -Invoke -CommandName Get-TargetResource `
                    -ParameterFilter { `
                        $Name -eq $setTargetResourceAbsentParams.Name } `
                    -Exactly -Times 1
                Should -Invoke -CommandName Restore-ADCommonObject `
                    -Exactly -Times 0
                Should -Invoke -CommandName New-ADUser `
                    -Exactly -Times 0
                Should -Invoke -CommandName Set-ADUser `
                    -Exactly -Times 0
                Should -Invoke -CommandName Remove-ADUser `
                    -Exactly -Times 0
                Should -Invoke -CommandName Test-Password `
                    -Exactly -Times 0
                Should -Invoke -CommandName Set-ADAccountPassword `
                    -Exactly -Times 0
                Should -Invoke -CommandName Rename-ADObject `
                    -Exactly -Times 0
                Should -Invoke -CommandName Move-ADObject `
                    -Exactly -Times 0
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
