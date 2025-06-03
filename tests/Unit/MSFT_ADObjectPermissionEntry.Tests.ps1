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
    $script:dscResourceName = 'MSFT_ADObjectPermissionEntry'

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

$testDefaultParameters = @{
    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
    IdentityReference                  = 'CONTOSO\User'
    AccessControlType                  = 'Allow'
    ObjectType                         = '00000000-0000-0000-0000-000000000000'
    ActiveDirectorySecurityInheritance = 'None'
    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
}

# $testPresentParameters = @{
#     Ensure                = 'Present'
#     ActiveDirectoryRights = 'GenericAll'
# }

# $testAbsentParameters = @{
#     Ensure                = 'Absent'
#     ActiveDirectoryRights = 'GenericAll'
# }

# $mockADDrivePSPath = '\'

# $mockGetAclPresent = {
# $mock = [PSCustomObject] @{
#     Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC01,CN=Computers,DC=contoso,DC=com'
#     Owner  = 'BUILTIN\Administrators'
#     Access = @(
#         [PSCustomObject] @{
#             ActiveDirectoryRights = 'GenericAll'
#             InheritanceType       = 'None'
#             ObjectType            = [System.Guid] '00000000-0000-0000-0000-000000000000'
#             InheritedObjectType   = [System.Guid] '00000000-0000-0000-0000-000000000000'
#             ObjectFlags           = 'None'
#             AccessControlType     = 'Allow'
#             IdentityReference     = [PSCustomObject] @{
#                 Value = 'CONTOSO\User'
#             }
#             IsInherited           = $false
#             InheritanceFlags      = 'None'
#             PropagationFlags      = 'None'
#         }
#     )
# }
# $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
# $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
# return $mock
# }

# $mockGetAclAbsent = {
# $mock = [PSCustomObject] @{
#     Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC,CN=Computers,DC=lab,DC=local'
#     Owner  = 'BUILTIN\Administrators'
#     Access = @()
# }

# $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
# $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
# return $mock
# }

Describe 'MSFT_ADObjectPermissionEntry\Get-TargetResource' -Tag 'Get' {
    Context 'When the desired ace is present' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith {
                $mock = [PSCustomObject] @{
                    Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC01,CN=Computers,DC=contoso,DC=com'
                    Owner  = 'BUILTIN\Administrators'
                    Access = @(
                        [PSCustomObject] @{
                            ActiveDirectoryRights = 'GenericAll'
                            InheritanceType       = 'None'
                            ObjectType            = [System.Guid] '00000000-0000-0000-0000-000000000000'
                            InheritedObjectType   = [System.Guid] '00000000-0000-0000-0000-000000000000'
                            ObjectFlags           = 'None'
                            AccessControlType     = 'Allow'
                            IdentityReference     = [PSCustomObject] @{
                                Value = 'CONTOSO\User'
                            }
                            IsInherited           = $false
                            InheritanceFlags      = 'None'
                            PropagationFlags      = 'None'
                        }
                    )
                }

                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
                return $mock
            }
        }

        It 'Should return a valid result if the ace is present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $targetResource = Get-TargetResource @testDefaultParameters

                $targetResource | Should -BeOfType [System.Collections.Hashtable]
                $targetResource.Ensure | Should -Be 'Present'
                $targetResource.Path | Should -Be $testDefaultParameters.Path
                $targetResource.IdentityReference | Should -Be $testDefaultParameters.IdentityReference
                $targetResource.ActiveDirectoryRights | Should -Be 'GenericAll'
                $targetResource.AccessControlType | Should -Be $testDefaultParameters.AccessControlType
                $targetResource.ObjectType | Should -Be $testDefaultParameters.ObjectType
                $targetResource.ActiveDirectorySecurityInheritance | Should -Be $testDefaultParameters.ActiveDirectorySecurityInheritance
                $targetResource.InheritedObjectType | Should -Be $testDefaultParameters.InheritedObjectType
            }
        }
    }

    Context 'When the desired ace is absent' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith {
                $mock = [PSCustomObject] @{
                    Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC,CN=Computers,DC=lab,DC=local'
                    Owner  = 'BUILTIN\Administrators'
                    Access = @()
                }

                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
                return $mock
            }
        }

        It 'Should return a valid result if the ace is absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $targetResource = Get-TargetResource @testDefaultParameters

                $targetResource.Ensure | Should -Be 'Absent'
                $targetResource.Path | Should -Be $testDefaultParameters.Path
                $targetResource.IdentityReference | Should -Be $testDefaultParameters.IdentityReference
                $targetResource.ActiveDirectoryRights | Should -Be ''
                $targetResource.AccessControlType | Should -Be $testDefaultParameters.AccessControlType
                $targetResource.ObjectType | Should -Be $testDefaultParameters.ObjectType
                $targetResource.ActiveDirectorySecurityInheritance | Should -Be $testDefaultParameters.ActiveDirectorySecurityInheritance
                $targetResource.InheritedObjectType | Should -Be $testDefaultParameters.InheritedObjectType
            }
        }
    }

    Context 'When the desired AD object path is absent' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith { throw New-Object System.Management.Automation.ItemNotFoundException }
        }

        It 'Should return a valid result if the AD object path is absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $targetResource = Get-TargetResource @testDefaultParameters
                $targetResource.Ensure | Should -Be 'Absent'
            }
        }
    }

    Context 'When an unknown error occurs' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith { throw 'Unknown Error' }
        }

        It 'Should throw an exception if an unknown error occurs calling Get-Acl' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                { Get-TargetResource @testDefaultParameters } | Should -Throw
            }
        }
    }
}

Describe 'MSFT_ADObjectPermissionEntry\Test-TargetResource' -Tag 'Test' {
    Context 'When the desired ace is present' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith {
                $mock = [PSCustomObject] @{
                    Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC01,CN=Computers,DC=contoso,DC=com'
                    Owner  = 'BUILTIN\Administrators'
                    Access = @(
                        [PSCustomObject] @{
                            ActiveDirectoryRights = 'GenericAll'
                            InheritanceType       = 'None'
                            ObjectType            = [System.Guid] '00000000-0000-0000-0000-000000000000'
                            InheritedObjectType   = [System.Guid] '00000000-0000-0000-0000-000000000000'
                            ObjectFlags           = 'None'
                            AccessControlType     = 'Allow'
                            IdentityReference     = [PSCustomObject] @{
                                Value = 'CONTOSO\User'
                            }
                            IsInherited           = $false
                            InheritanceFlags      = 'None'
                            PropagationFlags      = 'None'
                        }
                    )
                }

                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
                return $mock
            }
        }

        It 'Should return $true if the ace desired state is present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $testPresentParameters = @{
                    Ensure                = 'Present'
                    ActiveDirectoryRights = 'GenericAll'
                }

                Test-TargetResource @testDefaultParameters @testPresentParameters | Should -BeTrue
            }
        }

        It 'Should return $false if the ace desired state is absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $testAbsentParameters = @{
                    Ensure                = 'Absent'
                    ActiveDirectoryRights = 'GenericAll'
                }

                Test-TargetResource @testDefaultParameters @testAbsentParameters | Should -BeFalse
            }
        }
    }

    Context 'When the desired ace is absent' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith {
                $mock = [PSCustomObject] @{
                    Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC,CN=Computers,DC=lab,DC=local'
                    Owner  = 'BUILTIN\Administrators'
                    Access = @()
                }

                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
                return $mock
            }
        }

        It 'Should return $false if the ace desired state is present' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $testPresentParameters = @{
                    Ensure                = 'Present'
                    ActiveDirectoryRights = 'GenericAll'
                }

                Test-TargetResource @testDefaultParameters @testPresentParameters | Should -BeFalse
            }
        }

        It 'Should return $true if the ace desired state is absent' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $testAbsentParameters = @{
                    Ensure                = 'Absent'
                    ActiveDirectoryRights = 'GenericAll'
                }

                Test-TargetResource @testDefaultParameters @testAbsentParameters | Should -BeTrue
            }
        }
    }
}


Describe 'MSFT_ADObjectPermissionEntry\Set-TargetResource' -Tag 'Set' {
    Context 'When the desired ace is present' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith {
                $mock = [PSCustomObject] @{
                    Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC01,CN=Computers,DC=contoso,DC=com'
                    Owner  = 'BUILTIN\Administrators'
                    Access = @(
                        [PSCustomObject] @{
                            ActiveDirectoryRights = 'GenericAll'
                            InheritanceType       = 'None'
                            ObjectType            = [System.Guid] '00000000-0000-0000-0000-000000000000'
                            InheritedObjectType   = [System.Guid] '00000000-0000-0000-0000-000000000000'
                            ObjectFlags           = 'None'
                            AccessControlType     = 'Allow'
                            IdentityReference     = [PSCustomObject] @{
                                Value = 'CONTOSO\User'
                            }
                            IsInherited           = $false
                            InheritanceFlags      = 'None'
                            PropagationFlags      = 'None'
                        }
                    )
                }

                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
                return $mock
            }

            Mock -CommandName Set-Acl
        }

        It 'Should remove the ace from the existing acl' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $testAbsentParameters = @{
                    Ensure                = 'Absent'
                    ActiveDirectoryRights = 'GenericAll'
                }

                Set-TargetResource @testDefaultParameters @testAbsentParameters
            }

            Should -Invoke -CommandName Set-Acl -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the desired ace is absent' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Get-Acl -MockWith {
                $mock = [PSCustomObject] @{
                    Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC,CN=Computers,DC=lab,DC=local'
                    Owner  = 'BUILTIN\Administrators'
                    Access = @()
                }

                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
                $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
                return $mock
            }

            Mock -CommandName Set-Acl
        }

        It 'Should add the ace to the existing acl' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testDefaultParameters = @{
                    Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
                    IdentityReference                  = 'CONTOSO\User'
                    AccessControlType                  = 'Allow'
                    ObjectType                         = '00000000-0000-0000-0000-000000000000'
                    ActiveDirectorySecurityInheritance = 'None'
                    InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
                }

                $testPresentParameters = @{
                    Ensure                = 'Present'
                    ActiveDirectoryRights = 'GenericAll'
                }

                Set-TargetResource @testDefaultParameters @testPresentParameters
            }

            Should -Invoke -CommandName Set-Acl -Exactly -Times 1 -Scope It
        }
    }
}

Describe -Name 'MSFT_ADObjectPermissionEntry\Get-ADDrivePSPath' -Tag 'Helper' {
    BeforeAll {
        Mock -CommandName Assert-ADPSDrive
        Mock -CommandName Get-Item -MockWith {
            return @{
                PSPath = '\'
            }
        }
    }

    It 'Should return the correct result' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            Get-ADDrivePSPath | Should -Be '\'
        }

        Should -Invoke -CommandName Assert-ADPSDrive -Exactly -Times 1 -Scope It
    }
}
