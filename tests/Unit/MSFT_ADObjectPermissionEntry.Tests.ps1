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

Describe 'MSFT_ADObjectPermissionEntry\Get-TargetResource' -Tag 'Get' {
    Context 'When the desired ace is present' {
        BeforeAll {
            Mock -CommandName Get-ADDrivePSPath -MockWith {
                return '\'
            }

            Mock -CommandName Test-IsGuid -MockWith {
                return $false
            }

            Mock -CommandName Get-ADSchemaGuid -MockWith {
                return '00000000-0000-0000-0000-000000000000'
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
                $targetResource.ActiveDirectoryRights | Should -Be @('GenericAll')
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $true
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
                $targetResource.ActiveDirectoryRights | Should -Be @()
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $true
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $true
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $false
            }

            Mock -CommandName Get-ADSchemaGuid -MockWith {
                return '00000000-0000-0000-0000-000000000000'
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $true
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $false
            }

            Mock -CommandName Get-ADSchemaGuid -MockWith {
                return '00000000-0000-0000-0000-000000000000'
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

            Mock -CommandName Test-IsGuid -MockWith {
                return $true
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

Describe -Name 'MSFT_ADObjectPermissionEntry\Get-ADSchemaGuid' -Tag 'Helper' {
    Context 'When DisplayName matches a schema object' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            Mock -CommandName Get-ADObject -MockWith {
                return @{ schemaIDGUID = ([guid]'bf967aba-0de6-11d0-a285-00aa003049e2').ToByteArray() }
            }
        }

        It 'Should return schemaIDGUID' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $guid = Get-ADSchemaGuid -DisplayName 'user'

                $guid | Should -Be 'bf967aba-0de6-11d0-a285-00aa003049e2'
            }
        }
    }

    Context 'When DisplayName matches an extended right' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            $script:mockCallCount = 0

            Mock -CommandName Get-ADObject -MockWith {
                $script:mockCallCount++
                if ($script:mockCallCount -eq 1)
                {
                    return
                }
                else
                {
                    return @{ rightsGUID = 'ab721a54-1e2f-11d0-9819-00aa0040529b' }
                }
            }
        }

        It 'Should return rightsGUID' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $guid = Get-ADSchemaGuid -DisplayName 'Send As'

                $guid | Should -Be 'ab721a54-1e2f-11d0-9819-00aa0040529b'
            }
        }
    }

    Context 'When no matching GUID found for DisplayName' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            Mock -CommandName Get-ADObject
        }

        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Get-ADSchemaGuid -DisplayName 'non-existent' } | Should -Throw
            }
        }
    }

    Context 'When retrieving ADRootDSE fails' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith { throw 'Unknown error' }
        }

        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Get-ADSchemaGuid -DisplayName 'user' } | Should -Throw
            }
        }
    }

    Context 'When searching the Active Directory schema fails' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            Mock -CommandName Get-ADObject -MockWith { throw 'Unknown error' }
        }

        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Get-ADSchemaGuid -DisplayName 'user' } | Should -Throw
            }
        }
    }

    Context 'When searching the Extended Rights container fails' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            $script:mockCallCount = 0

            Mock -CommandName Get-ADObject -MockWith {
                $script:mockCallCount++
                if ($script:mockCallCount -eq 1)
                {
                    return
                }
                else
                {
                    throw 'Unknown error'
                }
            }
        }

        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Get-ADSchemaGuid -DisplayName 'user' } | Should -Throw
            }
        }
    }

    Context 'When multiple schema objects are found' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            Mock -CommandName Get-ADObject -MockWith {
                return @(
                    @{ schemaIDGUID = ([guid]'bf967aba-0de6-11d0-a285-00aa003049e2').ToByteArray() }
                    @{ schemaIDGUID = ([guid]'00a0a7cf-3f83-4d47-a203-f1c6bf6d8251').ToByteArray() }
                )
            }
        }

        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Get-ADSchemaGuid -DisplayName 'user' } | Should -Throw
            }
        }
    }

    Context 'When multiple extended rights objects are found' {
        BeforeAll {
            Mock -CommandName Get-ADRootDSE -MockWith {
                $mock = [PSCustomObject] @{
                    configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                    defaultNamingContext        = 'DC=contoso,DC=com'
                    schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                }
                return $mock
            }

            $script:mockCallCount = 0

            Mock -CommandName Get-ADObject -MockWith {
                $script:mockCallCount++
                if ($script:mockCallCount -eq 1)
                {
                    return
                }
                else
                {
                    return @(
                        @{ rightsGUID = 'ab721a54-1e2f-11d0-9819-00aa0040529b' }
                        @{ rightsGUID = '735c1fed-227f-4a80-920b-671da2705bd6' }
                    )
                }
            }
        }

        It 'Should throw an exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Get-ADSchemaGuid -DisplayName 'user' } | Should -Throw
            }
        }
    }
}

Describe -Name 'MSFT_ADObjectPermissionEntry\Test-IsGuid' -Tag 'Helper' {
    It 'Should return true if testing a valid GUID' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $isGuid = Test-IsGuid -InputString '550e8400-e29b-41d4-a716-446655440000'

            $isGuid | Should -BeTrue
        }
    }

    It 'Should return false if testing an invalid GUID' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $isGuid = Test-IsGuid -InputString 'No valid GUID'

            $isGuid | Should -BeFalse
        }
    }
}

Describe -Name 'MSFT_ADObjectPermissionEntry\Get-EscapedLdapFilterValue' -Tag 'Helper' {
    It 'Should escape backslash character' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $escapedLdapFilterValue = Get-EscapedLdapFilterValue -Value 'Smith \ Admin'

            $escapedLdapFilterValue | Should -Be 'Smith \5c Admin'
        }
    }

    It 'Should escape asterisk character' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $escapedLdapFilterValue = Get-EscapedLdapFilterValue -Value 'Smith *Admin*'

            $escapedLdapFilterValue | Should -Be 'Smith \2aAdmin\2a'
        }
    }

    It 'Should escape opening and closing parentheses characters' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $escapedLdapFilterValue = Get-EscapedLdapFilterValue -Value 'Smith (Admin)'

            $escapedLdapFilterValue | Should -Be 'Smith \28Admin\29'
        }
    }

    It 'Should escape NULL character' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $escapedLdapFilterValue = Get-EscapedLdapFilterValue -Value "Smith`0Admin"

            $escapedLdapFilterValue | Should -Be 'Smith\00Admin'
        }
    }
}
