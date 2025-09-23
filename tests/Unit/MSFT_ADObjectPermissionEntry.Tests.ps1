$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADObjectPermissionEntry'

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

        #region Pester Test Initialization
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

        $testAbsentParameters = @{
            Ensure                = 'Absent'
            ActiveDirectoryRights = 'GenericAll'
        }

        $mockADDrivePSPath = '\'

        $mockADSchemaGuid = '00000000-0000-0000-0000-000000000000'

        $mockGetAclPresent = {
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

        $mockGetAclAbsent = {
            $mock = [PSCustomObject] @{
                Path   = 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=PC,CN=Computers,DC=lab,DC=local'
                Owner  = 'BUILTIN\Administrators'
                Access = @()
            }
            $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
            $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
            return $mock
        }

        $mockGetADRootDSE = {
            $mock = [PSCustomObject] @{
                configurationNamingContext  = 'CN=Configuration,DC=contoso,DC=com'
                defaultNamingContext        = 'DC=contoso,DC=com'
                schemaNamingContext         = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
            }
            return $mock
        }
        #endregion

        #region Function Get-ADDrivePSPath
        Describe -Name 'ADObjectPermissionEntry\Get-ADDrivePSPath' {
            Mock -CommandName 'Assert-ADPSDrive'
            Mock -CommandName Get-Item -MockWith {
                return @{
                    PSPath = $mockADDrivePSPath
                }
            }

            It 'Should call "Assert-ADPSDrive" to check AD PS Drive is created' {
                # Act
                $ADDrivePSPath = Get-ADDrivePSPath

                # Assert
                Assert-MockCalled -CommandName Assert-ADPSDrive -Scope It -Exactly -Times 1
            }

            It 'Should return full PSPath for the AD Drive' {
                # Act
                $ADDrivePSPath = Get-ADDrivePSPath

                # Assert
                $ADDrivePSPath | Should -Be $mockADDrivePSPath
            }
        }
        #endregion Function Get-ADDrivePSPath

        #region Function Get-TargetResource
        Describe 'ADObjectPermissionEntry\Get-TargetResource' {
            Mock -CommandName 'Get-ADDrivePSPath' -MockWith {
                return $mockADDrivePSPath
            }

            Mock -CommandName 'Test-IsGuid' -MockWith {
                return $false
            }

            Mock -CommandName 'Get-ADSchemaGuid' -MockWith {
                return $mockADSchemaGuid
            }

            Context 'When the desired ace is present' {

                Mock -CommandName 'Get-Acl' -MockWith $mockGetAclPresent

                It 'Should return a "System.Collections.Hashtable" object type' {
                    # Act
                    $targetResource = Get-TargetResource @testDefaultParameters

                    # Assert
                    $targetResource | Should -BeOfType [System.Collections.Hashtable]
                }

                It 'Should return a valid result if the ace is present' {
                    # Act
                    $targetResource = Get-TargetResource @testDefaultParameters

                    # Assert
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

            Context 'When the desired ace is absent' {

                Mock -CommandName 'Get-Acl' -MockWith $mockGetAclAbsent

                It 'Should return a valid result if the ace is absent' {
                    # Act
                    $targetResource = Get-TargetResource @testDefaultParameters

                    # Assert
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
            Context 'When the desired AD object path is absent' {

                Mock -CommandName 'Get-Acl' -MockWith { throw New-Object System.Management.Automation.ItemNotFoundException }

                It 'Should return a valid result if the AD object path is absent' {
                    # Act / Assert
                    $targetResource = Get-TargetResource @testDefaultParameters
                    $targetResource.Ensure | Should -Be 'Absent'
                }
            }
            Context 'When an unknown error occurs' {

                $error = 'Unknown Error'
                Mock -CommandName 'Get-Acl' -MockWith { throw $error }

                It 'Should throw an exception if an unknown error occurs calling Get-Acl' {
                    # Act / Assert
                    { Get-TargetResource @testDefaultParameters } | Should -Throw
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADObjectPermissionEntry\Test-TargetResource' {
            Mock -CommandName 'Get-ADDrivePSPath' -MockWith {
                return $mockADDrivePSPath
            }

            Context 'When the desired ace is present' {

                Mock -CommandName 'Get-Acl' -MockWith $mockGetAclPresent

                It 'Should return a "System.Boolean" object type' {
                    # Act
                    $targetResource = Test-TargetResource @testDefaultParameters @testPresentParameters

                    # Assert
                    $targetResource | Should -BeOfType [System.Boolean]
                }

                It 'Should return $true if the ace desired state is present' {
                    # Act
                    $targetResource = Test-TargetResource @testDefaultParameters @testPresentParameters

                    # Assert
                    $targetResource | Should -BeTrue
                }

                It 'Should return $false if the ace desired state is absent' {
                    # Act
                    $targetResource = Test-TargetResource @testDefaultParameters @testAbsentParameters

                    # Assert
                    $targetResource | Should -BeFalse
                }
            }

            Context 'When the desired ace is absent' {

                Mock -CommandName 'Get-Acl' -MockWith $mockGetAclAbsent

                It 'Should return $false if the ace desired state is present' {
                    # Act
                    $targetResource = Test-TargetResource @testDefaultParameters @testPresentParameters

                    # Assert
                    $targetResource | Should -BeFalse
                }

                It 'Should return $true if the ace desired state is absent' {
                    # Act
                    $targetResource = Test-TargetResource @testDefaultParameters @testAbsentParameters

                    # Assert
                    $targetResource | Should -BeTrue
                }
            }
        }
        #endregion

        #region Function Set-TargetResource
        Describe 'ADObjectPermissionEntry\Set-TargetResource' {
            Mock -CommandName 'Get-ADDrivePSPath' -MockWith {
                return $mockADDrivePSPath
            }

            Mock -CommandName 'Test-IsGuid' -MockWith {
                return $false
            }

            Mock -CommandName 'Get-ADSchemaGuid' -MockWith {
                return $mockADSchemaGuid
            }

            Context 'When the desired ace is present' {

                Mock -CommandName 'Get-Acl' -MockWith $mockGetAclPresent
                Mock -CommandName 'Set-Acl' -Verifiable

                It 'Should remove the ace from the existing acl' {
                    # Act
                    Set-TargetResource @testDefaultParameters @testAbsentParameters

                    # Assert
                    Assert-MockCalled -CommandName 'Set-Acl' -Scope It -Times 1 -Exactly
                }
            }

            Context 'When the desired ace is absent' {

                Mock -CommandName 'Get-Acl' -MockWith $mockGetAclAbsent
                Mock -CommandName 'Set-Acl' -Verifiable

                It 'Should add the ace to the existing acl' {
                    # Act
                    Set-TargetResource @testDefaultParameters @testPresentParameters

                    # Assert
                    Assert-MockCalled -CommandName 'Set-Acl' -Scope It -Times 1 -Exactly
                }
            }
        }

        #region Function Get-ADSchemaGuid
        Describe -Name 'ADObjectPermissionEntry\Get-ADSchemaGuid' {
            Mock -CommandName 'Get-ADRootDSE' -MockWith $mockGetADRootDSE

            Context 'When DisplayName matches a schema object' {
                It 'Should return schemaIDGUID' {
                    Mock -CommandName 'Get-ADObject' -MockWith {
                        return @{ schemaIDGUID = 'bf967aba-0de6-11d0-a285-00aa003049e2' }
                    }

                    # Act
                    $guid = Get-ADSchemaGuid -DisplayName 'user'
                    
                    # Assert
                    $guid | Should -Be 'bf967aba-0de6-11d0-a285-00aa003049e2'
                }
            }

            Context 'When DisplayName matches an extended right' {
                It 'Should return rightsGUID' {
                    $script:mockCallCount = 0

                    Mock -CommandName 'Get-ADObject' -MockWith {
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

                    # Act
                    $guid = Get-ADSchemaGuid -DisplayName 'Send As'
                    
                    # Assert
                    $guid | Should -Be 'ab721a54-1e2f-11d0-9819-00aa0040529b'
                }
            }

            Context 'When no matching GUID found for DisplayName' {
                It 'Should throw an exception' {
                    Mock -CommandName 'Get-ADObject' -MockWith { return }

                    { Get-ADSchemaGuid -DisplayName 'non-existent' } | Should -Throw
                }
            }
        }
        #endregion Function Get-ADSchemaGuid

        #region Function Test-IsGuid
        Describe -Name 'ADObjectPermissionEntry\Test-IsGuid' {
            Context 'When testing a valid GUID' {
                It 'Should return true' {
                    # Act
                    $isGuid = Test-IsGuid -InputString '550e8400-e29b-41d4-a716-446655440000'

                    # Assert
                    $isGuid | Should -BeTrue
                }
            }

            Context 'When testing an invalid GUID' {
                It 'Should return false' {
                    # Act
                    $isGuid = Test-IsGuid -InputString 'No valid GUID'

                    # Assert
                    $isGuid | Should -BeFalse
                }
            }
        }
        #endregion Function Test-IsGuid

        #region Function Get-EscapedLdapFilterValue
        Describe -Name 'ADObjectPermissionEntry\Get-EscapedLdapFilterValue' {
            Context 'When value contains special characters' {
                It 'Should return escaped LDAP filter value' {
                    # Act
                    $escapedLdapFilterValue = Get-EscapedLdapFilterValue -Value 'Smith (Admin)*'
                    
                    # Assert
                    $escapedLdapFilterValue | Should -Be 'Smith \28Admin\29\2a'
                }
            }
        }
        #endregion Function Get-EscapedLdapFilterValue
    }
}
finally
{
    Invoke-TestCleanup
}
