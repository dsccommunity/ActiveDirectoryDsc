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
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\..\source\Modules\ActiveDirectoryDsc.Common\ActiveDirectoryDsc.Common.psm1') -Force

        #region Pester Test Initialization
        $mockCredentialUserName = 'COMPANY\User'
        $mockCredentialPassword = 'dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force
        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockCredentialUserName, $mockCredentialPassword
        )

        $testDefaultParameters = @{
            Path                               = 'CN=PC01,CN=Computers,DC=contoso,DC=com'
            IdentityReference                  = 'CONTOSO\User'
            AccessControlType                  = 'Allow'
            ObjectType                         = '00000000-0000-0000-0000-000000000000'
            ActiveDirectorySecurityInheritance = 'None'
            InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
            Credential                         = $mockCredential
        }

        $testPresentParameters = @{
            Ensure                = 'Present'
            ActiveDirectoryRights = 'GenericAll'
        }

        $testAbsentParameters = @{
            Ensure                = 'Absent'
            ActiveDirectoryRights = 'GenericAll'
        }

        $mockGetAclPresent = {
            $mock = [PSCustomObject] @{
                Path   = 'AD:CN=PC01,CN=Computers,DC=contoso,DC=com'
                Owner  = 'BUILTIN\Administrators'
                ObjectSecurity = [PSCustomObject]@{
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
            }
            $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
            $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
            return $mock
        }

        $mockGetAclAbsent = {
            $mock = [PSCustomObject] @{
                Path   = 'AD:CN=PC,CN=Computers,DC=lab,DC=local'
                Owner  = 'BUILTIN\Administrators'
                Access = @()
            }
            $mock | Add-Member -MemberType 'ScriptMethod' -Name 'AddAccessRule' -Value { }
            $mock | Add-Member -MemberType 'ScriptMethod' -Name 'RemoveAccessRule' -Value { }
            return $mock
        }
        #endregion

        #region Function Get-TargetResource
        Describe 'ADObjectPermissionEntry\Get-TargetResource' {
            Mock -CommandName 'Assert-ADPSDrive'

            Context 'When the desired ace is present' {

                Mock -CommandName 'Get-DirectoryEntry' -MockWith $mockGetAclPresent

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

                Mock -CommandName 'Get-DirectoryEntry' -MockWith $mockGetAclAbsent

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

                Mock -CommandName 'Get-DirectoryEntry' -MockWith { throw New-Object System.Management.Automation.ItemNotFoundException }

                It 'Should return a valid result if the AD object path is absent' {
                    # Act / Assert
                    $targetResource = Get-TargetResource @testDefaultParameters
                    $targetResource.Ensure | Should -Be 'Absent'
                }
            }
            Context 'When an unknown error occurs' {

                $errormsg = 'Unknown Error'
                Mock -CommandName 'Get-DirectoryEntry' -MockWith { throw $errormsg }

                It 'Should throw an exception if an unknown error occurs calling Get-Acl' {
                    # Act / Assert
                    { Get-TargetResource @testDefaultParameters } | Should -Throw
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADObjectPermissionEntry\Test-TargetResource' {
            Mock -CommandName 'Assert-ADPSDrive' { }

            Context 'When the desired ace is present' {

                Mock -CommandName 'Get-DirectoryEntry' -MockWith $mockGetAclPresent

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

                Mock -CommandName 'Get-DirectoryEntry' -MockWith $mockGetAclAbsent

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
    }
}
finally
{
    Invoke-TestCleanup
}
