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
    $script:dscResourceName = 'MSFT_ADGroup'

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

$testPresentParams = @{
    GroupName        = 'TestGroup'
    CommonName       = 'TestGroup'
    GroupScope       = 'Global'
    Category         = 'Security'
    Path             = 'OU=OU,DC=contoso,DC=com'
    Description      = 'Test AD group description'
    DisplayName      = 'Test display name'
    AdminDescription = 'Group_'
    Ensure           = 'Present'
    Notes            = 'This is a test AD group'
    ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
}

$mockGroupName = 'TestGroup'
$mockCommonName = 'TestGroup'
$mockGroupPath = 'OU=Test,DC=contoso,DC=com'
$mockGroupDN = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'

$mockADGroupMembersAsADObjects = @(
    @{
        DistinguishedName = 'CN=User 1,CN=Users,DC=contoso,DC=com'
        ObjectGUID        = 'a97cc867-0c9e-4928-8387-0dba0c883b8e'
        SamAccountName    = 'USER1'
        ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1106'
        ObjectClass       = 'user'
    }
    @{
        DistinguishedName = 'CN=Group 1,CN=Users,DC=contoso,DC=com'
        ObjectGUID        = 'e2328767-2673-40b2-b3b7-ce9e6511df06'
        SamAccountName    = 'GROUP1'
        ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1206'
        ObjectClass       = 'group'
    }
    @{
        DistinguishedName = 'CN=Computer 1,CN=Users,DC=contoso,DC=com'
        ObjectGUID        = '42f9d607-0934-4afc-bb91-bdf93e07cbfc'
        SamAccountName    = 'COMPUTER1'
        ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-6606'
        ObjectClass       = 'computer'
    }
    # This entry is used to represent a group member from a one-way trusted domain
    @{
        DistinguishedName = 'CN=S-1-5-21-8562719340-2451078396-046517832-2106,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        ObjectGUID        = '6df78e9e-c795-4e67-a626-e17f1b4a0d8b'
        SamAccountName    = 'ADATUM\USER1'
        ObjectSID         = 'S-1-5-21-8562719340-2451078396-046517832-2106'
        ObjectClass       = 'foreignSecurityPrincipal'
    }
)

$mockADGroup = @{
    SamAccountName    = 'TestGroup'
    CN                = 'TestGroup'
    GroupScope        = 'Global'
    GroupCategory     = 'Security'
    Path              = 'OU=Test,DC=contoso,DC=com'
    Description       = 'Test AD group description'
    DisplayName       = 'Test display name'
    AdminDescription  = 'Group_'
    Info              = 'This is a test AD group'
    ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
    DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
    Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
}

$mockADGroupChanged = @{
    GroupScope  = 'Universal'
    Description = 'Test AD group description changed'
    DisplayName = 'Test display name changed'
    ManagedBy   = 'CN=User 2,CN=Users,DC=contoso,DC=com'
    CommonName  = 'ChangedCN'
}

$mockGetTargetResourceResults = @{
    GroupName         = 'TestGroup'
    CommonName        = 'TestGroup'
    GroupScope        = 'Global'
    Category          = 'Security'
    Path              = 'OU=Test,DC=contoso,DC=com'
    Description       = 'Test AD group description'
    DisplayName       = 'Test display name'
    AdminDescription  = 'Group_'
    Notes             = 'This is a test AD group'
    ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
    DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
    Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
    Ensure            = 'Present'
}

$mockGetTargetResourceResultsAbsent = @{
    GroupName         = 'TestGroup'
    CommonName        = $null
    GroupScope        = $null
    GroupCategory     = $null
    Path              = $null
    Description       = $null
    DisplayName       = $null
    AdminDescription  = $null
    Notes             = $null
    ManagedBy         = $null
    DistinguishedName = $null
    Members           = @()
    Ensure            = 'Absent'
}

$testDomainController = 'TESTDC'

$testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
    'DummyUser',
    $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
)

Describe 'MSFT_ADGroup\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module
    }

    Context 'When the resource is Present' {
        BeforeAll {
            $mockADGroupMembersAsADObjects = @(
                @{
                    DistinguishedName = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                    ObjectGUID        = 'a97cc867-0c9e-4928-8387-0dba0c883b8e'
                    SamAccountName    = 'USER1'
                    ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1106'
                    ObjectClass       = 'user'
                }
                @{
                    DistinguishedName = 'CN=Group 1,CN=Users,DC=contoso,DC=com'
                    ObjectGUID        = 'e2328767-2673-40b2-b3b7-ce9e6511df06'
                    SamAccountName    = 'GROUP1'
                    ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1206'
                    ObjectClass       = 'group'
                }
                @{
                    DistinguishedName = 'CN=Computer 1,CN=Users,DC=contoso,DC=com'
                    ObjectGUID        = '42f9d607-0934-4afc-bb91-bdf93e07cbfc'
                    SamAccountName    = 'COMPUTER1'
                    ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-6606'
                    ObjectClass       = 'computer'
                }
                # This entry is used to represent a group member from a one-way trusted domain
                @{
                    DistinguishedName = 'CN=S-1-5-21-8562719340-2451078396-046517832-2106,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
                    ObjectGUID        = '6df78e9e-c795-4e67-a626-e17f1b4a0d8b'
                    SamAccountName    = 'ADATUM\USER1'
                    ObjectSID         = 'S-1-5-21-8562719340-2451078396-046517832-2106'
                    ObjectClass       = 'foreignSecurityPrincipal'
                }
            )

            Mock -CommandName Get-ADGroup -MockWith {
                @{
                    SamAccountName    = 'TestGroup'
                    CN                = 'TestGroup'
                    GroupScope        = 'Global'
                    GroupCategory     = 'Security'
                    Path              = 'OU=Test,DC=contoso,DC=com'
                    Description       = 'Test AD group description'
                    DisplayName       = 'Test display name'
                    AdminDescription  = 'Group_'
                    Info              = 'This is a test AD group'
                    ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                    DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                    Members           = $mockADGroupMembersAsADObjects.SamAccountName
                }
            }

            Mock -CommandName Get-ADGroupMember -MockWith { $mockADGroupMembersAsADObjects }
        }

        It 'Should return the correct result' {
            $mockParameters = @{
                GroupName = 'TestGroup'
            }

            InModuleScope -Parameters @{
                mockParameters = $mockParameters
            } -ScriptBlock {
                Set-StrictMode -Version 1.0


                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Present'
                $result.GroupName | Should -Be $mockParameters.GroupName
                $result.CommonName | Should -Be 'TestGroup'
                $result.GroupScope | Should -Be 'Global'
                $result.Category | Should -Be 'Security'
                $result.Path | Should -Be 'OU=Test,DC=contoso,DC=com'
                $result.Description | Should -Be 'Test AD group description'
                $result.DisplayName | Should -Be 'Test display name'
                $result.MembersToInclude | Should -BeNullOrEmpty
                $result.MembersToExclude | Should -BeNullOrEmpty
                $result.MembershipAttribute | Should -Be 'SamAccountName'
                $result.ManagedBy | Should -Be 'CN=User 1,CN=Users,DC=contoso,DC=com'
                $result.AdminDescription | Should -Be 'Group_'
                $result.Notes | Should -Be 'This is a test AD group'
                $result.DistinguishedName | Should -Be 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                $result.Members | Should -HaveCount 4
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADGroup -ParameterFilter {
                $Identity -eq $mockParameters.GroupName
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Get-ADGroupMember -ParameterFilter {
                $Identity -eq $mockParameters.GroupName
            } -Exactly -Times 1 -Scope It
        }

        Context 'When the ''Credential'' parameter is specified' {
            It 'Should call the expected mocks' {
                $mockParameters = @{
                    GroupName  = 'TestGroup'
                    Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                InModuleScope -Parameters @{
                    mockParameters = $mockParameters
                } -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    { Get-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-ADGroup -ParameterFilter {
                    $Identity -eq $mockParameters.GroupName -and
                    $Credential -eq $mockParameters.Credential
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Get-ADGroupMember -ParameterFilter {
                    $Identity -eq $mockParameters.GroupName -and
                    $Credential -eq $mockParameters.Credential
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the ''DomainController'' parameter is specified' {
            It 'Should call the expected mocks' {
                $mockParameters = @{
                    GroupName        = 'TestGroup'
                    DomainController = 'TESTDC'
                }

                InModuleScope -Parameters @{
                    mockParameters = $mockParameters
                } -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    { Get-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-ADGroup -ParameterFilter {
                    $Identity -eq $mockParameters.GroupName -and
                    $Server -eq $mockParameters.DomainController
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Get-ADGroupMember -ParameterFilter {
                    $Identity -eq $mockParameters.GroupName -and
                    $Server -eq $mockParameters.DomainController
                } -Exactly -Times 1 -Scope It
            }
        }

        # Context 'When ''Get-ADGroupMember'' fails due to one-way trust' {
        #     BeforeAll {
        #         Mock -CommandName Get-ADGroupMember -MockWith {
        #             throw 'ActiveDirectoryServer:0,Microsoft.ActiveDirectory.Management.Commands.GetADGroupMember'
        #         }

        #         Mock -CommandName Resolve-SamAccountName -ParameterFilter {
        #             $ObjectSID -eq 'S-1-5-21-1131554080-2861379300-292325817-1106'
        #         } -MockWith {
        #             'USER1'
        #         }

        #         Mock -CommandName Get-ADObject -ParameterFilter {
        #             $Filter -like 'USER1'
        #         } -MockWith {
        #             @{
        #                 DistinguishedName = 'CN=User 1,CN=Users,DC=contoso,DC=com'
        #                 ObjectGUID        = 'a97cc867-0c9e-4928-8387-0dba0c883b8e'
        #                 SamAccountName    = 'USER1'
        #                 ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1106'
        #                 ObjectClass       = 'user'
        #             }
        #         }

        #         Mock -CommandName Resolve-SamAccountName -ParameterFilter {
        #             $ObjectSID -eq 'S-1-5-21-1131554080-2861379300-292325817-1206'
        #         } -MockWith {
        #             'GROUP1'
        #         }

        #         Mock -CommandName Get-ADObject -ParameterFilter {
        #             $Filter -eq 'DistinguishedName -eq "GROUP1"' -and
        #             $Properties -eq @('SamAccountName', 'ObjectSID')
        #         } -MockWith {
        #             @{
        #                 DistinguishedName = 'CN=Group 1,CN=Users,DC=contoso,DC=com'
        #                 ObjectGUID        = 'e2328767-2673-40b2-b3b7-ce9e6511df06'
        #                 SamAccountName    = 'GROUP1'
        #                 ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1206'
        #                 ObjectClass       = 'group'
        #             }
        #         }

        #         Mock -CommandName Resolve-SamAccountName -ParameterFilter {
        #             $ObjectSID -eq 'S-1-5-21-1131554080-2861379300-292325817-6606'
        #         } -MockWith {
        #             'COMPUTER1'
        #         }

        #         Mock -CommandName Get-ADObject -ParameterFilter {
        #             $Filter -eq 'DistinguishedName -eq "COMPUTER1"' -and
        #             $Properties -eq @('SamAccountName', 'ObjectSID')
        #         } -MockWith {
        #             @{
        #                 DistinguishedName = 'CN=Computer 1,CN=Users,DC=contoso,DC=com'
        #                 ObjectGUID        = '42f9d607-0934-4afc-bb91-bdf93e07cbfc'
        #                 SamAccountName    = 'COMPUTER1'
        #                 ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-6606'
        #                 ObjectClass       = 'computer'
        #             }
        #         }

        #         Mock -CommandName Resolve-SamAccountName -ParameterFilter {
        #             $ObjectSID -eq 'S-1-5-21-8562719340-2451078396-046517832-2106'
        #         } -MockWith {
        #             'ADATUM\USER1'
        #         }

        #         Mock -CommandName Get-ADObject -ParameterFilter {
        #             $Filter -eq 'DistinguishedName -eq "ADATUM\USER1"' -and
        #             $Properties -eq @('SamAccountName', 'ObjectSID')
        #         } -MockWith {
        #             @{
        #                 DistinguishedName = 'CN=S-1-5-21-8562719340-2451078396-046517832-2106,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
        #                 ObjectGUID        = '6df78e9e-c795-4e67-a626-e17f1b4a0d8b'
        #                 SamAccountName    = 'ADATUM\USER1'
        #                 ObjectSID         = 'S-1-5-21-8562719340-2451078396-046517832-2106'
        #                 ObjectClass       = 'foreignSecurityPrincipal'
        #             }
        #         }
        #     }

        #     Context 'When ''MembershipAttribute'' is ''SamAccountName''' {
        #         It 'Should return the correct result' {
        #             $mockParameters = @{
        #                 GroupName           = 'TestGroup'
        #                 MembershipAttribute = 'SamAccountName'
        #             }

        #             InModuleScope -Parameters @{
        #                 mockParameters = $mockParameters
        #             } -ScriptBlock {
        #                 Set-StrictMode -Version 1.0

        #                 $result = Get-TargetResource @mockParameters

        #                 $result.Members | Should -HaveCount 4
        #             }

        #             Should -Invoke -CommandName Assert-Module -ParameterFilter -Exactly -Times 1 -Scope It
        #             Should -Invoke -CommandName Get-ADGroup -ParameterFilter {
        #                 $Identity -eq $mockParameters.GroupName
        #             } -Exactly -Times 1 -Scope It

        #             Should -Invoke -CommandName Get-ADGroupMember -ParameterFilter {
        #                 $Identity -eq $mockParameters.GroupName
        #             } -Exactly -Times 1 -Scope It
        #         }
        #     }

        #     Context "When 'MembershipAttribute' is 'SID'" {
        #         BeforeAll {
        #             $script:getADObjectCallCount = 0
        #         }

        #         It 'Should return the correct result' {
        #             $getTargetResourceParameters = @{
        #                 GroupName           = 'TestGroup'
        #                 MembershipAttribute = 'SID'
        #             }

        #             $result = Get-TargetResource @getTargetResourceParameters

        #             $result.Members | Should -HaveCount $mockADGroupMembersAsADObjects.Count
        #             foreach ($member in $result.Members)
        #             {
        #                 $mockADGroupMembersAsADObjects.ObjectSID | Should -Contain $member
        #             }
        #         }

        #         It 'Should call the expected mocks' {
        #             Should -Invoke -CommandName Assert-Module -Exactly -Times 1
        #             Should -Invoke -CommandName Get-ADGroup -ParameterFilter { $Identity -eq $getTargetResourceParameters.GroupName } -Exactly -Times 1
        #             Should -Invoke -CommandName Get-ADGroupMember -ParameterFilter { $Identity -eq $getTargetResourceParameters.GroupName } -Exactly -Times 1
        #         }
        #     }
        # }

        Context "When 'Get-ADGroup' throws an exception" {
            BeforeAll {
                Mock -CommandName Get-ADGroup -MockWith { Throw 'Error' }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName = 'TestGroup'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message (
                        $script:localizedData.RetrievingGroupError -f $mockParameters.GroupName
                    )

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }
            }
        }

        Context "When 'Get-ADGroupMember' throws an exception" {
            BeforeAll {
                Mock -CommandName Get-ADGroupMember -MockWith { Throw 'Error' }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName = 'TestGroup'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message (
                        $script:localizedData.RetrievingGroupMembersError -f $mockParameters.GroupName
                    )

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }
            }
        }
    }

    Context 'When the resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-ADGroup -MockWith {
                throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }

            Mock -CommandName Get-ADGroupMember
        }

        It 'Should return the correct result' {
            $mockParameters = @{
                GroupName = 'TestGroup'
            }

            InModuleScope -Parameters @{
                mockParameters = $mockParameters
            } -ScriptBlock {
                Set-StrictMode -Version 1.0


                $result = Get-TargetResource @mockParameters

                $result.Ensure | Should -Be 'Absent'
                $result.GroupName | Should -Be $mockParameters.GroupName
                $result.CommonName | Should -BeNullOrEmpty
                $result.GroupScope | Should -BeNullOrEmpty
                $result.Category | Should -BeNullOrEmpty
                $result.Path | Should -BeNullOrEmpty
                $result.Description | Should -BeNullOrEmpty
                $result.DisplayName | Should -BeNullOrEmpty
                $result.Members | Should -BeNullOrEmpty
                $result.MembersToInclude | Should -BeNullOrEmpty
                $result.MembersToExclude | Should -BeNullOrEmpty
                $result.MembershipAttribute | Should -Be 'SamAccountName'
                $result.ManagedBy | Should -BeNullOrEmpty
                $result.AdminDescription | Should -BeNullOrEmpty
                $result.Notes | Should -BeNullOrEmpty
                $result.DistinguishedName | Should -BeNullOrEmpty
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADGroup -ParameterFilter {
                $Identity -eq $mockParameters.GroupName
            } -Exactly -Times 1 -Scope It

            Should -Invoke -CommandName Get-ADGroupMember -Exactly -Times 0 -Scope It
        }
    }
}

Describe 'MSFT_ADGroup\Test-TargetResource' -Tag 'Test' {
    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    GroupName         = 'TestGroup'
                    CommonName        = 'TestGroup'
                    GroupScope        = 'Global'
                    Category          = 'Security'
                    Path              = 'OU=Test,DC=contoso,DC=com'
                    Description       = 'Test AD group description'
                    DisplayName       = 'Test display name'
                    AdminDescription  = 'Group_'
                    Notes             = 'This is a test AD group'
                    ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                    DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                    Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                    Ensure            = 'Present'
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Present'
                    }

                    { Test-TargetResource @mockParameters } | Should -Not -Throw
                }
            }

            Context 'When the ''Credential'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                            Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        { Test-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $GroupName -eq 'TestGroup' -and
                        $Credential -ne $null
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''DomainController'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                            DomainController = 'TESTDC'
                        }

                        { Test-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                        $GroupName -eq 'TestGroup' -and
                        $DomainController -eq 'TESTDC'
                    } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            Context 'When the ''MembersToInclude'' property is in the desired state' {
                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            MembersToInclude = 'USER1'
                            Ensure           = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            Context 'When the ''MembersToExclude'' property is in the desired state' {
                It 'Should return $true' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            MembersToExclude = 'ExcludedUser'
                            Ensure           = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }
            }

            Context 'When a resource property is not in the desired state' {
                BeforeDiscovery {
                    $testCases = @(
                        @{
                            Property = 'GroupScope'
                            Value    = 'Universal'
                            Remove   = $null
                        }
                        @{
                            Property = 'Description'
                            Value    = 'Test AD group description changed'
                            Remove   = $null
                        }
                        @{
                            Property = 'DisplayName'
                            Value    = 'Test display name changed'
                            Remove   = $null
                        }
                        @{
                            Property = 'ManagedBy'
                            Value    = 'CN=User 2,CN=Users,DC=contoso,DC=com'
                            Remove   = $null
                        }
                        @{
                            Property = 'CommonName'
                            Value    = 'ChangedCN'
                            Remove   = $null
                        }
                        @{
                            Property = 'Members'
                            Value    = 'ChangedUser'
                            Remove   = $null
                        }
                        @{
                            Property = 'MembersToInclude'
                            Value    = 'NotIncludedUser'
                            Remove   = 'Members'
                        }
                        @{
                            Property = 'MembersToExclude'
                            Value    = 'USER1'
                            Remove   = 'Members'
                        }
                    )
                }

                Context 'When the <Property> resource property is not in the desired state' -ForEach $testCases {
                    It 'Should return $false' {
                        InModuleScope -Parameters $_ -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Present'
                            }

                            if ($Remove)
                            {
                                $mockParameters.Remove($Remove)
                            }

                            $mockParameters.$Property = $Value

                            Test-TargetResource @mockParameters | Should -BeFalse
                        }
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $GroupName -eq 'TestGroup'
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    GroupName         = 'TestGroup'
                    CommonName        = $null
                    GroupScope        = $null
                    GroupCategory     = $null
                    Path              = $null
                    Description       = $null
                    DisplayName       = $null
                    AdminDescription  = $null
                    Notes             = $null
                    ManagedBy         = $null
                    DistinguishedName = $null
                    Members           = @()
                    Ensure            = 'Absent'
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should return $false' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Present'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter {
                    $GroupName -eq 'TestGroup'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return $true' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeTrue
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADGroup\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName New-ADGroup
        Mock -CommandName Set-ADGroup
        Mock -CommandName Remove-ADGroup
        Mock -CommandName Move-ADObject
        Mock -CommandName Rename-ADObject
        Mock -CommandName Set-ADCommonGroupMember
        Mock -CommandName Restore-ADCommonObject
    }

    Context 'When the Resource should be Present' {
        Context 'When the Resource is Present' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        GroupName         = 'TestGroup'
                        CommonName        = 'TestGroup'
                        GroupScope        = 'Global'
                        Category          = 'Security'
                        Path              = 'OU=Test,DC=contoso,DC=com'
                        Description       = 'Test AD group description'
                        DisplayName       = 'Test display name'
                        AdminDescription  = 'Group_'
                        Notes             = 'This is a test AD group'
                        ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                        Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure            = 'Present'
                    }
                }
            }

            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'GroupScope'
                        Value    = 'Universal'
                    }
                    @{
                        Property = 'Description'
                        Value    = 'Test AD group description changed'
                    }
                    @{
                        Property = 'DisplayName'
                        Value    = 'Test display name changed'
                    }
                    @{
                        Property = 'ManagedBy'
                        Value    = 'CN=User 2,CN=Users,DC=contoso,DC=com'
                    }
                    @{
                        Property = 'CommonName'
                        Value    = 'ChangedCN'
                    }
                )
            }

            Context 'When property ''<Property>'' has changed' -ForEach $testCases {
                It 'Should call the expected mocks' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockProperties = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        $mockProperties.$Property = $Value

                        { Set-TargetResource @mockProperties } | Should -Not -Throw
                    }

                    if ($Property -eq 'CommonName')
                    {
                        Should -Invoke -CommandName Rename-ADObject -ParameterFilter { $NewName -eq 'ChangedCN' } -Exactly -Times 1
                    }
                    else
                    {
                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADGroup -ParameterFilter { $null -ne (Get-Variable -Name $Property -ValueOnly) } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Move-ADObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When the ''Path'' property has changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Changed,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Move-ADObject -ParameterFilter {
                        $TargetPath -eq 'OU=Changed,DC=contoso,DC=com'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                }

                Context "When 'Move-ADObject' throws an unexpected exception" {
                    BeforeAll {
                        Mock -CommandName Move-ADObject -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Changed,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Present'
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message (
                                $script:localizedData.MovingGroupError -f $mockParameters.GroupName,
                                $mockParameters.Path,
                                $mockParameters.Path
                            )

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }

            Context 'When the ''Category'' property has changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Distribution'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                        $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                        $GroupCategory -eq 'Distribution'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''GroupScope'' property has changed' {
                Context 'When the ''GroupScope'' property was ''Global'' and has changed to ''Domain Local''' {
                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'DomainLocal'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Present'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                            $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                            $GroupScope -eq 'Universal'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                            $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                            $GroupScope -eq 'DomainLocal'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                    }
                }

                Context 'When the ''GroupScope'' property was ''DomainLocal'' and has changed to ''Global''' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            @{
                                GroupName         = 'TestGroup'
                                CommonName        = 'TestGroup'
                                GroupScope        = 'DomainLocal'
                                Category          = 'Security'
                                Path              = 'OU=Test,DC=contoso,DC=com'
                                Description       = 'Test AD group description'
                                DisplayName       = 'Test display name'
                                AdminDescription  = 'Group_'
                                Notes             = 'This is a test AD group'
                                ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                                Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure            = 'Present'
                            }
                        }
                    }

                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Present'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                            $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                            $GroupScope -eq 'Universal'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                            $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                            $GroupScope -eq 'Global'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                    }

                    Context 'When the ''Credential'' parameter is specified' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    GroupName        = 'TestGroup'
                                    CommonName       = 'TestGroup'
                                    GroupScope       = 'Global'
                                    Category         = 'Security'
                                    Path             = 'OU=Test,DC=contoso,DC=com'
                                    Description      = 'Test AD group description changed'
                                    DisplayName      = 'Test display name'
                                    ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                    AdminDescription = 'Group_'
                                    Notes            = 'This is a test AD group'
                                    Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                    Ensure           = 'Present'
                                    Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                        'DummyUser',
                                        $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                                    )
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                                $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                                $GroupScope -eq 'Universal' -and
                                $null -ne $Credential
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When the ''DomainController'' parameter is specified' {
                        It 'Should call the expected mocks' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    GroupName        = 'TestGroup'
                                    CommonName       = 'TestGroup'
                                    GroupScope       = 'Global'
                                    Category         = 'Security'
                                    Path             = 'OU=Test,DC=contoso,DC=com'
                                    Description      = 'Test AD group description changed'
                                    DisplayName      = 'Test display name'
                                    ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                    AdminDescription = 'Group_'
                                    Notes            = 'This is a test AD group'
                                    Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                    Ensure           = 'Present'
                                    DomainController = 'TESTDC'
                                }

                                { Set-TargetResource @mockParameters } | Should -Not -Throw
                            }

                            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                            Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                                $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                                $GroupScope -eq 'Universal' -and
                                $Server -eq 'TESTDC'
                            } -Exactly -Times 1 -Scope It
                        }
                    }

                    Context 'When ''Set-ADGroup'' throws an unexpected exception' {
                        BeforeAll {
                            Mock -CommandName Set-ADGroup -ParameterFilter { $GroupScope -eq 'Universal' } -MockWith { throw 'UnexpectedError' }
                        }

                        It 'Should throw the correct exception' {
                            InModuleScope -ScriptBlock {
                                Set-StrictMode -Version 1.0

                                $mockParameters = @{
                                    GroupName        = 'TestGroup'
                                    CommonName       = 'TestGroup'
                                    GroupScope       = 'Global'
                                    Category         = 'Security'
                                    Path             = 'OU=Test,DC=contoso,DC=com'
                                    Description      = 'Test AD group description changed'
                                    DisplayName      = 'Test display name'
                                    ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                    AdminDescription = 'Group_'
                                    Notes            = 'This is a test AD group'
                                    Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                    Ensure           = 'Present'
                                    DomainController = 'TESTDC'
                                }

                                $errorRecord = Get-InvalidOperationRecord -Message (
                                    $script:localizedData.SettingGroupError -f
                                    $mockParameters.GroupName
                                )

                                { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                            }
                        }
                    }
                }
            }

            Context 'When the ''Notes'' property has changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'Changed Notes'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                        $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                         (Get-Variable -Name Replace -ValueOnly).Info -eq 'Changed Notes'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''AdminDescription'' property has changed' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Changed Admin Description'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                        $Identity -eq 'CN=TestGroup,OU=Test,DC=contoso,DC=com' -and
                         (Get-Variable -Name Replace -ValueOnly).adminDescription -eq 'Changed Admin Description'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''Members'' property has changed' {
                Context 'When the ''Members'' property has members to add' {
                    It 'Should call the expected mocks' {
                        $changedMembers = @('ChangedMember1', 'ChangedMember2')

                        InModuleScope -Parameters @{
                            changedMembers = $changedMembers
                        } -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1') + $changedMembers
                                Ensure           = 'Present'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                            $Members.Count -eq $changedMembers.Count -and
                            $Members -contains $changedMembers[0] -and
                            $Members -contains $changedMembers[1] -and
                            $Action -eq 'Add'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When the ''Members'' property has members to remove' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                        $Members.Count -eq 2 -and
                        $Members -contains 'COMPUTER1' -and
                        $Action -eq 'Remove'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''Members'' property is specified as empty' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @()
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                        $Members.Count -eq 4
                        $Action -eq 'Remove'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context "When the resource 'Members' value is empty" {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            GroupName         = 'TestGroup'
                            CommonName        = 'TestGroup'
                            GroupScope        = 'Global'
                            Category          = 'Security'
                            Path              = 'OU=Test,DC=contoso,DC=com'
                            Description       = 'Test AD group description'
                            DisplayName       = 'Test display name'
                            AdminDescription  = 'Group_'
                            Notes             = 'This is a test AD group'
                            ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                            Members           = @()
                            Ensure            = 'Present'
                        }
                    }
                }

                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                        $Members.Count -eq 4 -and
                        $Action -eq 'Add'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''MembersToInclude'' property is not in the desired state' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            MembersToInclude = @('IncludeUser')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                        $Members -contains 'IncludeUser' -and
                        $Action -eq 'Add'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }

                Context 'When the resource ''Members'' value is empty' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            @{
                                GroupName         = 'TestGroup'
                                CommonName        = 'TestGroup'
                                GroupScope        = 'Global'
                                Category          = 'Security'
                                Path              = 'OU=Test,DC=contoso,DC=com'
                                Description       = 'Test AD group description'
                                DisplayName       = 'Test display name'
                                AdminDescription  = 'Group_'
                                Notes             = 'This is a test AD group'
                                ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                                Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure            = 'Present'
                            }
                        }
                    }

                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                MembersToInclude = @('IncludeUser')
                                Ensure           = 'Present'
                            }
                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                            $Members -contains 'IncludeUser' -and
                            $Action -eq 'Add'
                        } -Exactly -Times 1 -Scope It

                        Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When the ''MembersToExclude'' property is not in the desired state' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            MembersToExclude = @('USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                        $Members -contains 'USER1' -and
                        $Action -eq 'Remove'
                    } -Exactly -Times 1 -Scope It

                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }

                Context 'When the resource ''Members'' value is empty' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith {
                            @{
                                GroupName         = 'TestGroup'
                                CommonName        = 'TestGroup'
                                GroupScope        = 'Global'
                                Category          = 'Security'
                                Path              = 'OU=Test,DC=contoso,DC=com'
                                Description       = 'Test AD group description'
                                DisplayName       = 'Test display name'
                                AdminDescription  = 'Group_'
                                Notes             = 'This is a test AD group'
                                ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                                Members           = @()
                                Ensure            = 'Present'
                            }
                        }
                    }

                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                MembersToExclude = @('USER1')
                                Ensure           = 'Present'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                        Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    }
                }
            }

            Context 'When the ''Credential'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description changed'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                            Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''DomainController'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description changed'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                            DomainController = 'TESTDC'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -ParameterFilter { $Server -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When ''Set-ADGroup'' throws an unexpected error' {
                BeforeAll {
                    Mock -CommandName Set-ADGroup -MockWith { throw 'UnexpectedError' }
                }

                It 'Should throw the correct exception' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description changed'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        $errorRecord = Get-InvalidOperationRecord -Message (
                            $script:localizedData.SettingGroupError -f
                            $mockParameters.GroupName)

                        { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                    }
                }
            }

            Context 'When the Resource is in the desired state' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                }
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    GroupName         = 'TestGroup'
                    CommonName        = $null
                    GroupScope        = $null
                    GroupCategory     = $null
                    Path              = $null
                    Description       = $null
                    DisplayName       = $null
                    AdminDescription  = $null
                    Notes             = $null
                    ManagedBy         = $null
                    DistinguishedName = $null
                    Members           = @()
                    Ensure            = 'Absent'
                }
            }
        }

        It 'Should call the expected mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    GroupName        = 'TestGroup'
                    CommonName       = 'TestGroup'
                    GroupScope       = 'Global'
                    Category         = 'Security'
                    Path             = 'OU=Test,DC=contoso,DC=com'
                    Description      = 'Test AD group description'
                    DisplayName      = 'Test display name'
                    ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                    AdminDescription = 'Group_'
                    Notes            = 'This is a test AD group'
                    Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                    Ensure           = 'Present'
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName New-ADGroup -ParameterFilter { $Name -eq 'TestGroup' } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Remove-ADgroup -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
        }

        Context 'When the ''RestoreFromRecycleBin'' parameter is specified' {
            BeforeAll {
                Mock -CommandName Restore-ADCommonObject -MockWith { $true }
            }

            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName             = 'TestGroup'
                        CommonName            = 'TestGroup'
                        GroupScope            = 'Global'
                        Category              = 'Security'
                        Path                  = 'OU=Test,DC=contoso,DC=com'
                        Description           = 'Test AD group description'
                        DisplayName           = 'Test display name'
                        ManagedBy             = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription      = 'Group_'
                        Notes                 = 'This is a test AD group'
                        Members               = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure                = 'Present'
                        RestoreFromRecycleBin = $true
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter { $Identity -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
            }

            Context "When 'Restore-ADCommonObject' does not return an object" {
                BeforeAll {
                    Mock -CommandName Restore-ADCommonObject
                }

                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName             = 'TestGroup'
                            CommonName            = 'TestGroup'
                            GroupScope            = 'Global'
                            Category              = 'Security'
                            Path                  = 'OU=Test,DC=contoso,DC=com'
                            Description           = 'Test AD group description'
                            DisplayName           = 'Test display name'
                            ManagedBy             = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription      = 'Group_'
                            Notes                 = 'This is a test AD group'
                            Members               = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure                = 'Present'
                            RestoreFromRecycleBin = $true
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter { $Identity -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADGroup -ParameterFilter { $Name -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                }
            }

            Context 'When the ''Credential'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName             = 'TestGroup'
                            CommonName            = 'TestGroup'
                            GroupScope            = 'Global'
                            Category              = 'Security'
                            Path                  = 'OU=Test,DC=contoso,DC=com'
                            Description           = 'Test AD group description'
                            DisplayName           = 'Test display name'
                            ManagedBy             = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription      = 'Group_'
                            Notes                 = 'This is a test AD group'
                            Members               = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure                = 'Present'
                            RestoreFromRecycleBin = $true
                            Credential            = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                'DummyUser',
                                $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                            )
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the ''DomainController'' parameter is specified' {
                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName             = 'TestGroup'
                            CommonName            = 'TestGroup'
                            GroupScope            = 'Global'
                            Category              = 'Security'
                            Path                  = 'OU=Test,DC=contoso,DC=com'
                            Description           = 'Test AD group description'
                            DisplayName           = 'Test display name'
                            ManagedBy             = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription      = 'Group_'
                            Notes                 = 'This is a test AD group'
                            Members               = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure                = 'Present'
                            RestoreFromRecycleBin = $true
                            DomainController      = 'TESTDC'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -ParameterFilter { $Server -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When the ''Credential'' parameter is specified' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Present'
                        Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'DummyUser',
                            $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADGroup -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the ''DomainController'' parameter is specified' {
            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Present'
                        DomainController = 'TESTDC'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADGroup -ParameterFilter { $Server -eq 'TESTDC' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When ''New-ADGroup'' throws an unexpected error' {
            BeforeAll {
                Mock -CommandName New-ADGroup -MockWith { throw 'UnexpectedError' }
            }

            It 'Should throw the correct exception' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Present'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.AddingGroupError -f $mockParameters.GroupName)

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                }
            }
        }

        Context 'When the ''MembersToInclude'' property is specified' {
            BeforeAll {
                $script:membersToInclude = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
            }

            It 'Should call the expected mocks' {
                InModuleScope -Parameters @{
                    members = $script:membersToInclude
                } -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'TestGroup'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        MembersToInclude = $members
                        Ensure           = 'Present'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADGroup -ParameterFilter { $Name -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADCommonGroupMember -ParameterFilter {
                    $Members.Count -eq $membersToInclude.Count -and
                    $Members -contains $membersToInclude[0] -and
                    $Members -contains $membersToInclude[1] -and
                    $Members -contains $membersToInclude[2] -and
                    $Members -contains $membersToInclude[3] -and
                    $Action -eq 'Add'
                } -Exactly -Times 1 -Scope It

                Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
            }
        }

        Context 'When creating a new group with a different CommonName' {
            BeforeAll {
                Mock -CommandName New-ADGroup -MockWith {
                    @{
                        DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                    }
                }
            }

            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        GroupName        = 'TestGroup'
                        CommonName       = 'ChangedCN'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        Path             = 'OU=Test,DC=contoso,DC=com'
                        Description      = 'Test AD group description'
                        DisplayName      = 'Test display name'
                        ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                        AdminDescription = 'Group_'
                        Notes            = 'This is a test AD group'
                        Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                        Ensure           = 'Present'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Rename-ADObject -ParameterFilter { $NewName -eq 'ChangedCN' } -Exactly -Times 1 -Scope It
            }
        }


        Context 'When the Resource should be Absent' {
            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            GroupName         = 'TestGroup'
                            CommonName        = 'TestGroup'
                            GroupScope        = 'Global'
                            Category          = 'Security'
                            Path              = 'OU=Test,DC=contoso,DC=com'
                            Description       = 'Test AD group description'
                            DisplayName       = 'Test display name'
                            AdminDescription  = 'Group_'
                            Notes             = 'This is a test AD group'
                            ManagedBy         = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            DistinguishedName = 'CN=TestGroup,OU=Test,DC=contoso,DC=com'
                            Members           = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure            = 'Present'
                        }
                    }
                }

                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Absent'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -ParameterFilter { $Identity -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }

                Context 'When the ''Credential'' parameter is specified' {
                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Absent'
                                Credential       = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                                    'DummyUser',
                                    $(ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                                )
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Remove-ADGroup -ParameterFilter { $null -ne $Credential } -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When the ''DomainController'' parameter is specified' {
                    It 'Should call the expected mocks' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Absent'
                                DomainController = 'TESTDC'
                            }

                            { Set-TargetResource @mockParameters } | Should -Not -Throw
                        }

                        Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                        Should -Invoke -CommandName Remove-ADGroup -ParameterFilter { $Server -eq 'TESTDC' } -Exactly -Times 1 -Scope It
                    }
                }

                Context 'When ''Remove-ADGroup'' throws an unexpected error' {
                    BeforeAll {
                        Mock -CommandName Remove-ADGroup -MockWith { throw 'UnexpectedError' }
                    }

                    It 'Should throw the correct exception' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                GroupName        = 'TestGroup'
                                CommonName       = 'TestGroup'
                                GroupScope       = 'Global'
                                Category         = 'Security'
                                Path             = 'OU=Test,DC=contoso,DC=com'
                                Description      = 'Test AD group description'
                                DisplayName      = 'Test display name'
                                ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                                AdminDescription = 'Group_'
                                Notes            = 'This is a test AD group'
                                Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                                Ensure           = 'Absent'
                            }

                            $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RemovingGroupError -f $mockParameters.GroupName)

                            { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord.Message
                        }
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith {
                        @{
                            GroupName         = 'TestGroup'
                            CommonName        = $null
                            GroupScope        = $null
                            GroupCategory     = $null
                            Path              = $null
                            Description       = $null
                            DisplayName       = $null
                            AdminDescription  = $null
                            Notes             = $null
                            ManagedBy         = $null
                            DistinguishedName = $null
                            Members           = @()
                            Ensure            = 'Absent'
                        }
                    }
                }

                It 'Should call the expected mocks' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            GroupName        = 'TestGroup'
                            CommonName       = 'TestGroup'
                            GroupScope       = 'Global'
                            Category         = 'Security'
                            Path             = 'OU=Test,DC=contoso,DC=com'
                            Description      = 'Test AD group description'
                            DisplayName      = 'Test display name'
                            ManagedBy        = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                            AdminDescription = 'Group_'
                            Notes            = 'This is a test AD group'
                            Members          = @('USER1', 'GROUP1', 'COMPUTER1', 'ADATUM\USER1')
                            Ensure           = 'Absent'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $GroupName -eq 'TestGroup' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADCommonGroupMember -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName New-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Set-ADGroup -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Restore-ADCommonObject -Exactly -Times 0 -Scope It
                }
            }
        }
    }
}
