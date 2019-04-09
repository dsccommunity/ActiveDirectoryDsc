[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]

#region HEADER
$script:DSCModuleName      = 'xActiveDirectory'
$script:DSCResourceName    = 'MSFT_xADManagedServiceAccount'

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment  `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit
#endregion HEADER

function Invoke-TestSetup
{
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope $script:DSCResourceName {
        $mockPath               = 'OU=Fake,DC=contoso,DC=com'
        $mockDomainController   = 'MockDC'
        $mockCredentials        = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        $mockADUSer = @{
            SamAccountName    = 'User1'
            DistinguishedName = 'CN=User1,OU=Fake,DC=contoso,DC=com'
            Enabled           = $true
            SID               = 'S-1-5-21-1409167834-891301383-2860967316-1142'
            ObjectGUID        = '91bffe90-4c84-4026-b1fc-d03671ff56ab'
            GivenName         = ''
            Name              = 'User1'
        }

        $mockADComputer = @{
            SamAccountName    = 'Node1$'
            DistinguishedName = 'CN=Node1,OU=Fake,DC=contoso,DC=com'
            Enabled           = $true
            SID               = 'S-1-5-21-1409167834-891301383-2860967316-1143'
            ObjectClass       = 'computer'
            ObjectGUID        = '91bffe90-4c84-4026-b1fc-d03671ff56ac'
            DnsHostName       = 'Node1.fake.contoso.com'
        }

        $mockSingleServiceAccount = @{
            Name              = 'TestSMSA'
            DistinguishedName = "CN={0},{1}" -f ('TestSMSA', $mockPath)
            Description       = 'Dummy single service account for unit testing'
            DisplayName       = ''
            ObjectClass       = 'msDS-ManagedServiceAccount'
            Enabled           = $true
        }

        $mockGroupServiceAccount = @{
            Name              = 'TestGMSA'
            DistinguishedName = "CN={0},{1}" -f ('TestGMSA', $mockPath)
            Description       = 'Dummy group service account for unit testing'
            DisplayName       = ''
            ObjectClass       = 'msDS-GroupManagedServiceAccount'
            Enabled           = $true
            PrincipalsAllowedToRetrieveManagedPassword = @($mockADUSer.DistinguishedName, $mockADComputer.DistinguishedName)
        }

        #region Function Get-TargetResource
        Describe -Name "MSFT_xADManagedServiceAccount\Get-TargetResource" -Tag 'Get' {
            Context 'When the system uses specific parameters' {
                Mock -CommandName Assert-Module -ParameterFilter {
                    $ModuleName -eq 'ActiveDirectory'
                }

                Mock -CommandName Get-ADServiceAccount -MockWith {
                    return $mockSingleServiceAccount
                }

                It 'Should call "Assert-Module" to check AD module is installed' {
                    $testResourceParametersSingle = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                    }

                    $null = Get-TargetResource @testResourceParametersSingle

                    Assert-MockCalled -CommandName Assert-Module -ParameterFilter {
                        $ModuleName -eq 'ActiveDirectory'
                    } -Scope It -Exactly -Times 1
                }

                It 'Should call "Get-ADServiceAccount" with "Server" parameter when "DomainController" specified' {
                    $testResourceParametersWithServer = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                        DomainController   = $mockDomainController
                    }

                    $null = Get-TargetResource  @testResourceParametersWithServer

                    Assert-MockCalled -CommandName Get-ADServiceAccount -ParameterFilter {
                        $Server -eq $mockDomainController
                    } -Scope It -Exactly -Times 1
                }

                It 'Should call "Get-ADServiceAccount" with "Credential" parameter when specified' {
                    $testResourceParametersWithCredentials = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                        Credential         = $mockCredentials
                    }
                    $null = Get-TargetResource  @testResourceParametersWithCredentials

                    Assert-MockCalled -CommandName Get-ADServiceAccount -ParameterFilter {
                        $Credential -eq $mockCredentials
                    } -Scope It -Exactly -Times 1
                }
            }

            Context 'When system cannot connect to domain or other errors' {
                Mock -CommandName Get-ADServiceAccount -MockWith {
                    throw 'Microsoft.ActiveDirectory.Management.ADServerDownException'
                }

                It 'Should call "Get-ADServiceAccount" and throw an error when catching any other errors besides "Account Not Found"'{
                    $getTargetResourceParameters = @{
                        ServiceAccountName = $testPresentParams.ServiceAccountName
                    }

                    { $null = Get-TargetResource  @getTargetResourceParameters -ErrorAction 'SilentlyContinue' } | Should Throw
                }
            }

            Context 'When the system is in desired state (sMSA)' {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockSingleServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockSingleServiceAccount
                }

                It 'Should mock call to Get-ADServiceAccount return identical information' {
                    $testResourceParametersSingle = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                    }

                    $getTargetResourceResult = Get-TargetResource @testResourceParametersSingle

                    $getTargetResourceResult.ServiceAccountName | Should -Be $mockSingleServiceAccount.Name
                    $getTargetResourceResult.Ensure | Should -Be 'Present'
                    $getTargetResourceResult.AccountType | Should -Be 'Single'
                    $getTargetResourceResult.Description | Should -Be $mockSingleServiceAccount.Description
                    $getTargetResourceResult.DisplayName | Should -Be $mockSingleServiceAccount.DisplayName
                    $getTargetResourceResult.Members | Should -Be @()
                    $getTargetResourceResult.Path | Should -Be $mockPath
                }
            }

            Context 'When the system is in desired state (gMSA)' {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockGroupServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockGroupServiceAccount
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADComputer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADComputer
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADUSer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADUser
                }

                It 'Should mock call to Get-ADServiceAccount return identical information' {
                    $testResourceParametersGroup = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SamAccountName'
                    }

                    $getTargetResourceResult = Get-TargetResource @testResourceParametersGroup

                    $getTargetResourceResult.ServiceAccountName | Should -Be $mockGroupServiceAccount.Name
                    $getTargetResourceResult.Ensure | Should -Be 'Present'
                    $getTargetResourceResult.AccountType | Should -Be 'Group'
                    $getTargetResourceResult.Description | Should -Be $mockGroupServiceAccount.Description
                    $getTargetResourceResult.DisplayName | Should -Be $mockGroupServiceAccount.DisplayName
                    $getTargetResourceResult.Members | Should -Be `
                        @($mockADUSer.($testResourceParametersGroup.MembershipAttribute), `
                          $mockADComputer.($testResourceParametersGroup.MembershipAttribute))
                    $getTargetResourceResult.Path | Should -Be $mockPath
                }
            }

            Context -Name 'When the system is not in the desired state (Both)' {
                BeforeAll {
                    Mock -CommandName Get-ADServiceAccount -MockWith {
                        throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                    }

                    $testResourceParametersSingle = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                    }

                    $getTargetResourceResult = Get-TargetResource @testResourceParametersSingle
                }

                It "Should return 'Ensure' is 'Absent'" {
                    $getTargetResourceResult.Ensure | Should Be 'Absent'
                }

                It "Should return 'ServiceAccountName' when 'Absent'" {
                    $getTargetResourceResult.ServiceAccountName | Should -Not -BeNullOrEmpty
                    $getTargetResourceResult.ServiceAccountName | Should -BeExactly $testResourceParametersSingle.ServiceAccountName
                }
            }
        }
        #endregion Function Get-TargetResource

        #region Function Compare-TargetResourceState
        Describe -Name "MSFT_xADManagedServiceAccount\Compare-TargetResourceState" -Tag 'Compare' {
            Context -Name 'When the system is in the desired state (sMSA)' {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockSingleServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockSingleServiceAccount
                }

                $testResourceParametersSingle = @{
                    ServiceAccountName = $mockSingleServiceAccount.Name
                    AccountType        = 'Single'
                    Path               = $mockPath
                    Description        = $mockSingleServiceAccount.Description
                    Ensure             = 'Present'
                    DisplayName        = $mockSingleServiceAccount.DisplayName
                }

                $getTargetResourceResult = Compare-TargetResourceState @testResourceParametersSingle
                $testCases = @()
                $getTargetResourceResult | ForEach-Object {
                    $testCases += @{
                        Parameter = $_.Parameter
                        Expected  = $_.Expected
                        Actual    = $_.Actual
                        Pass      = $_.Pass
                    }
                }

                It "Should return identical information for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Expected,

                        [Parameter()]
                        $Actual,

                        [Parameter()]
                        $Pass
                    )

                    $Expected | Should -BeExactly $Actual
                    $Pass | Should -BeTrue
                }

            }

            Context -Name 'When the system is in the desired state (gMSA)' {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockGroupServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockGroupServiceAccount
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADComputer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADComputer
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADUSer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADUser
                }

                $testResourceParametersGroup = @{
                    ServiceAccountName  = $mockGroupServiceAccount.Name
                    MembershipAttribute = 'SamAccountName'
                    AccountType         = 'Group'
                    Path                = $mockPath
                    Description         = $mockGroupServiceAccount.Description
                    Ensure              = 'Present'
                    Members             = 'Node1$', 'User1'
                    DisplayName         = $mockGroupServiceAccount.DisplayName
                }

                $getTargetResourceResult = Compare-TargetResourceState @testResourceParametersGroup
                $testCases = @()
                $getTargetResourceResult | ForEach-Object {
                    $testCases += @{
                        Parameter = $_.Parameter
                        Expected  = $_.Expected
                        Actual    = $_.Actual
                        Pass      = $_.Pass
                    }
                }

                It "Should return identical information for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Expected,

                        [Parameter()]
                        $Actual,

                        [Parameter()]
                        $Pass
                    )

                    $Expected | Should -BeExactly $Actual
                    $Pass | Should -BeTrue
                }

                It "Should return identical information for 'Members' when using 'SamAccountName'" {
                    $testResourceParametersGroupSAM = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SamAccountName'
                        Members             = 'Node1$', 'User1'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultSAM  = Compare-TargetResourceState @testResourceParametersGroupSAM

                    $getTargetResourceResultSAM.Expected | Should -BeExactly $getTargetResourceResultSAM.Actual
                    $getTargetResourceResultSAM.Pass | Should -BeTrue
                }

                It "Should return identical information for 'Members' when using 'DistinguishedName'" {
                    $testResourceParametersGroupDN = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'DistinguishedName'
                        Members             = 'CN=Node1,OU=Fake,DC=contoso,DC=com', 'CN=User1,OU=Fake,DC=contoso,DC=com'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultDN  = Compare-TargetResourceState @testResourceParametersGroupDN

                    $getTargetResourceResultDN.Expected | Should -BeExactly $getTargetResourceResultDN.Actual
                    $getTargetResourceResultDN.Pass | Should -BeTrue
                }

                It "Should return identical information for 'Members' when using 'SID'" {
                    $testResourceParametersGroupSID = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SID'
                        Members             = 'S-1-5-21-1409167834-891301383-2860967316-1143', 'S-1-5-21-1409167834-891301383-2860967316-1142'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultSID  = Compare-TargetResourceState @testResourceParametersGroupSID

                    $getTargetResourceResultSID.Expected | Should -BeExactly $getTargetResourceResultSID.Actual
                    $getTargetResourceResultSID.Pass | Should -BeTrue
                }

                It "Should return identical information for 'Members' when using 'ObjectGUID'" {
                    $testResourceParametersGroupGUID = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'ObjectGUID'
                        Members             = '91bffe90-4c84-4026-b1fc-d03671ff56ac', '91bffe90-4c84-4026-b1fc-d03671ff56ab'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultGUID  = Compare-TargetResourceState @testResourceParametersGroupGUID

                    $getTargetResourceResultGUID.Expected | Should -BeExactly $getTargetResourceResultGUID.Actual
                    $getTargetResourceResultGUID.Pass | Should -BeTrue
                }
            }

            Context -Name 'When the system is NOT in the desired state (sMSA)' {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockSingleServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockSingleServiceAccount
                }

                $testResourceParametersSingleNotCompliant = @{
                    ServiceAccountName = $mockSingleServiceAccount.Name
                    AccountType        = 'Group'
                    Path               = 'OU=FakeWrong,DC=contoso,DC=com'
                    Description        = 'Test MSA description Wrong'
                    Ensure             = 'Absent'
                    DisplayName        = 'WrongDisplayName'
                }

                $getTargetResourceResult = Compare-TargetResourceState @testResourceParametersSingleNotCompliant
                $testCases = @()
                # Need to remove parameters that will always be true
                $getTargetResourceResult = $getTargetResourceResult | Where-Object {
                    $_.Parameter -ne 'ServiceAccountName' -and
                    $_.Parameter -ne 'DistinguishedName' -and
                    $_.Parameter -ne 'MembershipAttribute'
                }

                $getTargetResourceResult | ForEach-Object {
                    $testCases += @{
                        Parameter = $_.Parameter
                        Expected  = $_.Expected
                        Actual    = $_.Actual
                        Pass      = $_.Pass
                    }
                }

                It "Should return false for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Expected,

                        [Parameter()]
                        $Actual,

                        [Parameter()]
                        $Pass
                    )

                    $Expected | Should -Not -Be $Actual
                    $Pass | Should -BeFalse
                }

            }

            Context -Name 'When the system is NOT in the desired state (gMSA)' {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockGroupServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockGroupServiceAccount
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADComputer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADComputer
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADUSer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADUser
                }

                $testResourceParametersGroup = @{
                    ServiceAccountName = $mockGroupServiceAccount.Name
                    AccountType        = 'Single'
                    Path               = 'OU=FakeWrong,DC=contoso,DC=com'
                    Description        = 'Test MSA description Wrong'
                    Ensure             = 'Absent'
                    DisplayName        = 'WrongDisplayName'
                }

                $getTargetResourceResult = Compare-TargetResourceState @testResourceParametersGroup
                $testCases = @()
                # Need to remove parameters that will always be true
                $getTargetResourceResult = $getTargetResourceResult | Where-Object {
                    $_.Parameter -ne 'ServiceAccountName' -and
                    $_.Parameter -ne 'DistinguishedName' -and
                    $_.Parameter -ne 'MembershipAttribute'
                }
                $getTargetResourceResult | ForEach-Object {
                    $testCases += @{
                        Parameter = $_.Parameter
                        Expected  = $_.Expected
                        Actual    = $_.Actual
                        Pass      = $_.Pass
                    }
                }

                It "Should return false for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Expected,

                        [Parameter()]
                        $Actual,

                        [Parameter()]
                        $Pass
                    )

                    $Expected | Should -Not -Be $Actual
                    $Pass | Should -BeFalse
                }

                It "Should return false for 'Members' when using 'SamAccountName'" {
                    $testResourceParametersGroupSAM = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SamAccountName'
                        Members             = 'Node1$'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultSAM  = Compare-TargetResourceState @testResourceParametersGroupSAM

                    $membersState = $getTargetResourceResultSAM | Where-Object {$_.Parameter -eq 'Members'}
                    $membersState.Expected | Should -Not -BeExactly $membersState.Actual
                    $membersState.Pass | Should -BeFalse
                }

                It "Should return false for 'Members' when using 'DistinguishedName'" {
                    $testResourceParametersGroupDN = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'DistinguishedName'
                        Members             = 'CN=Node1,OU=Fake,DC=contoso,DC=com'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultDN  = Compare-TargetResourceState @testResourceParametersGroupDN

                    $membersState = $getTargetResourceResultDN | Where-Object {$_.Parameter -eq 'Members'}
                    $membersState.Expected | Should -Not -BeExactly $membersState.Actual
                    $membersState.Pass | Should -BeFalse
                }

                It "Should return false for 'Members' when using 'SID'" {
                    $testResourceParametersGroupSID = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SID'
                        Members             = 'S-1-5-21-1409167834-891301383-2860967316-1143'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultSID  = Compare-TargetResourceState @testResourceParametersGroupSID

                    $membersState = $getTargetResourceResultSID | Where-Object {$_.Parameter -eq 'Members'}
                    $membersState.Expected | Should -Not -BeExactly $membersState.Actual
                    $membersState.Pass | Should -BeFalse
                }

                It "Should return false for 'Members' when using 'ObjectGUID'" {
                    $testResourceParametersGroupGUID = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'ObjectGUID'
                        Members             = '91bffe90-4c84-4026-b1fc-d03671ff56ac'
                        AccountType         = 'Group'
                    }

                    $getTargetResourceResultGUID  = Compare-TargetResourceState @testResourceParametersGroupGUID

                    $membersState = $getTargetResourceResultGUID | Where-Object {$_.Parameter -eq 'Members'}
                    $membersState.Expected | Should -Not -BeExactly $membersState.Actual
                    $membersState.Pass | Should -BeFalse
                }
            }
        }
        #endregion Function Compare-TargetResourceState

        #region Function Test-TargetResource
        Describe -Name "MSFT_xADManagedServiceAccount\Test-TargetResource" {
            BeforeAll {
                Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }
            }

            Context -Name "When the system is in the desired state and 'Ensure' is 'Present' (sMSA)" {
                It "Should pass when the Parameters are properly set" {
                    Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                        $mockSingleServiceAccount.Name -eq $Identity
                    } -MockWith {
                        return $mockSingleServiceAccount
                    }

                    $testResourceParametersSingle = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                        AccountType        = 'Single'
                        Path               = $mockPath
                        Description        = $mockSingleServiceAccount.Description
                        Ensure             = 'Present'
                        DisplayName        = ''
                    }

                    Test-TargetResource @testResourceParametersSingle | Should Be $true
                }
            }

            Context -Name "When the system is in the desired state and 'Ensure' is 'Present' (gMSA)" {
                It "Should pass when the Parameters are properly set" {
                    Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                        $mockGroupServiceAccount.Name -eq $Identity
                    } -MockWith {
                        return $mockGroupServiceAccount
                    }

                    Mock -CommandName Get-ADObject -ParameterFilter {
                        $mockADComputer.DistinguishedName -eq $Identity
                    } -MockWith {
                        return $mockADComputer
                    }

                    Mock -CommandName Get-ADObject -ParameterFilter {
                        $mockADUSer.DistinguishedName -eq $Identity
                    } -MockWith {
                        return $mockADUser
                    }

                    $testResourceParametersGroup = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SamAccountName'
                        AccountType         = 'Group'
                        Path                = $mockPath
                        Description         = $mockGroupServiceAccount.Description
                        Ensure              = 'Present'
                        Members             = 'Node1$', 'User1'
                        DisplayName         = ''
                    }

                    Test-TargetResource @testResourceParametersGroup | Should Be $true
                }
            }

            Context -Name "When the system is in the desired state and 'Ensure' is 'Absent' (Both)" {
                It "Should pass when 'Ensure' is set to 'Absent" {
                    Mock -CommandName Get-ADServiceAccount -MockWith {
                        throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                    }

                    $testResourceParametersSingle = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                        Ensure             = 'Absent'
                    }

                    Test-TargetResource @testResourceParametersSingle | Should Be $true
                }
            }

            Context -Name "When the system is NOT in the desired state and 'Ensure' is 'Present' (sMSA)" {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockSingleServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockSingleServiceAccount
                }

                $testIncorrectParameters = @{
                    AccountType = 'Group'
                    Path        = 'WrongPath'
                    Description = 'WrongDescription'
                    Ensure      = 'Absent'
                    DisplayName = 'DisplayNameWrong'
                }

                $testCases = @()
                foreach($incorrectParameter in $testIncorrectParameters.GetEnumerator())
                {
                    $testCases += @{ Parameter = $incorrectParameter.Name; Value = $incorrectParameter.Value }
                }

                It "Should return $false when <Parameter> is incorrect" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Value
                    )

                    $testResourceParametersSingle = @{
                        ServiceAccountName = $mockSingleServiceAccount.Name
                        AccountType        = 'Single'
                        Path               = $mockPath
                        Description        = $mockSingleServiceAccount.Description
                        Ensure             = 'Present'
                        DisplayName        = ''
                    }

                    $testResourceParametersSingle[$Parameter] = $value
                    Test-TargetResource @testResourceParametersSingle | Should Be $false
                }
            }

            Context -Name "When the system is NOT in the desired state and 'Ensure' is 'Present' (gMSA)" {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter {
                    $mockGroupServiceAccount.Name -eq $Identity
                } -MockWith {
                    return $mockGroupServiceAccount
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADComputer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADComputer
                }

                Mock -CommandName Get-ADObject -ParameterFilter {
                    $mockADUSer.DistinguishedName -eq $Identity
                } -MockWith {
                    return $mockADUser
                }

                $testIncorrectParameters = @{
                    AccountType = 'Single'
                    Path        = 'WrongPath'
                    Description = 'WrongDescription'
                    Ensure      = 'Absent'
                    Members     = ''
                    DisplayName = 'DisplayNameWrong'
                }

                $testCases = @()
                foreach($incorrectParameter in $testIncorrectParameters.GetEnumerator())
                {
                    $testCases += @{ Parameter = $incorrectParameter.Name; Value = $incorrectParameter.Value }
                }

                It "Should return $false when <Parameter> is incorrect" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Value
                    )

                    $testResourceParametersGroup = @{
                        ServiceAccountName  = $mockGroupServiceAccount.Name
                        MembershipAttribute = 'SamAccountName'
                        AccountType         = 'Group'
                        Path                = $mockPath
                        Description         = $mockGroupServiceAccount.Description
                        Ensure              = 'Present'
                        Members             = 'Node1$', 'User1'
                        DisplayName         = ''
                    }

                    $testResourceParametersGroup[$Parameter] = $value
                    Test-TargetResource @testResourceParametersGroup | Should Be $false
                }
            }
        }
        #endregion Function Test-TargetResource

    }
}
finally
{
    Invoke-TestCleanup
}
