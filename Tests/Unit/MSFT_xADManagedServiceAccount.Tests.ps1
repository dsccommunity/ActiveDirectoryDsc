[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]

#region HEADER
# TODO: Update to correct module name and resource name.
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

# TODO: Insert the correct <ModuleName> and <ResourceName> for your resource
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit

#endregion HEADER

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    # TODO: Other Optional Cleanup Code Goes Here...
}

# Begin Testing
try
{
    #region Pester Tests

    InModuleScope $script:DSCResourceName {
       #region Pester Test Initialization
        $testPresentParams = @{
            ServiceAccountName = 'TestMSA'
            AccountType        = 'Single'
            Path               = 'OU=Fake,DC=contoso,DC=com'
            Description        = 'Test MSA description'
            DisplayName        = 'Test MSA display name'
            Ensure             = 'Present'
        }

        $testAbsentParams = $testPresentParams.Clone()
        $testAbsentParams['Ensure'] = 'Absent'

        $fakeADMSASingle = @{
            Name              = $testPresentParams.ServiceAccountName
            Identity          = $testPresentParams.Name
            DistinguishedName = "CN=$($testPresentParams.ServiceAccountName),$($testPresentParams.Path)"
            Description       = $testPresentParams.Description
            DisplayName       = $testPresentParams.DisplayName
            ObjectClass       = 'msDS-ManagedServiceAccount'
            Enabled           = $true
        }

        $fakeADNode = @{
          SamAccountName = 'Node1$'
          DistinguishedName = 'CN=Node1,OU=Fake,DC=contoso,DC=com'
        }

        $testPresentParamsGroup = $testPresentParams.Clone()
        $testPresentParamsGroup['AccountType'] = 'Group'
        $testPresentParamsGroup['Members'] = $fakeADNode.SamAccountName

        $testAbsentParamsGroup = $testPresentParamsGroup.Clone()
        $testAbsentParamsGroup['Ensure'] = 'Absent'

        $fakeADMSAGroup = $fakeADMSASingle.Clone()
        $fakeADMSAGroup['ObjectClass'] = 'msDS-GroupManagedServiceAccount'
        $fakeADMSAGroup['PrincipalsAllowedToRetrieveManagedPassword'] = @($fakeADNode.DistinguishedName)

        $testDomainController = 'TESTDC'
        $testCredentials = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        # region Function Compare-TargetResourceState
        Describe -Name "MSFT_xADManagedServiceAccount\Compare-TargetResourceState" {
            It 'Should call "Get-ADServiceAccount"' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }
                $null = Compare-TargetResourceState @testPresentParams

                Assert-MockCalled -CommandName Get-ADServiceAccount
            }

            Context -Name 'When the system is in the desired state (Single)' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }

                $resource = Compare-TargetResourceState @testPresentParams
                $testCases = @()
                $resource | ForEach-Object {
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

            Context -Name 'When the system is in the desired state (Group)' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }
                Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }

                $resource = Compare-TargetResourceState @testPresentParamsGroup
                $testCases = @()
                $resource | ForEach-Object {
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

            Context -Name 'When the system is not in the desired state (Single)' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }
                $duffTestParamsWrong = $testPresentParams.Clone()

                $duffTestParams = @{
                    AccountType         = 'Group'
                    Path                = 'OU=FakeWrong,DC=contoso,DC=com'
                    Description         = 'Test MSA description Wrong'
                    DisplayName         = 'Test MSA display name Wrong'
                    Ensure              = 'Absent'
                }

                $duffTestParams.GetEnumerator() | ForEach-Object {
                    $duffTestParamsWrong[$_.Name] = $_.Value
                }

                $resource = Compare-TargetResourceState @duffTestParamsWrong

                $testCases = @()
                $duffTestParams.GetEnumerator() | ForEach-Object {
                    $testParam = $_.Name
                    $resourceParam = $resource | Where-Object {$_.Parameter -eq $testParam}

                    $testCases += @{
                        Parameter = $resourceParam.Parameter
                        Expected  = $resourceParam.Expected
                        Actual    = $resourceParam.Actual
                        Pass      = $resourceParam.Pass
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

            Context -Name 'When the system is not in the desired state (Group)' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }
                Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }

                $duffTestParamsWrong = $testPresentParamsGroup.Clone()

                $duffTestParams = @{
                    AccountType         = 'Single'
                    Path                = 'OU=FakeWrong,DC=contoso,DC=com'
                    Description         = 'Test MSA description Wrong'
                    DisplayName         = 'Test MSA display name Wrong'
                    Ensure              = 'Absent'
                }

                $duffTestParams.GetEnumerator() | ForEach-Object {
                    $duffTestParamsWrong[$_.Name] = $_.Value
                }

                $resource = Compare-TargetResourceState @duffTestParamsWrong

                $testCases = @()
                $duffTestParams.GetEnumerator() | ForEach-Object {
                    $testParam = $_.Name
                    $resourceParam = $resource | Where-Object {$_.Parameter -eq $testParam}

                    $testCases += @{
                        Parameter = $resourceParam.Parameter
                        Expected  = $resourceParam.Expected
                        Actual    = $resourceParam.Actual
                        Pass      = $resourceParam.Pass
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
        }
        # end region

        # region Function Get-TargetResource
        Describe -Name "MSFT_xADManagedServiceAccount\Get-TargetResource" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            It 'Should call "Assert-Module" to check AD module is installed' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }

                $getTargetResourceParameters = @{
                    ServiceAccountName = $testPresentParams.ServiceAccountName
                }
                $null = Get-TargetResource @getTargetResourceParameters

                Assert-MockCalled -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Scope It -Exactly -Times 1
            }

            It "Should call 'Get-ADServiceAccount' with 'Server' parameter when 'DomainController' specified" {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter { $Server -eq $testDomainController } -MockWith { return $fakeADMSASingle }

                $getTargetResourceParameters = @{
                    ServiceAccountName = $testPresentParams.ServiceAccountName
                    DomainController   = $testDomainController
                }
                $null = Get-TargetResource  @getTargetResourceParameters

                Assert-MockCalled -CommandName Get-ADServiceAccount -ParameterFilter { $Server -eq $testDomainController } -Scope It -Exactly -Times 1
            }

            It "Should call 'Get-ADServiceAccount' with 'Credential' parameter when specified" {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -MockWith { return $fakeADMSASingle }

                $getTargetResourceParameters = @{
                    ServiceAccountName = $testPresentParams.ServiceAccountName
                    Credential         = $testCredentials
                }
                $null = Get-TargetResource  @getTargetResourceParameters

                Assert-MockCalled -CommandName Get-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
            }

            It "Should call 'Write-Error' when catching other errors" {
                Mock -CommandName Get-ADServiceAccount -MockWith { throw 'Microsoft.ActiveDirectory.Management.ADServerDownException' }

                $getTargetResourceParameters = @{
                    ServiceAccountName = $testPresentParams.ServiceAccountName
                }

                { $null = Get-TargetResource  @getTargetResourceParameters -ErrorAction 'SilentlyContinue' } | Should Throw

            }

            Context -Name 'When the system is in the desired state (Single)' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }

                $testCases = @()
                foreach ($param in $testPresentParams.GetEnumerator())
                {
                    $testCases += @{ Parameter = $param.Name; Value = $param.Value }
                }

                It "Should return identical information for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Value
                    )

                    $getTargetResourceParameters = @{
                        ServiceAccountName = $testPresentParams.ServiceAccountName
                    }

                    $resource = Get-TargetResource @getTargetResourceParameters
                    $resource.$Parameter | Should -BeExactly $Value

                    Assert-MockCalled -CommandName Get-ADServiceAccount
                }
            }

            Context -Name 'When the system is in the desired state (Group)' {
              Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }
              Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }

              $testCases = @()
              foreach ($param in $testPresentParamsGroup.GetEnumerator())
              {
                  $testCases += @{ Parameter = $param.Name; Value = $param.Value }
              }

              It "Should return identical information for <Parameter>" -TestCases $testCases {
                  param (
                      [Parameter()]
                      $Parameter,

                      [Parameter()]
                      $Value
                  )

                  $getTargetResourceParameters = @{
                      ServiceAccountName = $testPresentParamsGroup.ServiceAccountName
                  }

                  $resource = Get-TargetResource @getTargetResourceParameters
                  $resource.$Parameter | Should -BeExactly $Value

                  Assert-MockCalled -CommandName Get-ADServiceAccount
              }
            }

            Context -Name 'When the system is not in the desired state (Both)' {
                It "Should return 'Ensure' is 'Absent'" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }

                    $getTargetResourceParameters = @{
                        ServiceAccountName = $testPresentParams.ServiceAccountName
                    }

                    (Get-TargetResource @getTargetResourceParameters).Ensure | Should Be 'Absent'
                }

                $resource = Get-DscResource -Module xActiveDirectory -Name xADManagedServiceAccount
                $requiredParameters = $resource.Properties | Where-Object { $_.IsMandatory -eq $true }
                $requiredParameterCases = @()
                foreach ($requiredParameter in $requiredParameters)
                {
                    $requiredParameterCases += @{ Name = $requiredParameter.Name }
                }

                It "Should return values for required parameter <Name> when absent" -TestCases $requiredParameterCases {
                    param (
                        [Parameter()]
                        $Name
                    )

                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }

                    $getTargetResourceParameters = @{
                        ServiceAccountName = $testPresentParams.ServiceAccountName
                    }

                    $resource = Get-TargetResource @getTargetResourceParameters
                    $resource.$Name | Should -Not -BeNullOrEmpty
                    $resource.$Name | Should -BeExactly $testPresentParams.$Name
                }
            }
        }
        # end region

        # region Function Test-TargetResource
        Describe -Name "MSFT_xADManagedServiceAccount\Test-TargetResource" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            Context -Name 'When the system is in the desired state (Single)' {
                It "Should pass when Managed Service Account exists, target matches and 'Ensure' is 'Present'" {
                    Mock -CommandName Get-TargetResource -MockWith { return $testPresentParams }

                    Test-TargetResource @testPresentParams | Should Be $true
                }

                It "Should pass when Managed Service Account does not exist and 'Ensure' is 'Absent'" {
                    Mock -CommandName Get-TargetResource -MockWith { return $testAbsentParams }

                    Test-TargetResource @testAbsentParams | Should Be $true
                }
            }

            Context -Name 'When the system is in the desired state (Group)' {
              It "Should pass when Managed Service Account exists, target matches and 'Ensure' is 'Present'" {
                  Mock -CommandName Get-TargetResource -MockWith { return $testPresentParamsGroup }

                  Test-TargetResource @testPresentParamsGroup | Should Be $true
              }

              It "Should pass when Managed Service Account does not exist and 'Ensure' is 'Absent'" {
                  Mock -CommandName Get-TargetResource -MockWith { return $testAbsentParamsGroup }

                  Test-TargetResource @testAbsentParamsGroup | Should Be $true
              }
            }

            Context -Name 'When the system is not in the desired state (Single)' {
                It "Should return $false when Managed Service Account does not exist and 'Ensure' is 'Present'" {
                    Mock -CommandName Get-TargetResource -MockWith { return $testAbsentParams }

                    Test-TargetResource @testPresentParams | Should Be $false
                }

                It "Should return $false when Managed Service Account exists and 'Ensure' is 'Absent'" {
                    Mock -CommandName Get-TargetResource -MockWith { return $testPresentParams }

                    Test-TargetResource @testAbsentParams | Should Be $false
                }

                It "Should return $false when 'Path' is wrong" {
                    Mock -CommandName Get-TargetResource -MockWith {
                        $duffADMSA = $testPresentParams.Clone()
                        $duffADMSA['Path'] = 'OU=WrongPath,DC=contoso,DC=com'
                        return $duffADMSA
                    }

                    Test-TargetResource @testPresentParams | Should Be $false
                }

                It "Should return $false when 'Description' is wrong" {
                    Mock -CommandName Get-TargetResource -MockWith {
                        $duffADMSA = $testPresentParams.Clone()
                        $duffADMSA['Description'] = 'Test AD MSA description is wrong'
                        return $duffADMSA
                    }

                    Test-TargetResource @testPresentParams | Should Be $false
                }

                It "Should return $false when 'DisplayName' is wrong" {
                    Mock -CommandName Get-TargetResource -MockWith {
                        $duffADMSA = $testPresentParams.Clone()
                        $duffADMSA['DisplayName'] = 'Wrong display name'
                        return $duffADMSA
                    }

                    Test-TargetResource @testPresentParams | Should Be $false
                }

                It "Should return $false when 'AccountType' is wrong" {
                  Mock -CommandName Get-TargetResource -MockWith {
                      $duffADMSA = $testPresentParams.Clone()
                      $duffADMSA['AccountType'] = 'Group'
                      return $duffADMSA
                  }

                  Test-TargetResource @testPresentParams | Should Be $false
                }
            }

            Context -Name 'When the system is not in the desired state (Group)' {
              It "Should return $false when 'Members' is wrong" {
                  Mock -CommandName Get-TargetResource -MockWith {
                      $duffADMSA = $testPresentParamsGroup.Clone()
                      $duffADMSA['Members'] = @()
                      return $duffADMSA
                  }

                  Test-TargetResource @testPresentParamsGroup | Should Be $false
              }

              It "Should return $false when 'AccountType' is wrong" {
                Mock -CommandName Get-TargetResource -MockWith {
                    $duffADMSA = $testPresentParamsGroup.Clone()
                    $duffADMSA['AccountType'] = 'Single'
                    return $duffADMSA
                }

                Test-TargetResource @testPresentParamsGroup | Should Be $false
              }
          }
        }
        # end region

        # region Function Set-TargetResource
        Describe "MSFT_xADManagedServiceAccount\Set-TargetResource" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            Context 'When the system is in the desired state' {
                It "Should not take any action when 'Ensure' is 'Present' (Single)" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }
                    Mock -CommandName New-ADServiceAccount
                    Mock -CommandName Remove-ADServiceAccount
                    Mock -CommandName Set-ADServiceAccount

                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 0
                }

                It "Should not take any action when 'Ensure' is 'Present' (Group)" {
                  Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }
                  Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }
                  Mock -CommandName New-ADServiceAccount
                  Mock -CommandName Remove-ADServiceAccount
                  Mock -CommandName Set-ADServiceAccount

                  Set-TargetResource @testPresentParamsGroup

                  Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                  Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                  Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0
                  Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 0
                  Assert-MockCalled -CommandName Get-ADObject -Scope It -Exactly -Times 1
                }

                It "Should not take any action when 'Ensure' is 'Absent' (Single)" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                    Mock -CommandName New-ADServiceAccount
                    Mock -CommandName Remove-ADServiceAccount
                    Mock -CommandName Set-ADServiceAccount

                    Set-TargetResource @testAbsentParams

                    Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 0
                }

                It "Should not take any action when 'Ensure' is 'Absent' (Group)" {
                  Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                  Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }
                  Mock -CommandName New-ADServiceAccount
                  Mock -CommandName Remove-ADServiceAccount
                  Mock -CommandName Set-ADServiceAccount

                  Set-TargetResource @testAbsentParamsGroup

                  Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                  Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                  Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0
                  Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 0
                  Assert-MockCalled -CommandName Get-ADObject -Scope It -Exactly -Times 0
              }
            }

            Context 'When the system is not in the desired state' {
                It "Should call 'New-ADServiceAccount' when 'Ensure' is 'Present' and the Managed Service Account does not exist (Single)" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName New-ADServiceAccount -MockWith { return $fakeADMSASingle }

                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 1
                }

                It "Should call 'New-ADServiceAccount' when 'Ensure' is 'Present' and the Managed Service Account does not exist (Group)" {
                  Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                  Mock -CommandName Set-ADServiceAccount
                  Mock -CommandName New-ADServiceAccount -MockWith { return $fakeADMSAGroup }

                  Set-TargetResource @testPresentParamsGroup

                  Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 1
                }

                $testCases = @(
                    @{Property = 'Description'; Value = 'Test AD MSA description is wrong'},
                    @{Property = 'DisplayName'; Value = 'Test DisplayName'}
                )

                It "Should call 'Set-ADServiceAccount' when 'Ensure' is 'Present' and <Property> is specified (Single)" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Property,

                        [Parameter()]
                        $Value
                    )

                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Get-ADServiceAccount -MockWith {
                        $duffADMSA = $fakeADMSASingle.Clone()
                        $duffADMSA[$Property] = $Value
                        return $duffADMSA
                    }

                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 1
                }

                It "Should call 'New-ADServiceAccount' when 'Ensure' is 'Present' and AccountType is specified and AccountTypeForce is true (Single)" {
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Remove-ADServiceAccount
                    Mock -CommandName New-ADServiceAccount
                    Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }

                    $testPresentParams['AccountTypeForce'] = $true
                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 1
                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 1
                }

                It "Should not call 'New-ADServiceAccount' when 'Ensure' is 'Present' and AccountType is specified and AccountTypeForce is not true (Single)" {
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Remove-ADServiceAccount
                    Mock -CommandName New-ADServiceAccount
                    Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }

                    $testPresentParams['AccountTypeForce'] = $false
                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                }

                It "Should call 'Set-ADServiceAccount' when 'Ensure' is 'Present' and Members is specified (Group)" {
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Test-Members -MockWith { return $false }
                    Mock -CommandName Get-ADObject -MockWith { return $fakeADNode }
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSAGroup }

                    $duffParams = $testPresentParamsGroup.Clone()
                    $duffParams['Members'] = ''
                    Set-TargetResource @duffParams

                    Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Members -Scope It -Exactly -Times 1
                }

                It "Should remove Managed Service Account when 'Ensure' is 'Absent' (Both)" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSASingle }
                    Mock -CommandName Remove-ADServiceAccount

                    Set-TargetResource @testAbsentParams

                    Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 1
                }

                # Regression test for issue #106
                It "Should call 'Set-ADServiceAccount' with credentials when 'Ensure' is 'Present'" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { $fakeADMSASingle['DisplayName'] = 'FakeDisplayName'; return $fakeADMSASingle }
                    Mock -CommandName New-ADServiceAccount -MockWith { return [PSCustomObject] $fakeADMSASingle }
                    Mock -CommandName Set-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials }

                    Set-TargetResource @testPresentParams -Credential $testCredentials

                    Assert-MockCalled -CommandName Set-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
                }

                # Regression test for issue #106
                It "Should call 'New-ADServiceAccount' with credentials when 'Ensure' is 'Present' and the Managed Service Account does not exist" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                    Mock -CommandName New-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } { return [PSCustomObject] $fakeADMSASingle }

                    Set-TargetResource @testPresentParams -Credential $testCredentials

                    Assert-MockCalled -CommandName New-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
                }

                # Regression test for issue #106
                It "Should call 'Move-ADObject' with credentials when specified" {
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Move-ADObject -ParameterFilter { $Credential -eq $testCredentials }
                    Mock -CommandName Get-ADServiceAccount -MockWith {
                        $duffADMSA = $fakeADMSASingle.Clone()
                        $duffADMSA['DistinguishedName'] = "CN=$($testPresentParams.ServiceAccountName),OU=WrongPath,DC=contoso,DC=com"
                        return $duffADMSA
                    }

                    Set-TargetResource @testPresentParams -Credential $testCredentials

                    Assert-MockCalled -CommandName Move-ADObject -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
                }
            }
        }
        # end region
    }
    # end region
}
finally
{
    Invoke-TestCleanup
}
