[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param()

$Global:DSCModuleName      = 'xActiveDirectory'
$Global:DSCResourceName    = 'MSFT_xADManagedServiceAccount'

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
Write-Host $moduleRoot -ForegroundColor Green
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit
#endregion

# Begin Testing
try
{
    #region Pester Tests

    InModuleScope $Global:DSCResourceName {
       #region Pester Test Initialization
        $testPresentParams = @{
            ServiceAccountName = 'TestMSA'
            Path = 'OU=Fake,DC=contoso,DC=com'
            Description = 'Test MSA description'
            DisplayName = 'Test MSA display name'
            Ensure = 'Present'
        }

        $testAbsentParams = $testPresentParams.Clone()
        $testAbsentParams['Ensure'] = 'Absent'

        $fakeADMSA = @{
            Name = $testPresentParams.ServiceAccountName
            Identity = $testPresentParams.Name
            DistinguishedName = "CN=$($testPresentParams.Name),$($testPresentParams.Path)"
            Description = $testPresentParams.Description
            DisplayName = $testPresentParams.DisplayName
        }

        $testDomainController = 'TESTDC'
        $testCredentials = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        #region Function Get-TargetResource
        Describe -Name "$($Global:DSCResourceName)\Get-TargetResource" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            It 'Should call "Assert-Module" to check AD module is installed' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSA }

                $null = Get-TargetResource @testPresentParams

                Assert-MockCalled -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Scope It -Exactly -Times 1
            }

            It "Should call 'Get-ADServiceAccount' with 'Server' parameter when 'DomainController' specified" {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter { $Server -eq $testDomainController } -MockWith { return $fakeADMSA }

                $null = Get-TargetResource @testPresentParams -DomainController $testDomainController

                Assert-MockCalled -CommandName Get-ADServiceAccount -ParameterFilter { $Server -eq $testDomainController } -Scope It -Exactly -Times 1
            }

            It "Should call 'Get-ADServiceAccount' with 'Credential' parameter when specified" {
                Mock -CommandName Get-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -MockWith { return $fakeADMSA }

                $null = Get-TargetResource @testPresentParams -Credential $testCredentials

                Assert-MockCalled -CommandName Get-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
            }

            Context -Name 'When the system is in the desired state' {
                Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSA }

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

                    $resource = Get-TargetResource @testPresentParams
                    $resource.$Parameter | Should -BeExactly $Value

                    Assert-MockCalled -CommandName Get-ADServiceAccount
                }
            }

            Context -Name 'When the system is not in the desired state' {
                It "Should return 'Ensure' is 'Absent'" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }

                    (Get-TargetResource @testPresentParams).Ensure | Should Be 'Absent'
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

                    $resource = Get-TargetResource @testPresentParams
                    $resource.$Name | Should -Not -BeNullOrEmpty
                    $resource.$Name | Should -BeExactly $testPresentParams.$Name
                }
            }
        }
        #end region

        #region Function Test-TargetResource
        Describe -Name "$($Global:DSCResourceName)\Test-TargetResource" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            Context -Name 'When the system is in the desired state' {
                It "Should pass when Managed Service Account exists, target matches and 'Ensure' is 'Present'" {
                    Mock -CommandName Get-TargetResource -MockWith { return $testPresentParams }

                    Test-TargetResource @testPresentParams | Should Be $true
                }

                It "Should pass when Managed Service Account does not exist and 'Ensure' is 'Absent'" {
                    Mock -CommandName Get-TargetResource -MockWith { return $testAbsentParams }

                    Test-TargetResource @testAbsentParams | Should Be $true
                }
            }

            Context -Name 'When the system is not in the desired state' {
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
            }
        }
        #end region

        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            Context 'When the system is in the desired state' {
                It "Should not take any action when 'Ensure' is 'Present'" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { return [PSCustomObject] $fakeADMSA }
                    Mock -CommandName New-ADServiceAccount
                    Mock -CommandName Remove-ADServiceAccount
                    Mock -CommandName Set-ADServiceAccount

                    Set-TargetResource @testPresentParams -Verbose

                    Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 0
                    Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 0
                }

                It "Should not take any action when 'Ensure' is 'Absent'" {
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
            }

            Context 'When the system is not in the desired state' {
                It "Should call 'New-ADServiceAccount' when 'Ensure' is 'Present' and the Managed Service Account does not exist" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName New-ADServiceAccount -MockWith { return [PSCustomObject] $fakeADMSA }

                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName New-ADServiceAccount -Scope It -Exactly -Times 1
                }

                $testCases = @(
                    @{Property = 'Description'; Value = 'Test AD MSA description is wrong'},
                    @{Property = 'DisplayName'; Value = 'Test DisplayName'}
                )

                It "Should call 'Set-ADServiceAccount' when 'Ensure' is 'Present' and <Property> is specified" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Property,

                        [Parameter()]
                        $Value
                    )

                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Get-ADServiceAccount -MockWith {
                        $duffADMSA = $fakeADMSA.Clone()
                        $duffADMSA[$Property] = $Value
                        return $duffADMSA
                    }

                    Set-TargetResource @testPresentParams

                    Assert-MockCalled -CommandName Set-ADServiceAccount -Scope It -Exactly -Times 1
                }

                It "Should remove Managed Service Account when 'Ensure' is 'Absent'" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSA }
                    Mock -CommandName Remove-ADServiceAccount

                    Set-TargetResource @testAbsentParams -Verbose

                    Assert-MockCalled -CommandName Get-ADServiceAccount -Scope It -Times 1
                    Assert-MockCalled -CommandName Remove-ADServiceAccount -Scope It -Exactly -Times 1
                }

                # Regression test for issue #106
                It "Should call 'Set-ADServiceAccount' with credentials when 'Ensure' is 'Present' and the Managed Service Account exists" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { return $fakeADMSA }
                    Mock -CommandName New-ADServiceAccount -MockWith { return [PSCustomObject] $fakeADMSA }
                    Mock -CommandName Set-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials }

                    Set-TargetResource @testPresentParams -Credential $testCredentials

                    Assert-MockCalled -CommandName Set-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
                }

                # Regression test for issue #106
                It "Should call 'New-ADServiceAccount' with credentials when 'Ensure' is 'Present' and the Managed Service Account does not exist" {
                    Mock -CommandName Get-ADServiceAccount -MockWith { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                    Mock -CommandName New-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } { return [PSCustomObject] $fakeADMSA }

                    Set-TargetResource @testPresentParams -Credential $testCredentials

                    Assert-MockCalled -CommandName New-ADServiceAccount -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
                }

                # Regression test for issue #106
                It "Should call 'Move-ADObject' with credentials when specified" {
                    Mock -CommandName Set-ADServiceAccount
                    Mock -CommandName Move-ADObject -ParameterFilter { $Credential -eq $testCredentials }
                    Mock -CommandName Get-ADServiceAccount -MockWith {
                        $duffADMSA = $fakeADMSA.Clone()
                        $duffADMSA['DistinguishedName'] = "CN=$($testPresentParams.ServiceAccountName),OU=WrongPath,DC=contoso,DC=com"
                        return $duffADMSA
                    }

                    Set-TargetResource @testPresentParams -Credential $testCredentials

                    Assert-MockCalled -CommandName Move-ADObject -ParameterFilter { $Credential -eq $testCredentials } -Scope It -Exactly -Times 1
                }
            }
        }
        #end region

    }
    #end region
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}