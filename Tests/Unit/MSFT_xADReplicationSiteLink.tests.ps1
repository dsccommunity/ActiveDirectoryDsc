
#region HEADER

# Unit Test Template Version: 1.2.1
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force
Import-Module (Join-Path -Path $moduleRoot -ChildPath 'Tests\ActiveDirectoryStub.psm1')

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'RPS_xActiveDirectory' `
    -DSCResourceName 'MSFT_xADSiteLink' `
    -TestType Unit

#endregion HEADER

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    InModuleScope 'MSFT_xADSiteLink' {
        Describe 'xADSiteLink\Get-TargetResource' {
            $mockGetADSiteLink = @{
                Name                          = 'TestSiteLink'
                Cost                          = 100
                Description                   = 'HQ Site'
                ReplicationFrequencyInMinutes = 180
                SitesIncluded                 = @('site1', 'site2')
            }

            Context 'Ensure is Present' {
                Mock -CommandName Get-ADReplicationSiteLink -MockWith {$mockGetADSiteLink}

                It 'Ensure should be Present' {
                    Mock -CommandName Resolve-SiteLinkName -MockWith { @('Site1', 'Site2') }
                    $getResult = Get-TargetResource -Name HQSiteLink -Ensure Present
                    $getResult.Ensure | Should Be 'Present'
                }
            }

            Context 'Ensure is Absent' {
                Mock -CommandName Get-ADReplicationSiteLink -MockWith {throw 'Site link not found'}
                It 'Ensure Should be Absent' {
                    $getResult = Get-TargetResource -Name HQSiteLink -Ensure Present
                    $getResult.Ensure | Should Be 'Absent'
                }
            }

            Context 'When Sites are included' {
                Mock -CommandName Get-ADReplicationSiteLink -MockWith {$mockGetADSiteLink}
                Mock -CommandName Resolve-SiteLinkName -Verifiable
                Get-TargetResource -Name HQSiteLink -Ensure Present

                It 'Should call Resolve-SiteLinkName' {
                    Assert-MockCalled -CommandName Resolve-SiteLinkName -Times 1
                }
            }

            Context 'When Sites are excluded' {
                $returnMock = @{
                    Name                          = 'TestSiteLink'
                    Cost                          = 100
                    Description                   = 'HQ Site'
                    ReplicationFrequencyInMinutes = 180
                    SitesIncluded                 = $null
                }

                Mock -CommandName Get-ADReplicationSiteLink -MockWith {$returnMock}
                Mock -CommandName Resolve-SiteLinkName -Verifiable
                Get-TargetResource -Name HQSiteLink -Ensure Present

                It 'Should NOT call Resolve-SiteLinkName when SitesIncluded is NULL' {
                    Assert-MockCalled -CommandName Resolve-SiteLinkName -Times 0
                }
            }
        }

        Describe 'xADSiteLink\Test-TargetResource' {
            $mockGetTarget = @{
                Name                          = 'TestSiteLink'
                Cost                          = 100
                Description                   = 'HQ Site'
                ReplicationFrequencyInMinutes = 180
                SitesIncluded                 = @( 'site1', 'site2' )
                Ensure                        = 'Present'
            }

            Context 'Not in a desired state' {
                $falseTestParameters = @{
                    Name                          = 'TestSiteLink'
                    Cost                          = 101
                    Description                   = 'WH Site'
                    ReplicationFrequencyInMinutes = 181
                    SitesIncluded                 = @( 'site11', 'site22' )
                    Ensure                        = 'Absent'
                }

                $testParametersStarter = @{
                    Name = 'TestSiteLink'
                }

                foreach ( $key in $falseTestParameters.Keys )
                {
                    $testParameters = $testParametersStarter.Clone()
                    if ( $key -ne 'Name')
                    {
                        if ( $key -ne 'Ensure' )
                        {
                            $testParameters.Add( 'Ensure' , $mockGetTarget['Ensure'] )
                            $testParameters.Add( $key, $falseTestParameters[$key] )
                        }
                        else
                        {
                            $testParameters.Add( $key, 'Absent' )
                        }

                        It "Should return False when $key not in desired state" {
                            Mock Get-TargetResource -MockWith { $mockGetTarget }

                            $testResult = Test-TargetResource @testParameters
                            $testResult | Should Be $false
                        }
                    }
                }
            }

            Context 'In a desired state' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTarget }
                It 'Should return True' {
                    $testResult = Test-TargetResource @mockGetTarget

                    $testResult | Should Be $true
                }
            }
        }

        Describe 'xADSiteLink\Set-TargetResource' {
            Context 'Site Link is Absent but is desired Present' {
                Mock -CommandName Get-TargetResource -MockWith { @{ Ensure = 'Absent' } } -Verifiable
                Mock -CommandName New-ADReplicationSiteLink -Verifiable
                Mock -CommandName Set-ADReplicationSiteLink
                Mock -CommandName Remove-ADReplicationSiteLink

                Set-TargetResource -Name 'TestSiteLink' -Ensure 'Present'

                It 'Should call New-ADReplicationSiteLink' {
                    Assert-VerifiableMock
                }
            }

            Context 'Site Link is Present but desired Absent' {
                Mock -CommandName Get-TargetResource -MockWith { @{ Ensure = 'Present' } }
                Mock -CommandName New-ADReplicationSiteLink
                Mock -CommandName Set-ADReplicationSiteLink
                Mock -CommandName Remove-ADReplicationSiteLink -Verifiable

                Set-TargetResource -Name 'TestSiteLink' -Ensure 'Absent'

                It 'Should call Remove-ADReplicationSiteLink' {
                    Assert-VerifiableMock
                }
            }

            Context 'Site Link is Present and Should be but not in a desired state' {
                $addSitesParameters = @{
                    Name          = 'TestSite'
                    SitesIncluded = 'Site1'
                    Ensure        = 'Present'
                }

                $removeSitesParameters = @{
                    Name          = 'TestSite'
                    SitesExcluded = 'Site1'
                    Ensure        = 'Present'
                }

                Mock -CommandName Get-TargetResource -MockWith { @{ Ensure = 'Present' ; SitesIncluded = 'Site0'} }
                Mock -CommandName Set-ADReplicationSiteLink

                It "Should call Set-ADReplicationSiteLink with SitesIncluded-Add when SitesInluded is populated" {
                    Mock -CommandName Set-ADReplicationSiteLink -ParameterFilter {$SitesIncluded -and $SitesIncluded['Add'] -eq 'Site1'} -Verifiable
                    Set-TargetResource @addSitesParameters
                    Assert-VerifiableMock
                }

                It 'Should call Set-ADReplicationSiteLink with SitesIncluded-Remove when SitesExcluded is populated' {
                    Mock -CommandName Set-ADReplicationSiteLink -ParameterFilter {$SitesIncluded -and $SitesIncluded['Remove'] -eq 'Site1'} -Verifiable
                    Set-TargetResource @removeSitesParameters
                    Assert-VerifiableMock
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
    Remove-Module -Name ActiveDirectoryStub
}
