[CmdletBinding()]
param()

if (!$PSScriptRoot) # $PSScriptRoot is not defined in 2.0
{
    $PSScriptRoot = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path $PSScriptRoot\..).Path

$ModuleName = 'MSFT_xADGroup'
Import-Module (Join-Path $RepoRoot "DSCResources\$ModuleName\$ModuleName.psm1") -Force;
## Active Directory module required to throw Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
Import-Module ActiveDirectory;

Describe "xADGroup" {
    
    InModuleScope $ModuleName {

        $testPresentParams = @{
            GroupName = 'TestGroup'
            Scope = 'Global';
            Category = 'Security';
            Path = 'OU=Fake,DC=contoso,DC=com';
            Description = 'Test AD group description';
            DisplayName = 'Test display name';
            #Credential = '';
            #DomainController = '';
            Ensure = 'Present';
        }
        
        $testAbsentParams = $testPresentParams.Clone();
        $testAbsentParams['Ensure'] = 'Absent';
        
        $fakeADGroup = @{
            Name = $testPresentParams.GroupName;
            GroupScope = $testPresentParams.Scope;
            GroupCategory = $testPresentParams.Category;
            DistinguishedName = "CN=$($testPresentParams.GroupName),$($testPresentParams.Path)";
            Description = $testPresentParams.Description;
            DisplayName = $testPresentParams.DisplayName;
        }

        $testDomainController = 'TESTDC';
        $testCredentials = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        Context "Validate Assert-Module method" {
            It "Throws if Active Directory module is not present" {
                Mock Get-Module -ParameterFilter { $ModuleName -eq 'ActiveDirecory'} -MockWith { throw; }
                Assert-Module -ModuleName ActiveDirectory;
            }
        }

        Context "Validate Get-ADCommonParameters method" {
            It "Adds Server parameter when DomainController parameter is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -DomainController $testDomainController;
                $adCommonParams.Server | Should Be $testDomainController;
            }
            It "Adds Credential parameter when Credential parameter is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -Credential $testCredentials;
                $adCommonParams.Credential | Should Be $testCredentials;
            }
        }
        
        Context "Validate Get-TargetResource method" {
            It "Returns Ensure is Present when DNS record exists" {
                Mock Get-ADGroup { return $fakeADGroup; }
                (Get-TargetResource @testPresentParams).Ensure | Should Be 'Present';
            }
            It "Returns Ensure is Absent when DNS record does not exist" {
                Mock Get-ADGroup { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                (Get-TargetResource @testPresentParams).Ensure | Should Be 'Absent';
            }
            It "Calls Get-ADGroup with -Server parameter when -DomainController specified" {
                Mock Get-ADGroup -ParameterFilter { $Server -eq $testDomainController } -MockWith { return $fakeADGroup; }
                Get-TargetResource @testPresentParams -DomainController $testDomainController;
                Assert-MockCalled Get-ADGroup -ParameterFilter { $Server -eq $testDomainController } -Scope It;
            }
            It "Calls Get-ADGroup with -Credential parameter when -Credential specified" {
                Mock Get-ADGroup -ParameterFilter { $Credential -eq $testCredentials } -MockWith { return $fakeADGroup; }
                Get-TargetResource @testPresentParams -Credential $testCredentials;
                Assert-MockCalled Get-ADGroup -ParameterFilter { $Credential -eq $testCredentials } -Scope It;
            }
        } #end context Validate Get-TargetResource method
        
        Context "Validate Test-TargetResource method" {
            It "Fails when group does not exist and Ensure is Present" {
                Mock Get-TargetResource { return $testAbsentParams }
                Test-TargetResource @testPresentParams | Should Be $false
            }
            It "Fails when group exists, Ensure is Present but Scope is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Scope'] = 'Universal';
                    return $duffADGroup;
                }
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            It "Fails when group exists, Ensure is Present but Category is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Category'] = 'Distribution';
                    return $duffADGroup;
                }
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            It "Fails when group exists, Ensure is Present but Path is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Path'] = 'OU=WrongPath,DC=contoso,DC=com';
                    return $duffADGroup;
                }
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            It "Fails when group exists, Ensure is Present but Description is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Description'] = 'Test AD group description is wrong';
                    return $duffADGroup;
                }
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            It "Fails when group exists, Ensure is Present but DisplayName is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['DisplayName'] = 'Wrong display name';
                    return $duffADGroup;
                }
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            It "Fails when group exists and Ensure is Absent" {
                Mock Get-TargetResource { return $testPresentParams }
                Test-TargetResource @testAbsentParams | Should Be $false
            }
            It "Passes when group exists, target matches and Ensure is Present" {
                Mock Get-TargetResource { return $testPresentParams } 
                Test-TargetResource @testPresentParams | Should Be $true
            }
            It "Passes when group does not exist and Ensure is Absent" {
                Mock Get-TargetResource { return $testAbsentParams } 
                Test-TargetResource @testAbsentParams | Should Be $true
            }
        } #end Context Validate Test-TargetResource method
        
        Context "Validate Set-TargetResource method" {
            It "Calls New-ADGroup in the set method when Ensure is Present and the group does not exist" {
                Mock Get-ADGroup { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                Mock New-ADGroup { }
                Set-TargetResource @testPresentParams;
                Assert-MockCalled New-ADGroup -Scope It;
            }
            It "Calls Set-ADGroup in the set method when Ensure is Present and the group does exist" {
                Mock Get-ADGroup { return $fakeADGroup; }
                Mock Set-ADGroup { }
                Set-TargetResource @testPresentParams;
                Assert-MockCalled Set-ADGroup -Scope It -Exactly 1;
            }
            It "Calls Set-ADGroup twice when Ensure is Present, the group exists but the Scope has changed" {
                Mock Get-ADGroup {
                    $duffADGroup = $fakeADGroup.Clone();
                    $duffADGroup['GroupScope'] = 'DomainLocal'
                    return $duffADGroup;
                }
                Mock Set-ADGroup { }
                Set-TargetResource @testPresentParams;
                Assert-MockCalled Set-ADGroup -Scope It -Exactly 2;
            }
            It "Calls Move-ADObject when Ensure is Present, the group exists but the Path has changed" {
                Mock Get-ADGroup {
                    $duffADGroup = $fakeADGroup.Clone();
                    $duffADGroup['DistinguishedName'] = "CN=$($testPresentParams.GroupName),OU=WrongPath,DC=contoso,DC=com";
                    return $duffADGroup;
                }
                Mock Set-ADGroup { }
                Mock Move-ADObject { }
                Set-TargetResource @testPresentParams;
                Assert-MockCalled Move-ADObject -Scope It;
            }
            It "Calls Remove-ADGroup when Ensure is Absent and group exists" {
                Mock Get-ADGroup { return $fakeADGroup; }
                Mock Remove-ADGroup { }
                Set-TargetResource @testAbsentParams;
                Assert-MockCalled Remove-ADGroup -Scope It;
            }
        } #end context Validate Set-TargetResource method
    
    } #end InModuleScope
}
