$Global:DSCModuleName      = 'xActiveDirectory' # Example xNetworking
$Global:DSCResourceName    = 'MSFT_xADComputer' # Example MSFT_xFirewall

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
Write-Host $moduleRoot -ForegroundColor Green;
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}
else
{
    & git @('-C',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'),'pull')
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

    # The InModuleScope command allows you to perform white-box unit testing on the internal
    # (non-exported) code of a Script Module.
    InModuleScope $Global:DSCResourceName {

        $testPresentParams = @{
            ComputerName = 'TESTCOMPUTER';
            Ensure = 'Present';
        }
        
        $testAbsentParams = $testPresentParams.Clone();
        $testAbsentParams['Ensure'] = 'Absent';
        
        $fakeADComputer = @{
            DistinguishedName = "CN=$($testPresentParams.ComputerName),CN=Computers,DC=contoso,DC=com";
            Enabled = $true;
            Name = $testPresentParams.ComputerName;
            SamAccountName = '{0}$' -f $testPresentParams.ComputerName;
            SID = 'S-1-5-21-1409167834-891301383-2860967316-1143';
            ObjectClass = 'computer';
            ObjectGUID = [System.Guid]::NewGuid();
            UserPrincipalName = '';
        }

        $testDomainController = 'TESTDC';
        $testCredential = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        $testStringProperties = @(
            'Location', 'DnsHostName', 'ServicePrincipalNames', 'UserPrincipalName', 'DisplayName', 'Path', 'Description', 'Manager'
        );
        $testBooleanProperties = @('Enabled');

        #region Function Get-TargetResource
        Describe "$($Global:DSCResourceName)\Get-TargetResource" {
        
            It "Returns a 'System.Collections.Hashtable' object type" {
                Mock Get-ADComputer { return [PSCustomObject] $fakeADComputer; }
        
                $adUser = Get-TargetResource @testPresentParams;
        
                $adUser -is [System.Collections.Hashtable] | Should Be $true;
            }
        
            It "Returns 'Ensure' is 'Present' when user account exists" {
                Mock Get-ADComputer { return [PSCustomObject] $fakeADComputer; }
        
                $adUser = Get-TargetResource @testPresentParams;
        
                $adUser.Ensure | Should Be 'Present';
            }
            
            It "Returns 'Ensure' is 'Absent' when user account does not exist" {
                Mock Get-ADComputer { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                
                $adUser = Get-TargetResource @testPresentParams;
                
                $adUser.Ensure | Should Be 'Absent';
            }
            
            It "Calls 'Get-ADComputer' with 'Server' parameter when 'DomainController' specified" {
                Mock Get-ADComputer -ParameterFilter { $Server -eq $testDomainController } -MockWith { return [PSCustomObject] $fakeADComputer; }
                
                Get-TargetResource @testPresentParams -DomainController $testDomainController;
                
                Assert-MockCalled Get-ADComputer -ParameterFilter { $Server -eq $testDomainController } -Scope It;
            }
            
            It "Calls 'Get-ADComputer' with 'Credential' parameter when 'DomainAdministratorCredential' specified" {
                Mock Get-ADComputer -ParameterFilter { $Credential -eq $testCredential } -MockWith { return [PSCustomObject] $fakeADComputer; }
        
                Get-TargetResource @testPresentParams -DomainAdministratorCredential $testCredential;
                
                Assert-MockCalled Get-ADComputer -ParameterFilter { $Credential -eq $testCredential } -Scope It;
            }
        
        }
        #endregion

        #region Function Test-TargetResource
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
            
            It "Passes when computer account does not exist and 'Ensure' is 'Absent'" {
                Mock Get-TargetResource { return $testAbsentParams }
                
                Test-TargetResource @testAbsentParams | Should Be $true;
            }
        
            It "Passes when computer account exists and 'Ensure' is 'Present'" {
                Mock Get-TargetResource { return $testPresentParams }
                
                Test-TargetResource @testPresentParams | Should Be $true;
            }
        
            It "Fails when computer account does not exist and 'Ensure' is 'Present'" {
                Mock Get-TargetResource { return $testAbsentParams }
                
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            
            It "Fails when computer account exists, and 'Ensure' is 'Absent'" {
                Mock Get-TargetResource { return $testPresentParams }
                
                Test-TargetResource @testAbsentParams | Should Be $false;
            }
        
            foreach ($testParameter in $testStringProperties) {
            
                It "Passes when computer account '$testParameter' matches AD account property" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADComputer[$testParameter] = $testParameterValue;
                        return $validADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
                It "Fails when computer account '$testParameter' does not match incorrect AD account property value" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $invalidADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADComputer[$testParameter] = $testParameterValue.Substring(0, ([System.Int32] $testParameterValue.Length/2));
                        return $invalidADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
                It "Fails when computer account '$testParameter' does not match empty AD account property value" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $invalidADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADComputer[$testParameter] = '';
                        return $invalidADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
                It "Fails when computer account '$testParameter' does not match null AD account property value" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $invalidADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADComputer[$testParameter] = $null;
                        return $invalidADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
                It "Passes when empty computer account '$testParameter' matches empty AD account property" {
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADComputer[$testParameter] = '';
                        return $validADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
                It "Passes when empty computer account '$testParameter' matches null AD account property" {
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADComputer[$testParameter] = $null;
                        return $validADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
            } #end foreach test string property
            
            foreach ($testParameter in $testBooleanProperties) {
                
                It "Passes when computer account '$testParameter' matches AD account property" {
                    $testParameterValue = $true;
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADComputer[$testParameter] = $testParameterValue;
                        return $validADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
                It "Fails when computer account '$testParameter' does not match AD account property value" {
                    $testParameterValue = $true;
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $invalidADComputer = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADComputer[$testParameter] = -not $testParameterValue;
                        return $invalidADComputer;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
            } #end foreach test boolean property
            
        }
        #endregion

        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            
            It "Calls 'New-ADComputer' when 'Ensure' is 'Present' and the account does not exist" {
                $newComputerName = 'NEWCOMPUTER'
                $newAbsentParams = $testAbsentParams.Clone();
                $newAbsentParams['ComputerName'] = $newComputerName;
                $newPresentParams = $testPresentParams.Clone();
                $newPresentParams['ComputerName'] = $newComputerName;                  
                Mock New-ADComputer -ParameterFilter { $Name -eq $newComputerName } -MockWith { }
                Mock Set-ADComputer { }
                Mock Get-TargetResource -ParameterFilter { $ComputerName -eq $newComputerName } -MockWith { return $newAbsentParams; }
                
                Set-TargetResource @newPresentParams;
                
                Assert-MockCalled New-ADComputer -ParameterFilter { $Name -eq $newComputerName } -Scope It;
            }
            
            It "Calls 'Move-ADObject' when 'Ensure' is 'Present', the computer account exists but Path is incorrect" {
                $testTargetPath = 'OU=NewPath,DC=contoso,DC=com';
                Mock Set-ADComputer { }
                Mock Get-ADComputer {
                    $duffADComputer = $fakeADComputer.Clone();
                    $duffADComputer['DistinguishedName'] = 'CN={0},OU=WrongPath,DC=contoso,DC=com' -f $testPresentParams.ComputerName;
                    return $duffADComputer;
                }
                Mock Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -MockWith { }
        
                Set-TargetResource @testPresentParams -Path $testTargetPath;
                
                Assert-MockCalled Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -Scope It;
            }

        
            <# It "Calls 'Set-ADUser' with 'Replace' when existing matching AD property is null" {
                $testADPropertyName = 'Description';
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser[$testADPropertyName] = $null;
                    return $duffADUser;
                }
                Mock Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -MockWith { }
        
                Set-TargetResource @testPresentParams -Description 'My custom description';
                
                Assert-MockCalled Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -Scope It -Exactly 1;
            }
            
            It "Calls 'Set-ADUser' with 'Replace' when existing matching AD property is empty" {
                $testADPropertyName = 'Description';
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser[$testADPropertyName] = '';
                    return $duffADUser;
                }
                Mock Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -MockWith { }
        
                Set-TargetResource @testPresentParams -Description 'My custom description';
                
                Assert-MockCalled Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -Scope It -Exactly 1;
            }
        
            It "Calls 'Set-ADUser' with 'Remove' when new matching AD property is empty" {
                $testADPropertyName = 'Description';
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser[$testADPropertyName] = 'Incorrect parameter value';
                    return $duffADUser;
                }
                Mock Set-ADUser -ParameterFilter { $Remove.ContainsKey($testADPropertyName) } -MockWith { }
        
                Set-TargetResource @testPresentParams -Description '';
                
                Assert-MockCalled Set-ADUser -ParameterFilter { $Remove.ContainsKey($testADPropertyName) } -Scope It -Exactly 1;
            }
        
            It "Calls 'Set-ADUser' with 'Replace' when existing mismatched AD property is null" {
                $testADPropertyName = 'Title';
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser[$testADPropertyName] = $null;
                    return $duffADUser;
                }
                Mock Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -MockWith { }
        
                Set-TargetResource @testPresentParams -JobTitle 'Gaffer';
                
                Assert-MockCalled Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -Scope It -Exactly 1;
            }
        
            It "Calls 'Set-ADUser' with 'Replace' when existing mismatched AD property is empty" {
                $testADPropertyName = 'Title';
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser[$testADPropertyName] = '';
                    return $duffADUser;
                }
                Mock Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -MockWith { }
        
                Set-TargetResource @testPresentParams -JobTitle 'Gaffer';
                
                Assert-MockCalled Set-ADUser -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -Scope It -Exactly 1;
            }
        
            It "Calls 'Set-ADUser' with 'Remove' when new mismatched AD property is empty" {
                $testADPropertyName = 'Title';
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser[$testADPropertyName] = 'Incorrect job title';
                    return $duffADUser;
                }
                Mock Set-ADUser -ParameterFilter { $Remove.ContainsKey($testADPropertyName) } -MockWith { }
        
                Set-TargetResource @testPresentParams -JobTitle '';
                
                Assert-MockCalled Set-ADUser -ParameterFilter { $Remove.ContainsKey($testADPropertyName) } -Scope It -Exactly 1;
            }
            
            It "Calls 'Remove-ADUser' when 'Ensure' is 'Absent' and user account exists" {
                Mock Get-ADUser { return [PSCustomObject] $fakeADUser; }
                Mock Remove-ADUser -ParameterFilter { $Identity.ToString() -eq $testAbsentParams.UserName } -MockWith { }
                
                Set-TargetResource @testAbsentParams;
                
                Assert-MockCalled Remove-ADUser -ParameterFilter { $Identity.ToString() -eq $testAbsentParams.UserName } -Scope It;
            }
        #>
        }
        #endregion
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}

