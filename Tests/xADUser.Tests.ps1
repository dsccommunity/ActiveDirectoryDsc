[CmdletBinding()]
param()

Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path $PSScriptRoot\..).Path

$ModuleName = 'MSFT_xADUser'
Import-Module (Join-Path $RepoRoot "DSCResources\$ModuleName\$ModuleName.psm1") -Force;
## Disable default ADWS drive warning
$Env:ADPS_LoadDefaultDrive = 0;
Import-Module -Name ActiveDirectory -Force;

Describe "xADUser" {

    InModuleScope $ModuleName {

        $testPresentParams = @{
            DomainName = 'contoso.com';
            UserName = 'TestUser';
            Ensure = 'Present';
        }
        
        $testAbsentParams = $testPresentParams.Clone();
        $testAbsentParams['Ensure'] = 'Absent';
        
        $fakeADUser = @{
            DistinguishedName = "CN=$($testPresentParams.UserName),CN=Users,DC=contoso,DC=com";
            Enabled = $true;
            GivenName = '';
            Name = $testPresentParams.UserName;
            SamAccountName = $testPresentParams.UserName;
            Surname = '';
            UserPrincipalName = '';
        }

        $testDomainController = 'TESTDC';
        $testCredential = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        $testStringProperties = @(
            'UserPrincipalName', 'DisplayName', 'Path',  'GivenName', 'Initials', 'Surname', 'Description', 'StreetAddress',
            'POBox', 'City', 'State', 'PostalCode', 'Country', 'Department', 'Division', 'Company', 'Office', 'JobTitle',
            'EmailAddress', 'EmployeeID', 'EmployeeNumber', 'HomeDirectory', 'HomeDrive', 'HomePage', 'ProfilePath',
            'LogonScript', 'Notes', 'OfficePhone', 'MobilePhone', 'Fax', 'Pager', 'IPPhone', 'HomePhone','CommonName'
        );
        $testBooleanProperties = @('PasswordNeverExpires', 'CannotChangePassword','Enabled');

        Context "Validate Assert-Module method" {
        
            It "Throws if Active Directory module is not present" {
                $testModuleName = 'ActiveDirectory';
                Mock Get-Module -ParameterFilter { $Name -eq $testModuleName } -MockWith { }
        
                { Assert-Module -ModuleName $testModuleName } | Should Throw;
            }
        
        } #end context Validate Assert-Module method

        Context "Validate Get-ADCommonParameters method" {

            It "Adds 'Identity' parameter by default" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams;

                $adCommonParams.Identity | Should Be $testPresentParams.UserName;
            }

            It "Adds 'Name' parameter when 'UseNameParameter' is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -UseNameParameter;

                $adCommonParams.Name | Should Be $testPresentParams.UserName;
            }

            It "Adds 'Name' parameter when 'UseNameParameter' and 'CommonName' are specified" {
                $testCommonName = 'Test Common Name';
                $adCommonParams = Get-ADCommonParameters @testPresentParams -UseNameParameter -CommonName $testCommonName;

                $adCommonParams.Name | Should Be $testCommonName;
            }
            
            It "Adds 'Server' parameter when 'DomainController' parameter is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -DomainController $testDomainController;
                
                $adCommonParams.Server | Should Be $testDomainController;
            }
            
            It "Adds 'Credential' parameter when 'DomainAdministratorCredential' parameter is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -DomainAdministratorCredential $testCredential;
                
                $adCommonParams.Credential | Should Be $testCredential;
            }
        
        } #end context Validate Get-ADCommonParameters method

        Context "Validate Get-ADObjectParentDN method" {

            It "Returns CN object parent path" {
                Get-ADObjectParentDN -DN 'CN=Administrator,CN=Users,DC=contoso,DC=com' | Should Be 'CN=Users,DC=contoso,DC=com';
            }

            It "Returns OU object parent path" {
                Get-ADObjectParentDN -DN 'CN=Administrator,OU=Custom Organizational Unit,DC=contoso,DC=com' | Should Be 'OU=Custom Organizational Unit,DC=contoso,DC=com';
            }

        } #end context Validate Get-ADObjectParentDN method

        Context "Validate Validate-Parameters method" {

            It "Does not throw when 'PasswordNeverExpires' and 'CannotChangePassword' are specified" {
                { Validate-Parameters -PasswordNeverExpires $true -CannotChangePassword $true } | Should Not Throw;
            }

            It "Throws when account is disabled and 'Password' is specified" {
                { Validate-Parameters -Password $testCredential -Enabled $false } | Should Throw;
            }

        } #end context Validate Validate-PasswordParameters method
        
        Context "Validate Get-TargetResource method" {
        
            It "Returns a 'System.Collections.Hashtable' object type" {
                Mock Get-ADUser { return [PSCustomObject] $fakeADUser; }
        
                $adUser = Get-TargetResource @testPresentParams;
        
                $adUser -is [System.Collections.Hashtable] | Should Be $true;
            }
        
            It "Returns 'Ensure' is 'Present' when user account exists" {
                Mock Get-ADUser { return [PSCustomObject] $fakeADUser; }
        
                $adUser = Get-TargetResource @testPresentParams;
        
                $adUser.Ensure | Should Be 'Present';
            }
            
            It "Returns 'Ensure' is 'Absent' when user account does not exist" {
                Mock Get-ADUser { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                
                $adUser = Get-TargetResource @testPresentParams;
                
                $adUser.Ensure | Should Be 'Absent';
            }
            
            It "Calls 'Get-ADUser' with 'Server' parameter when 'DomainController' specified" {
                Mock Get-ADUser -ParameterFilter { $Server -eq $testDomainController } -MockWith { return [PSCustomObject] $fakeADUser; }
                
                Get-TargetResource @testPresentParams -DomainController $testDomainController;
                
                Assert-MockCalled Get-ADUser -ParameterFilter { $Server -eq $testDomainController } -Scope It;
            }
            
            It "Calls 'Get-ADUser' with 'Credential' parameter when 'DomainAdministratorCredential' specified" {
                Mock Get-ADUser -ParameterFilter { $Credential -eq $testCredential } -MockWith { return [PSCustomObject] $fakeADUser; }
        
                Get-TargetResource @testPresentParams -DomainAdministratorCredential $testCredential;
                
                Assert-MockCalled Get-ADUser -ParameterFilter { $Credential -eq $testCredential } -Scope It;
            }
        
        } #end context Validate Get-TargetResource method
         
        Context "Validate Test-TargetResource method" {
            
            It "Passes when user account does not exist and 'Ensure' is 'Absent'" {
                Mock Get-TargetResource { return $testAbsentParams }
                
                Test-TargetResource @testAbsentParams | Should Be $true;
            }
        
            It "Passes when user account exists and 'Ensure' is 'Present'" {
                Mock Get-TargetResource { return $testPresentParams }
                
                Test-TargetResource @testPresentParams | Should Be $true;
            }
        
            It "Passes when user account password matches and 'Password' is specified" {
                Mock Get-TargetResource { return $testPresentParams }
                Mock Test-Password { return $true; }
        
                Test-TargetResource @testPresentParams -Password $testCredential | Should Be $true;
            }
        
            It "Fails when user account does not exist and 'Ensure' is 'Present'" {
                Mock Get-TargetResource { return $testAbsentParams }
                
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            
            It "Fails when user account exists, and 'Ensure' is 'Absent'" {
                Mock Get-TargetResource { return $testPresentParams }
                
                Test-TargetResource @testAbsentParams | Should Be $false;
            }
        
            It "Fails when user account password is incorrect and 'Password' is specified" {
                Mock Get-TargetResource { return $testPresentParams }
                Mock Test-Password { return $false; }
        
                Test-TargetResource @testPresentParams -Password $testCredential | Should Be $false;
            }
            
            foreach ($testParameter in $testStringProperties) {
            
                It "Passes when user account '$testParameter' matches AD account property" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    $invalidADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADUser[$testParameter] = $testParameterValue;
                        return $validADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
                It "Fails when user account '$testParameter' does not match incorrect AD account property value" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    $invalidADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADUser[$testParameter] = $testParameterValue.Substring(0, ([System.Int32] $testParameterValue.Length/2));
                        return $invalidADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
                It "Fails when user account '$testParameter' does not match empty AD account property value" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    $invalidADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADUser[$testParameter] = '';
                        return $invalidADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
                It "Fails when user account '$testParameter' does not match null AD account property value" {
                    $testParameterValue = 'Test Parameter String Value';
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    $invalidADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADUser[$testParameter] = $null;
                        return $invalidADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
                It "Passes when empty user account '$testParameter' matches empty AD account property" {
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADUser[$testParameter] = '';
                        return $validADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
                It "Passes when empty user account '$testParameter' matches null AD account property" {
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADUser[$testParameter] = $null;
                        return $validADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
            } #end foreach test string property
            
            foreach ($testParameter in $testBooleanProperties) {
                
                It "Passes when user account '$testParameter' matches AD account property" {
                    $testParameterValue = $true;
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    $invalidADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $validADUser[$testParameter] = $testParameterValue;
                        return $validADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $true;
                }
            
                It "Fails when user account '$testParameter' does not match AD account property value" {
                    $testParameterValue = $true;
                    $testValidPresentParams = $testPresentParams.Clone();
                    $testValidPresentParams[$testParameter] = $testParameterValue;
                    $validADUser = $testPresentParams.Clone();
                    $invalidADUser = $testPresentParams.Clone();
                    Mock Get-TargetResource {
                        $invalidADUser[$testParameter] = -not $testParameterValue;
                        return $invalidADUser;
                    }
            
                    Test-TargetResource @testValidPresentParams | Should Be $false;
                }
            
            } #end foreach test boolean property
            
        } #end Context Validate Test-TargetResource method
        
        Context "Validate Set-TargetResource method" {
            
            It "Calls 'New-ADUser' when 'Ensure' is 'Present' and the account does not exist" {
                $newUserName = 'NewUser'
                $newAbsentParams = $testAbsentParams.Clone();
                $newAbsentParams['UserName'] = $newUserName;
                $newPresentParams = $testPresentParams.Clone();
                $newPresentParams['UserName'] = $newUserName;                  
                Mock New-ADUser -ParameterFilter { $Name -eq $newUserName } { }
                Mock Set-ADUser { }
                Mock Get-TargetResource -ParameterFilter { $Username -eq $newUserName } { return $newAbsentParams; }
                
                Set-TargetResource @newPresentParams;
                
                Assert-MockCalled New-ADUser -ParameterFilter { $Name -eq $newUserName } -Scope It;
            }
            
            It "Calls 'Move-ADObject' when 'Ensure' is 'Present', the account exists but Path is incorrect" {
                $testTargetPath = 'CN=Users,DC=contoso,DC=com';
                Mock Set-ADUser { }
                Mock Get-ADUser {
                    $duffADUser = $fakeADUser.Clone();
                    $duffADUser['DistinguishedName'] = "CN=$($testPresentParams.UserName),OU=WrongPath,DC=contoso,DC=com";
                    return $duffADUser;
                }
                Mock Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -MockWith { }
        
                Set-TargetResource @testPresentParams -Path $testTargetPath -Enabled $true;
                
                Assert-MockCalled Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -Scope It;
            }

            It "Calls 'Rename-ADObject' when 'Ensure' is 'Present', the account exists but 'CommonName' is incorrect" {
                $testCommonName = 'Test Common Name';
                Mock Set-ADUser { }
                Mock Get-ADUser { return $fakeADUser; }
                Mock Rename-ADObject -ParameterFilter { $NewName -eq $testCommonName } -MockWith { }
        
                Set-TargetResource @testPresentParams -CommonName $testCommonName -Enabled $true;
                
                Assert-MockCalled Rename-ADObject -ParameterFilter { $NewName -eq $testCommonName } -Scope It;
            }
        
            It "Calls 'Set-ADAccountPassword' when 'Password' parameter is specified" {
                Mock Get-ADUser { return $fakeADUser; }
                Mock Set-ADUser { }
                Mock Set-ADAccountPassword -ParameterFilter { $NewPassword -eq $testCredential.Password } -MockWith { }
        
                Set-TargetResource @testPresentParams -Password $testCredential;
        
                Assert-MockCalled Set-ADAccountPassword -ParameterFilter { $NewPassword -eq $testCredential.Password } -Scope It;
            }
        
            It "Calls 'Set-ADUser' with 'Replace' when existing matching AD property is null" {
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
        
        } #end context Validate Set-TargetResource method
   
    } #end InModuleScope
}
