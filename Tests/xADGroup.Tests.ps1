[CmdletBinding()]
param()

Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path $PSScriptRoot\..).Path

$ModuleName = 'MSFT_xADGroup'
Import-Module (Join-Path $RepoRoot "DSCResources\$ModuleName\$ModuleName.psm1") -Force;
## AD module required as we can't mock/reference Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
Import-Module ActiveDirectory;

Describe "xADGroup" {
    
    InModuleScope $ModuleName {

        $testPresentParams = @{
            GroupName = 'TestGroup'
            GroupScope = 'Global';
            Category = 'Security';
            Path = 'OU=Fake,DC=contoso,DC=com';
            Description = 'Test AD group description';
            DisplayName = 'Test display name';
            Ensure = 'Present';
            Notes = 'This is a test AD group';
            ManagedBy = 'CN=User 1,CN=Users,DC=contoso,DC=com';
        }
        
        $testAbsentParams = $testPresentParams.Clone();
        $testAbsentParams['Ensure'] = 'Absent';
        
        $fakeADGroup = @{
            Name = $testPresentParams.GroupName;
            Identity = $testPresentParams.GroupName;
            GroupScope = $testPresentParams.GroupScope;
            GroupCategory = $testPresentParams.Category;
            DistinguishedName = "CN=$($testPresentParams.GroupName),$($testPresentParams.Path)";
            Description = $testPresentParams.Description;
            DisplayName = $testPresentParams.DisplayName;
            ManagedBy = $testPresentParams.ManagedBy;
            Info = $testPresentParams.Notes;
        }

        $fakeADUser1 = [PSCustomObject] @{
            DistinguishedName = 'CN=User 1,CN=Users,DC=contoso,DC=com';
            ObjectGUID = 'a97cc867-0c9e-4928-8387-0dba0c883b8e';
            SamAccountName = 'USER1';
            SID = 'S-1-5-21-1131554080-2861379300-292325817-1106'
        }
        $fakeADUser2 = [PSCustomObject] @{
            DistinguishedName = 'CN=User 2,CN=Users,DC=contoso,DC=com';
            ObjectGUID = 'a97cc867-0c9e-4928-8387-0dba0c883b8f';
            SamAccountName = 'USER2';
            SID = 'S-1-5-21-1131554080-2861379300-292325817-1107'
        }
        $fakeADUser3 = [PSCustomObject] @{
            DistinguishedName = 'CN=User 3,CN=Users,DC=contoso,DC=com';
            ObjectGUID = 'a97cc867-0c9e-4928-8387-0dba0c883b90';
            SamAccountName = 'USER3';
            SID = 'S-1-5-21-1131554080-2861379300-292325817-1108'
        }

        $testDomainController = 'TESTDC';
        $testCredentials = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        Context "Validate Assert-Module method" {
            
            It "Throws if Active Directory module is not present" {
                Mock Get-Module -MockWith { throw; }
            
                { Assert-Module -ModuleName ActiveDirectory } | Should Throw;
            }

        } #end context Validate Assert-Module method

        Context "Validate Get-ADCommonParameters method" {
        
            It "Adds 'Server' parameter when 'DomainController' parameter is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -DomainController $testDomainController;
        
                $adCommonParams.Server | Should Be $testDomainController;
            }
            
            It "Adds 'Credential' parameter when 'Credential' parameter is specified" {
                $adCommonParams = Get-ADCommonParameters @testPresentParams -Credential $testCredentials;
        
                $adCommonParams.Credential | Should Be $testCredentials;
            }
        
        } #end context Validate Get-ADCommonParameters method

        Context "Validate RemoveDuplicateMembers method" {
            
            It 'Removes one duplicate' {
                $members = RemoveDuplicateMembers -Members 'User1','User2','USER1';

                $members.Count | Should Be 2;
                $members -contains 'User1' | Should Be $true;
                $members -contains 'User2' | Should Be $true;
            }
            
            It 'Removes two duplicates' {
                $members = RemoveDuplicateMembers -Members 'User1','User2','USER1','USER2';

                $members.Count | Should Be 2;
                $members -contains 'User1' | Should Be $true;
                $members -contains 'User2' | Should Be $true;
            }
            
            It 'Removes double duplicates' {
                $members = RemoveDuplicateMembers -Members 'User1','User2','USER1','user1';

                $members.Count | Should Be 2;
                $members -contains 'User1' | Should Be $true;
                $members -contains 'User2' | Should Be $true;
            }

        } #end context Validate RemoveDuplicateMembers method

        Context "Validate TestGroupMembership method" {

            It 'Passes when nothing is passed' {

                TestGroupMembership -GroupMembers $null | Should Be $true;
            }

            It 'Passes when there are existing members but members are required' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);

                TestGroupMembership -GroupMembers $testGroupMembers | Should Be $true;
            }

            It 'Passes when existing members match required members' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembers = @($fakeADUser2.SamAccountName, $fakeADUser1.SamAccountName);

                TestGroupMembership -GroupMembers $testGroupMembers -Members $testMembers | Should Be $true;
            }

            It 'Fails when there are no existing members and members are required' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembers = @($fakeADUser1.SamAccountName, $fakeADUser3.SamAccountName);

                TestGroupMembership -GroupMembers $null -Members $testMembers | Should Be $false;
            }

            It 'Fails when there are more existing members than the members required' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName, $fakeADUser3.SamAccountName);
                $testMembers = @($fakeADUser1.SamAccountName, $fakeADUser3.SamAccountName);

                TestGroupMembership -GroupMembers $null -Members $testMembers | Should Be $false;
            }

            It 'Fails when there are more existing members than the members required' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembers = @($fakeADUser1.SamAccountName, $fakeADUser3.SamAccountName, $fakeADUser2.SamAccountName);
            
                TestGroupMembership -GroupMembers $null -Members $testMembers | Should Be $false;
            }
            
            It 'Fails when existing members do not match required members' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembers = @($fakeADUser1.SamAccountName, $fakeADUser3.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -Members $testMembers | Should Be $false;
            }
            
            It 'Passes when existing members include required member' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembersToInclude = @($fakeADUser2.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToInclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Passes when existing members include required members' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembersToInclude = @($fakeADUser2.SamAccountName, $fakeADUser1.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToInclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Fails when existing members is missing a required member' {
                $testGroupMembers = @($fakeADUser1.SamAccountName);
                $testMembersToInclude = @($fakeADUser2.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToInclude $testMembersToInclude | Should Be $false;
            }
            
            It 'Fails when existing members is missing a required member' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser3.SamAccountName);
                $testMembersToInclude = @($fakeADUser2.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToInclude $testMembersToInclude | Should Be $false;
            }
            
            It 'Fails when existing members is missing a required members' {
                $testGroupMembers = @($fakeADUser3.SamAccountName);
                $testMembersToInclude = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToInclude $testMembersToInclude | Should Be $false;
            }
            
            It 'Passes when existing member does not include excluded member' {
                $testGroupMembers = @($fakeADUser1.SamAccountName);
                $testMembersToExclude = @($fakeADUser2.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToExclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Passes when existing member does not include excluded members' {
                $testGroupMembers = @($fakeADUser1.SamAccountName);
                $testMembersToExclude = @($fakeADUser2.SamAccountName, $fakeADUser3.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToExclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Passes when existing members does not include excluded member' {
                $testGroupMembers = @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                $testMembersToExclude = @($fakeADUser3.SamAccountName);
            
                TestGroupMembership -GroupMembers $testGroupMembers -MembersToExclude $testMembersToInclude | Should Be $true;
            }
        } #end context Validate TestGroupMembership method

        Context "Validate ValidateMemberParameters method" {
            
            It "Errors if 'Members' is specified but is empty" {
                { ValidateMemberParameters -Members @() -ErrorAction Stop } | Should Throw;
            }
            
            It "Errors if 'Members' and 'MembersToInclude' are specified" {
                { ValidateMemberParameters -Members @('User1') -MembersToInclude @('User1') -ErrorAction Stop } | Should Throw;
            }
            
            It "Errors if 'Members' and 'MembersToExclude' are specified" {
                { ValidateMemberParameters -Members @('User1') -MembersToExclude @('User2') -ErrorAction Stop } | Should Throw;
            }
            
            It "Errors if 'MembersToInlcude' and 'MembersToExclude' contain the same member" {
                { ValidateMemberParameters -MembersToExclude @('user1') -MembersToInclude @('USER1') -ErrorAction Stop } | Should Throw;
            }
            
            It "Errors if 'MembersToInlcude' and 'MembersToExclude' are empty" {
                { ValidateMemberParameters -MembersToExclude @() -MembersToInclude @() -ErrorAction Stop } | Should Throw;
            }

        } #end context Validate ValidateMemberParameters method
        
        Context "Validate Get-TargetResource method" {
            
            It "Returns 'Ensure' is 'Present' when group exists" {
                Mock Get-ADGroup { return $fakeADGroup; }
                Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
            
                (Get-TargetResource @testPresentParams).Ensure | Should Be 'Present';
            }
            
            It "Returns 'Ensure' is 'Absent' when group does not exist" {
                Mock Get-ADGroup { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
            
                (Get-TargetResource @testPresentParams).Ensure | Should Be 'Absent';
            }
            
            
            It "Calls 'Get-ADGroup' with 'Server' parameter when 'DomainController' specified" {
                Mock Get-ADGroup -ParameterFilter { $Server -eq $testDomainController } -MockWith { return $fakeADGroup; }
            
                Get-TargetResource @testPresentParams -DomainController $testDomainController;
            
                Assert-MockCalled Get-ADGroup -ParameterFilter { $Server -eq $testDomainController } -Scope It;
            }
            
            It "Calls 'Get-ADGroup' with 'Credential' parameter when specified" {
                Mock Get-ADGroup -ParameterFilter { $Credential -eq $testCredentials } -MockWith { return $fakeADGroup; }
            
                Get-TargetResource @testPresentParams -Credential $testCredentials;
            
                Assert-MockCalled Get-ADGroup -ParameterFilter { $Credential -eq $testCredentials } -Scope It;
            }

        } #end context Validate Get-TargetResource method
        
        Context "Validate Test-TargetResource method" {
            
            foreach ($attribute in @('SamAccountName','DistinguishedName','ObjectGUID','SID')) {
                
                It "Passes when group 'Members' match using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
                
                    $targetResource = Test-TargetResource @testPresentParams -Members $fakeADUser1.$attribute, $fakeADUser2.$attribute -MembershipAttribute $attribute;
                
                    $targetResource | Should Be $true;
                }
                
                It "Fails when group membership counts do not match using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1); }
                
                    $targetResource = Test-TargetResource @testPresentParams -Members $fakeADUser2.$attribute, $fakeADUser3.$attribute -MembershipAttribute $attribute;
                
                    $targetResource | Should Be $false;
                }
                
                It "Fails when group 'Members' do not match using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
            
                    $targetResource = Test-TargetResource @testPresentParams -Members $fakeADUser2.$attribute, $fakeADUser3.$attribute -MembershipAttribute $attribute;
            
                    $targetResource | Should Be $false;
                }
            
                It "Passes when specified 'MembersToInclude' match using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
            
                    $targetResource = Test-TargetResource @testPresentParams -MembersToInclude $fakeADUser2.$attribute -MembershipAttribute $attribute;
            
                    $targetResource | Should Be $true;
                }
            
                It "Fails when specified 'MembersToInclude' are missing using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
            
                    $targetResource = Test-TargetResource @testPresentParams -MembersToInclude $fakeADUser3.$attribute -MembershipAttribute $attribute;
            
                    $targetResource | Should Be $false;
                }
            
                It "Passes when specified 'MembersToExclude' are missing using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
            
                    $targetResource = Test-TargetResource @testPresentParams -MembersToExclude $fakeADUser3.$attribute -MembershipAttribute $attribute;
            
                    $targetResource | Should Be $true;
                }
            
                It "Fails when when specified 'MembersToExclude' match using '$attribute'" {
                    Mock Get-ADGroup { return $fakeADGroup; }
                    Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
            
                    $targetResource = Test-TargetResource @testPresentParams -MembersToExclude $fakeADUser2.$attribute -MembershipAttribute $attribute;
            
                    $targetResource | Should Be $false;
                }
            
            } #end foreach attribute

            It "Fails when group does not exist and 'Ensure' is 'Present'" {
                Mock Get-TargetResource { return $testAbsentParams }
            
                Test-TargetResource @testPresentParams | Should Be $false
            }
            
            It "Fails when group exists, 'Ensure' is 'Present' but 'Scope' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['GroupScope'] = 'Universal';
                    return $duffADGroup;
                }
            
                Test-TargetResource @testPresentParams | Should Be $false;
            }

            It "Fails when group exists, 'Ensure' is 'Present' but 'Category' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Category'] = 'Distribution';
                    return $duffADGroup;
                }
            
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            
            It "Fails when group exists, 'Ensure' is 'Present' but 'Path' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Path'] = 'OU=WrongPath,DC=contoso,DC=com';
                    return $duffADGroup;
                }
            
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            
            It "Fails when group exists, 'Ensure' is 'Present' but 'Description' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Description'] = 'Test AD group description is wrong';
                    return $duffADGroup;
                }
            
                Test-TargetResource @testPresentParams | Should Be $false;
            }

            It "Fails when group exists, 'Ensure' is 'Present' but 'DisplayName' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['DisplayName'] = 'Wrong display name';
                    return $duffADGroup;
                }
               
                Test-TargetResource @testPresentParams | Should Be $false;
            }

            It "Fails when group exists, 'Ensure' is 'Present' but 'ManagedBy' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['ManagedBy'] = $fakeADUser3.DistinguishedName;
                    return $duffADGroup;
                }
                
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            
            It "Fails when group exists, 'Ensure' is 'Present' but 'Notes' is wrong" {
                Mock Get-TargetResource {
                    $duffADGroup = $testPresentParams.Clone();
                    $duffADGroup['Notes'] = 'These notes are clearly wrong';
                    return $duffADGroup;
                }
                
                Test-TargetResource @testPresentParams | Should Be $false;
            }
            
            It "Fails when group exists and 'Ensure' is 'Absent'" {
                Mock Get-TargetResource { return $testPresentParams }
                
                Test-TargetResource @testAbsentParams | Should Be $false
            }

            It "Passes when group exists, target matches and 'Ensure' is 'Present'" {
                Mock Get-TargetResource { return $testPresentParams } 
                
                Test-TargetResource @testPresentParams | Should Be $true
            }

            It "Passes when group does not exist and 'Ensure' is 'Absent'" {
                Mock Get-TargetResource { return $testAbsentParams } 
                
                Test-TargetResource @testAbsentParams | Should Be $true
            }

        } #end Context Validate Test-TargetResource method
        
        Context "Validate Set-TargetResource method" {

            It "Calls 'New-ADGroup' when 'Ensure' is 'Present' and the group does not exist" {
                Mock Get-ADGroup { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                Mock Set-ADGroup { }
                Mock New-ADGroup { return [PSCustomObject] $fakeADGroup; }
                
                Set-TargetResource @testPresentParams;
                
                Assert-MockCalled New-ADGroup -Scope It;
            }
            
            $testProperties = @{
                Description = 'Test AD Group description is wrong';
                ManagedBy = $fakeADUser3.DistinguishedName;
                DisplayName = 'Test DisplayName';
            }
            
            foreach ($property in $testProperties.Keys) {
                It "Calls 'Set-ADGroup' when 'Ensure' is 'Present' and '$property' is specified" {
                    Mock Set-ADGroup { }
                    Mock Get-ADGroupMember { }
                    Mock Get-ADGroup {
                        $duffADGroup = $fakeADGroup.Clone();
                        $duffADGroup[$property] = $testProperties.$property;
                        return $duffADGroup;
                    }
                    
                    Set-TargetResource @testPresentParams;
                    
                    Assert-MockCalled Set-ADGroup -Scope It -Exactly 1;
                }
            }

            It "Calls 'Set-ADGroup' when 'Ensure' is 'Present' and 'Category' is specified" {
                Mock Set-ADGroup -ParameterFilter { $GroupCategory -eq $testPresentParams.Category } { }
                Mock Get-ADGroupMember { }
                Mock Get-ADGroup {
                    $duffADGroup = $fakeADGroup.Clone();
                    $duffADGroup['GroupCategory'] = 'Distribution';
                    return $duffADGroup;
                }
                    
                Set-TargetResource @testPresentParams;
                    
                Assert-MockCalled Set-ADGroup -ParameterFilter { $GroupCategory -eq $testPresentParams.Category } -Scope It -Exactly 1;
            }

            It "Calls 'Set-ADGroup' when 'Ensure' is 'Present' and 'Notes' is specified" {
                Mock Set-ADGroup -ParameterFilter { $Replace -ne $null } { }
                Mock Get-ADGroupMember { }
                Mock Get-ADGroup {
                    $duffADGroup = $fakeADGroup.Clone();
                    $duffADGroup['Info'] = 'My test note..';
                    return $duffADGroup;
                }
                    
                Set-TargetResource @testPresentParams;
                    
                Assert-MockCalled Set-ADGroup -ParameterFilter { $Replace -ne $null } -Scope It -Exactly 1;
            }

            It "Calls 'Set-ADGroup' twice when 'Ensure' is 'Present', the group exists but the 'Scope' has changed" {
                Mock Set-ADGroup { }
                Mock Get-ADGroupMember { }
                Mock Get-ADGroup {
                    $duffADGroup = $fakeADGroup.Clone();
                    $duffADGroup['GroupScope'] = 'DomainLocal';
                    return $duffADGroup;
                }
                
                Set-TargetResource @testPresentParams;
                
                Assert-MockCalled Set-ADGroup -Scope It -Exactly 2;
            }

            It "Adds group members when 'Ensure' is 'Present', the group exists and 'Members' are specified" {
                Mock Get-ADGroup { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                Mock Set-ADGroup { }
                Mock Add-ADGroupMember { }
                Mock New-ADGroup { return [PSCustomObject] $fakeADGroup; }
                
                Set-TargetResource @testPresentParams -Members @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                
                Assert-MockCalled Add-ADGroupMember -Scope It;
            }

            It "Adds group members when 'Ensure' is 'Present', the group exists and 'MembersToInclude' are specified" {
                Mock Get-ADGroup { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }
                Mock Set-ADGroup { }
                Mock Add-ADGroupMember { }
                Mock New-ADGroup { return [PSCustomObject] $fakeADGroup; }
                
                Set-TargetResource @testPresentParams -MembersToInclude @($fakeADUser1.SamAccountName, $fakeADUser2.SamAccountName);
                
                Assert-MockCalled Add-ADGroupMember -Scope It;
            }

            It "Moves group when 'Ensure' is 'Present', the group exists but the 'Path' has changed" {
                Mock Set-ADGroup { }
                Mock Get-ADGroupMember { }
                Mock Move-ADObject { }
                Mock Get-ADGroup {
                    $duffADGroup = $fakeADGroup.Clone();
                    $duffADGroup['DistinguishedName'] = "CN=$($testPresentParams.GroupName),OU=WrongPath,DC=contoso,DC=com";
                    return $duffADGroup;
                }

                Set-TargetResource @testPresentParams;

                Assert-MockCalled Move-ADObject -Scope It;
            }
            
            It "Resets group membership when 'Ensure' is 'Present' and 'Members' is incorrect" {
                Mock Get-ADGroup { return [PSCustomObject] $fakeADGroup; }
                Mock Set-ADGroup { }
                Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
                Mock Add-ADGroupMember { }
                Mock Remove-ADGroupMember { }

                Set-TargetResource @testPresentParams -Members $fakeADuser1.SamAccountName;

                Assert-MockCalled Remove-ADGroupMember -Scope It -Exactly 1;
                Assert-MockCalled Add-ADGroupMember -Scope It -Exactly 1;
            }
            
            It "Does not reset group membership when 'Ensure' is 'Present' and existing group is empty" {
                Mock Get-ADGroup { return [PSCustomObject] $fakeADGroup; }
                Mock Set-ADGroup { }
                Mock Get-ADGroupMember { }
                Mock Remove-ADGroupMember { }

                Set-TargetResource @testPresentParams -MembersToExclude $fakeADuser1.SamAccountName;

                Assert-MockCalled Remove-ADGroupMember -Scope It -Exactly 0;
            }

            It "Removes members when 'Ensure' is 'Present' and 'MembersToExclude' is incorrect" {
                Mock Get-ADGroup { return [PSCustomObject] $fakeADGroup; }
                Mock Set-ADGroup { }
                Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
                Mock Remove-ADGroupMember { }

                Set-TargetResource @testPresentParams -MembersToExclude $fakeADuser1.SamAccountName;

                Assert-MockCalled Remove-ADGroupMember -Scope It -Exactly 1;
            }
            
            It "Adds members when 'Ensure' is 'Present' and 'MembersToInclude' is incorrect" {
                Mock Get-ADGroup { return [PSCustomObject] $fakeADGroup; }
                Mock Set-ADGroup { }
                Mock Get-ADGroupMember { return @($fakeADUser1, $fakeADUser2); }
                Mock Add-ADGroupMember { }

                Set-TargetResource @testPresentParams -MembersToInclude $fakeADuser3.SamAccountName;

                Assert-MockCalled Add-ADGroupMember -Scope It -Exactly 1;
            }
            
            It "Removes group when 'Ensure' is 'Absent' and group exists" {
                Mock Get-ADGroup { return $fakeADGroup; }
                Mock Remove-ADGroup { }
            
                Set-TargetResource @testAbsentParams;
            
                Assert-MockCalled Remove-ADGroup -Scope It;
            }
        } #end context Validate Set-TargetResource method
    
    } #end InModuleScope

}
