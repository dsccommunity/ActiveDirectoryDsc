$Global:DSCModuleName      = 'xActiveDirectory' # Example xNetworking
$Global:DSCResourceName    = 'MSFT_xADCommon' # Example MSFT_xFirewall

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
Write-Host $moduleRoot -ForegroundColor Green;
#endregion

Import-Module (Join-Path $moduleRoot "DSCResources\$DSCResourceName\$DSCResourceName.psm1") -Force;

# Begin Testing
try
{

    #region Pester Tests

    # The InModuleScope command allows you to perform white-box unit testing on the internal
    # (non-exported) code of a Script Module.
    InModuleScope $Global:DSCResourceName {

        #region Pester Test Initialization
        
        #endregion
       
        #region Function ResolveDomainFQDN
        Describe "$($Global:DSCResourceName)\Resolve-DomainFQDN" {
            
            It 'Returns "DomainName" when "ParentDomainName" not supplied' {
                $testDomainName = 'contoso.com';
                $testParentDomainName = $null;
                
                $result = Resolve-DomainFQDN -DomainName $testDomainName -ParentDomainName $testParentDOmainName;
                
                $result | Should Be $testDomainName;
            }
            
            It 'Returns compound "DomainName.ParentDomainName" when "ParentDomainName" supplied' {
                $testDomainName = 'subdomain';
                $testParentDomainName = 'contoso.com';
                
                $result = Resolve-DomainFQDN -DomainName $testDomainName -ParentDomainName $testParentDomainName;
                
                $result | Should Be "$testDomainName.$testParentDomainName";
            }
            
        }
        #endregion
        
        #region Function TestDomainMember
        Describe "$($Global:DSCResourceName)\Test-DomainMember" {
            
            It 'Returns "True" when domain member' {
                Mock Get-CimInstance { return @{ Name = $env:COMPUTERNAME; PartOfDomain = $true; } }
                
                Test-DomainMember | Should Be $true;
            }
            
            It 'Returns "False" when workgroup member' {
                Mock Get-CimInstance { return @{ Name = $env:COMPUTERNAME; } }
                
                Test-DomainMember | Should Be $false;
            }
            
        }
        #endregion
        
        #region Function Assert-Module
        Describe "$($Global:DSCResourceName)\Assert-Module" {
            
            It 'Does not throw when module is installed' {
                $testModuleName = 'TestModule';
                Mock Get-Module -ParameterFilter { $Name -eq $testModuleName } { return $true; }
                
                { Assert-Module -ModuleName $testModuleName } | Should Not Throw;
            }
            
            It 'Throws when module is not installed' {
                $testModuleName = 'TestModule';
                Mock Get-Module -ParameterFilter { $Name -eq $testModuleName } { }
                
                { Assert-Module -ModuleName $testModuleName } | Should Throw;
            }
            
        }
        #endregion
        
        #region Function Assert-Module
        Describe "$($Global:DSCResourceName)\Get-ADObjectParentDN" {

            It "Returns CN object parent path" {
                Get-ADObjectParentDN -DN 'CN=Administrator,CN=Users,DC=contoso,DC=com' | Should Be 'CN=Users,DC=contoso,DC=com';
            }

            It "Returns OU object parent path" {
                Get-ADObjectParentDN -DN 'CN=Administrator,OU=Custom Organizational Unit,DC=contoso,DC=com' | Should Be 'OU=Custom Organizational Unit,DC=contoso,DC=com';
            }

        } 
        
        #region Function Remove-DuplicateMembers
        Describe "$($Global:DSCResourceName)\Remove-DuplicateMembers" {
            
            It 'Removes one duplicate' {
                $members = Remove-DuplicateMembers -Members 'User1','User2','USER1';

                $members.Count | Should Be 2;
                $members -contains 'User1' | Should Be $true;
                $members -contains 'User2' | Should Be $true;
            }
            
            It 'Removes two duplicates' {
                $members = Remove-DuplicateMembers -Members 'User1','User2','USER1','USER2';

                $members.Count | Should Be 2;
                $members -contains 'User1' | Should Be $true;
                $members -contains 'User2' | Should Be $true;
            }
            
            It 'Removes double duplicates' {
                $members = Remove-DuplicateMembers -Members 'User1','User2','USER1','user1';

                $members.Count | Should Be 2;
                $members -contains 'User1' | Should Be $true;
                $members -contains 'User2' | Should Be $true;
            }

        }
        #end region
        
        #region Function Test-Members
        Describe "$($Global:DSCResourceName)\Test-Members" {
            
            It 'Passes when nothing is passed' {
                Test-Members -ExistingMembers $null | Should Be $true;
            }

            It 'Passes when there are existing members but members are required' {
                $testExistingMembers = @('USER1', 'USER2');

                Test-Members -ExistingMembers $testExistingMembers | Should Be $true;
            }

            It 'Passes when existing members match required members' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembers = @('USER2', 'USER1');

                Test-Members -ExistingMembers $testExistingMembers -Members $testMembers | Should Be $true;
            }

            It 'Fails when there are no existing members and members are required' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembers = @('USER1', 'USER3');

                Test-Members -ExistingMembers $null -Members $testMembers | Should Be $false;
            }

            It 'Fails when there are more existing members than the members required' {
                $testExistingMembers = @('USER1', 'USER2', 'USER3');
                $testMembers = @('USER1', 'USER3');

                Test-Members -ExistingMembers $null -Members $testMembers | Should Be $false;
            }

            It 'Fails when there are more existing members than the members required' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembers = @('USER1', 'USER3', 'USER2');
            
                Test-Members -ExistingMembers $null -Members $testMembers | Should Be $false;
            }
            
            It 'Fails when existing members do not match required members' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembers = @('USER1', 'USER3');
            
                Test-Members -ExistingMembers $testExistingMembers -Members $testMembers | Should Be $false;
            }
            
            It 'Passes when existing members include required member' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembersToInclude = @('USER2');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Passes when existing members include required members' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembersToInclude = @('USER2', 'USER1');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Fails when existing members is missing a required member' {
                $testExistingMembers = @('USER1');
                $testMembersToInclude = @('USER2');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should Be $false;
            }
            
            It 'Fails when existing members is missing a required member' {
                $testExistingMembers = @('USER1', 'USER3');
                $testMembersToInclude = @('USER2');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should Be $false;
            }
            
            It 'Fails when existing members is missing a required members' {
                $testExistingMembers = @('USER3');
                $testMembersToInclude = @('USER1', 'USER2');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should Be $false;
            }
            
            It 'Passes when existing member does not include excluded member' {
                $testExistingMembers = @('USER1');
                $testMembersToExclude = @('USER2');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Passes when existing member does not include excluded members' {
                $testExistingMembers = @('USER1');
                $testMembersToExclude = @('USER2', 'USER3');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToInclude | Should Be $true;
            }
            
            It 'Passes when existing members does not include excluded member' {
                $testExistingMembers = @('USER1', 'USER2');
                $testMembersToExclude = @('USER3');
            
                Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToInclude | Should Be $true;
            }
        }
        #end region
        
        #region Function Validate-MemberParameters
        Describe "$($Global:DSCResourceName)\Validate-MemberParameters" {
            
            It "Throws if 'Members' is specified but is empty" {
                { Validate-MemberParameters -Members @() } | Should Throw 'The Members parameter value is null';
            }
            
            It "Throws if 'Members' and 'MembersToInclude' are specified" {
                { Validate-MemberParameters -Members @('User1') -MembersToInclude @('User1') } | Should Throw 'parameters conflict';
            }
            
            It "Throws if 'Members' and 'MembersToExclude' are specified" {
                { Validate-MemberParameters -Members @('User1') -MembersToExclude @('User2') } | Should Throw 'parameters conflict';
            }
            
            It "Throws if 'MembersToInclude' and 'MembersToExclude' contain the same member" {
                { Validate-MemberParameters -MembersToExclude @('user1') -MembersToInclude @('USER1') } | Should Throw 'member must not be included in both';
            }
            
            It "Throws if 'MembersToInclude' and 'MembersToExclude' are empty" {
                { Validate-MemberParameters -MembersToExclude @() -MembersToInclude @() } | Should Throw 'At least one member must be specified';
            }

        }
        #end region

    }
    #endregion
}
finally
{
    #region FOOTER
    
    #endregion
}
