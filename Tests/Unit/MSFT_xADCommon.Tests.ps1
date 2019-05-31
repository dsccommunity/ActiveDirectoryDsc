[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param()

$Global:DSCModuleName      = 'xActiveDirectory' # Example xNetworking
$Global:DSCResourceName    = 'MSFT_xADCommon' # Example MSFT_xFirewall

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
Write-Host $moduleRoot -ForegroundColor Green;
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

function Invoke-TestSetup
{
    # If one type does not exist, it's assumed the other ones does not exist either.
    if (-not ('Microsoft.DirectoryServices.Deployment.Types.ForestMode' -as [Type]))
    {
        Add-Type -Path (Join-Path -Path (Join-Path -Path (Join-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'Tests') -ChildPath 'Unit') -ChildPath 'Stubs') -ChildPath 'Microsoft.DirectoryServices.Deployment.Types.cs')
    }

    # If one type does not exist, it's assumed the other ones does not exist either.
    if (-not ('Microsoft.ActiveDirectory.Management.ADForestMode' -as [Type]))
    {
        Add-Type -Path (Join-Path -Path (Join-Path -Path (Join-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'Tests') -ChildPath 'Unit') -ChildPath 'Stubs') -ChildPath 'Microsoft.ActiveDirectory.Management.cs')
    }
}

# Begin Testing
try
{
    Invoke-TestSetup

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
                Mock -CommandName Get-CimInstance -MockWith { return @{ Name = $env:COMPUTERNAME; PartOfDomain = $true; } }

                Test-DomainMember | Should Be $true;
            }

            It 'Returns "False" when workgroup member' {
                Mock -CommandName Get-CimInstance -MockWith { return @{ Name = $env:COMPUTERNAME; } }

                Test-DomainMember | Should Be $false;
            }

        }
        #endregion

        #region Function Get-DomainName
        Describe "$($Global:DSCResourceName)\Get-DomainName" {

            It 'Returns exepected domain name' {
                Mock -CommandName Get-CimInstance -MockWith { return @{ Name = $env:COMPUTERNAME; Domain = 'contoso.com'; } }

                Get-DomainName | Should Be 'contoso.com';
            }

        }
        #endregion

        #region Function Assert-Module
        Describe "$($Global:DSCResourceName)\Assert-Module" {

            It 'Does not throw when module is installed' {
                $testModuleName = 'TestModule';
                Mock -CommandName Get-Module -ParameterFilter { $Name -eq $testModuleName } -MockWith { return $true; }

                { Assert-Module -ModuleName $testModuleName } | Should Not Throw;
            }

            It 'Should call Import-Module when the module is installed and ImportModule is specified' {
                $testModuleName = 'TestModule'
                Mock -CommandName Get-Module -ParameterFilter { $Name -eq $testModuleName } -MockWith { return $true; }
                Mock -CommandName Import-Module -ParameterFilter { $Name -eq $testModuleName }

                Assert-Module -ModuleName $testModuleName -ImportModule

                Assert-MockCalled -CommandName Import-Module
            }

            It 'Throws when module is not installed' {
                $testModuleName = 'TestModule';
                Mock -CommandName Get-Module -ParameterFilter { $Name -eq $testModuleName }

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
        #endregion

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
        #endregion

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
        #endregion

        #region Function Assert-MemberParameters
        Describe "$($Global:DSCResourceName)\Assert-MemberParameters" {

            It "Throws if 'Members' is specified but is empty" {
                { Assert-MemberParameters -Members @() } | Should Throw 'The Members parameter value is null';
            }

            It "Throws if 'Members' and 'MembersToInclude' are specified" {
                { Assert-MemberParameters -Members @('User1') -MembersToInclude @('User1') } | Should Throw 'parameters conflict';
            }

            It "Throws if 'Members' and 'MembersToExclude' are specified" {
                { Assert-MemberParameters -Members @('User1') -MembersToExclude @('User2') } | Should Throw 'parameters conflict';
            }

            It "Throws if 'MembersToInclude' and 'MembersToExclude' contain the same member" {
                { Assert-MemberParameters -MembersToExclude @('user1') -MembersToInclude @('USER1') } | Should Throw 'member must not be included in both';
            }

            It "Throws if 'MembersToInclude' and 'MembersToExclude' are empty" {
                { Assert-MemberParameters -MembersToExclude @() -MembersToInclude @() } | Should Throw 'At least one member must be specified';
            }

        }
        #endregion

        #region Function ConvertTo-Timespan
        Describe "$($Global:DSCResourceName)\ConvertTo-Timespan" {

            It "Returns 'System.TimeSpan' object type" {
                $testIntTimeSpan = 60;

                $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Minutes;

                $result -is [System.TimeSpan] | Should Be $true;
            }

            It "Creates TimeSpan from seconds" {
                $testIntTimeSpan = 60;

                $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Seconds;

                $result.TotalSeconds | Should Be $testIntTimeSpan;
            }

            It "Creates TimeSpan from minutes" {
                $testIntTimeSpan = 60;

                $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Minutes;

                $result.TotalMinutes | Should Be $testIntTimeSpan;
            }

            It "Creates TimeSpan from hours" {
                $testIntTimeSpan = 60;

                $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Hours;

                $result.TotalHours | Should Be $testIntTimeSpan;
            }

            It "Creates TimeSpan from days" {
                $testIntTimeSpan = 60;

                $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Days;

                $result.TotalDays | Should Be $testIntTimeSpan;
            }

        }
        #endregion

        #region Function ConvertTo-Timespan
        Describe "$($Global:DSCResourceName)\ConvertFrom-Timespan" {

            It "Returns 'System.UInt32' object type" {
                $testIntTimeSpan = 60;
                $testTimeSpan = New-TimeSpan -Seconds $testIntTimeSpan;

                $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Seconds;

                $result -is [System.UInt32] | Should Be $true;
            }

            It "Converts TimeSpan to total seconds" {
                $testIntTimeSpan = 60;
                $testTimeSpan = New-TimeSpan -Seconds $testIntTimeSpan;

                $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Seconds;

                $result | Should Be $testTimeSpan.TotalSeconds;
            }

            It "Converts TimeSpan to total minutes" {
                $testIntTimeSpan = 60;
                $testTimeSpan = New-TimeSpan -Minutes $testIntTimeSpan;

                $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Minutes;

                $result | Should Be $testTimeSpan.TotalMinutes;
            }

            It "Converts TimeSpan to total hours" {
                $testIntTimeSpan = 60;
                $testTimeSpan = New-TimeSpan -Hours $testIntTimeSpan;

                $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Hours;

                $result | Should Be $testTimeSpan.TotalHours;
            }

            It "Converts TimeSpan to total days" {
                $testIntTimeSpan = 60;
                $testTimeSpan = New-TimeSpan -Days $testIntTimeSpan;

                $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Days;

                $result | Should Be $testTimeSpan.TotalDays;
            }

        }
        #endregion

        #region Function Get-ADCommonParameters
        Describe "$($Global:DSCResourceName)\Get-ADCommonParameters" {

            It "Returns 'System.Collections.Hashtable' object type" {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity;

                $result -is [System.Collections.Hashtable] | Should Be $true;
            }

            It "Returns 'Identity' key by default" {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity;

                $result['Identity'] | Should Be $testIdentity;
            }

            It "Returns 'Name' key when 'UseNameParameter' is specified" {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity -UseNameParameter;

                $result['Name'] | Should Be $testIdentity;
            }

            foreach ($identityParam in @('UserName','GroupName','ComputerName'))
            {
                It "Returns 'Identity' key when '$identityParam' alias is specified" {
                    $testIdentity = 'contoso.com';
                    $getADCommonParameters = @{
                        $identityParam = $testIdentity;
                    }

                    $result = Get-ADCommonParameters @getADCommonParameters;

                    $result['Identity'] | Should Be $testIdentity;
                }
            }

            It "Returns 'Identity' key by default when 'Identity' and 'CommonName' are specified" {
                $testIdentity = 'contoso.com';
                $testCommonName = 'Test Common Name';

                $result = Get-ADCommonParameters -Identity $testIdentity -CommonName $testCommonName;

                $result['Identity'] | Should Be $testIdentity;
            }

            It "Returns 'Identity' key with 'CommonName' when 'Identity', 'CommonName' and 'PreferCommonName' are specified" {
                $testIdentity = 'contoso.com';
                $testCommonName = 'Test Common Name';

                $result = Get-ADCommonParameters -Identity $testIdentity -CommonName $testCommonName -PreferCommonName;

                $result['Identity'] | Should Be $testCommonName;
            }

            It "Returns 'Identity' key with 'Identity' when 'Identity' and 'PreferCommonName' are specified" {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity -PreferCommonName;

                $result['Identity'] | Should Be $testIdentity;
            }

            it "Returns 'Name' key when 'UseNameParameter' and 'PreferCommonName' are supplied" {
                $testIdentity = 'contoso.com';
                $testCommonName = 'Test Common Name';

                $result = Get-ADCommonParameters -Identity $testIdentity -UseNameParameter -CommonName $testCommonName -PreferCommonName;

                $result['Name'] | Should Be $testCommonName;
            }

            It "Does not return 'Credential' key by default" {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity;

                $result.ContainsKey('Credential') | Should Be $false;
            }

            It "Returns 'Credential' key when specified" {
                $testIdentity = 'contoso.com';
                $testCredential = [System.Management.Automation.PSCredential]::Empty;

                $result = Get-ADCommonParameters -Identity $testIdentity -Credential $testCredential;

                $result['Credential'] | Should Be $testCredential;
            }

            It "Does not return 'Server' key by default" {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity;

                $result.ContainsKey('Server') | Should Be $false;
            }

            It "Returns 'Server' key when specified" {
                $testIdentity = 'contoso.com';
                $testServer = 'testserver.contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity -Server $testServer;

                $result['Server'] | Should Be $testServer;
            }

            It "Converts 'DomainAdministratorCredential' parameter to 'Credential' key" {
                $testIdentity = 'contoso.com';
                $testCredential = [System.Management.Automation.PSCredential]::Empty;

                $result = Get-ADCommonParameters -Identity $testIdentity -DomainAdministratorCredential $testCredential;

                $result['Credential'] | Should Be $testCredential;
            }

            It "Converts 'DomainController' parameter to 'Server' key" {
                $testIdentity = 'contoso.com';
                $testServer = 'testserver.contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity -DomainController $testServer;

                $result['Server'] | Should Be $testServer;
            }

            It 'Accepts remaining arguments' {
                $testIdentity = 'contoso.com';

                $result = Get-ADCommonParameters -Identity $testIdentity -UnexpectedParameter 42;

                $result['Identity'] | Should Be $testIdentity;
            }

        }
        #endregion

        #region Function ConvertTo-DeploymentForestMode
        Describe "$($Global:DSCResourceName)\ConvertTo-DeploymentForestMode" {
            It 'Converts an Microsoft.ActiveDirectory.Management.ForestMode to Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
                ConvertTo-DeploymentForestMode -Mode Windows2012Forest | Should BeOfType [Microsoft.DirectoryServices.Deployment.Types.ForestMode]
            }

            It 'Converts an Microsoft.ActiveDirectory.Management.ForestMode to the correct Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
                ConvertTo-DeploymentForestMode -Mode Windows2012Forest | Should Be ([Microsoft.DirectoryServices.Deployment.Types.ForestMode]::Win2012)
            }

            It 'Converts valid integer to Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
                ConvertTo-DeploymentForestMode -ModeId 5 | Should BeOfType [Microsoft.DirectoryServices.Deployment.Types.ForestMode]
            }

            It 'Converts a valid integer to the correct Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
                ConvertTo-DeploymentForestMode -ModeId 5 | Should Be ([Microsoft.DirectoryServices.Deployment.Types.ForestMode]::Win2012)
            }

            It 'Throws an exception when an invalid forest mode is selected' {
                { ConvertTo-DeploymentForestMode -Mode Nonexistant } | Should Throw
            }

            It 'Throws no exception when a null value is passed' {
                { ConvertTo-DeploymentForestMode -Mode $null } | Should Not Throw
            }

            It 'Throws no exception when an invalid mode id is selected' {
                { ConvertTo-DeploymentForestMode -ModeId 666 } | Should Not Throw
            }

            It 'Returns $null when a null value is passed' {
                ConvertTo-DeploymentForestMode -Mode $null | Should Be $null
            }

            It 'Returns $null when an invalid mode id is selected' {
                ConvertTo-DeploymentForestMode -ModeId 666 | Should Be $null
            }
        }
        #endregion

        #region Function ConvertTo-DeploymentDomainMode
        Describe "$($Global:DSCResourceName)\ConvertTo-DeploymentDomainMode" {
            It 'Converts an Microsoft.ActiveDirectory.Management.DomainMode to Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
                ConvertTo-DeploymentDomainMode -Mode Windows2012Domain | Should BeOfType [Microsoft.DirectoryServices.Deployment.Types.DomainMode]
            }

            It 'Converts an Microsoft.ActiveDirectory.Management.DomainMode to the correct Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
                ConvertTo-DeploymentDomainMode -Mode Windows2012Domain | Should Be ([Microsoft.DirectoryServices.Deployment.Types.DomainMode]::Win2012)
            }

            It 'Converts valid integer to Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
                ConvertTo-DeploymentDomainMode -ModeId 5 | Should BeOfType [Microsoft.DirectoryServices.Deployment.Types.DomainMode]
            }

            It 'Converts a valid integer to the correct Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
                ConvertTo-DeploymentDomainMode -ModeId 5 | Should Be ([Microsoft.DirectoryServices.Deployment.Types.DomainMode]::Win2012)
            }

            It 'Throws an exception when an invalid domain mode is selected' {
                { ConvertTo-DeploymentDomainMode -Mode Nonexistant } | Should Throw
            }

            It 'Throws no exception when a null value is passed' {
                { ConvertTo-DeploymentDomainMode -Mode $null } | Should Not Throw
            }

            It 'Throws no exception when an invalid mode id is selected' {
                { ConvertTo-DeploymentDomainMode -ModeId 666 } | Should Not Throw
            }

            It 'Returns $null when a null value is passed' {
                ConvertTo-DeploymentDomainMode -Mode $null | Should Be $null
            }

            It 'Returns $null when an invalid mode id is selected' {
                ConvertTo-DeploymentDomainMode -ModeId 666 | Should Be $null
            }
        }
        #endregion

        #region Function Restore-ADCommonObject
        Describe "$($Global:DSCResourceName)\Restore-ADCommonObject" {
            $getAdObjectReturnValue = @(
                [PSCustomObject] @{
                    Deleted           = $true
                    DistinguishedName = 'CN=a375347\0ADEL:f0e3f4fe-212b-43e7-83dd-c8f3b47ebb9c,CN=Deleted Objects,DC=contoso,DC=com'
                    Name              = 'a375347'
                    ObjectClass       = 'user'
                    ObjectGUID        = 'f0e3f4fe-212b-43e7-83dd-c8f3b47ebb9c'
                    # Make this one day older.
                    whenChanged       = (Get-Date).AddDays(-1)
                },
                [PSCustomObject] @{
                    Deleted           = $true
                    DistinguishedName = 'CN=a375347\0ADEL:d3c8b8c1-c42b-4533-af7d-3aa73ecd2216,CN=Deleted Objects,DC=contoso,DC=com'
                    Name              = 'a375347'
                    ObjectClass       = 'user'
                    ObjectGUID        = 'd3c8b8c1-c42b-4533-af7d-3aa73ecd2216'
                    whenChanged       = Get-Date
                }
            )

            $restoreAdObjectReturnValue = [PSCustomObject]@{
                DistinguishedName = 'CN=a375347,CN=Accounts,DC=contoso,DC=com'
                Name              = 'a375347'
                ObjectClass       = 'user'
                ObjectGUID        = 'd3c8b8c1-c42b-4533-af7d-3aa73ecd2216'
            }

            function Restore-ADObject
            {
            }

            $getAdCommonParameterReturnValue = @{Identity = 'something'}
            $restoreIdentity = 'SomeObjectName'
            $restoreObjectClass = 'user'
            $restoreObjectWrongClass = 'wrong'

            Context 'When there are objects in the recycle bin' {
                Mock -CommandName Get-ADObject -MockWith { return $getAdObjectReturnValue } -Verifiable
                Mock -CommandName Get-ADCommonParameters -MockWith { return $getAdCommonParameterReturnValue }
                Mock -CommandName Restore-ADObject -Verifiable

                It 'Should not throw when called with the correct parameters' {
                    {Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass} | Should -Not -Throw
                }

                It 'Should return the correct restored object' {
                    Mock -CommandName Restore-ADObject -MockWith { return $restoreAdObjectReturnValue}
                    (Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass).ObjectClass | Should -Be 'user'
                }

                It 'Should throw the correct error when invalid parameters are used' {
                    {Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectWrongClass} | Should -Throw "Cannot validate argument on parameter 'ObjectClass'"
                }

                It 'Should call Get-ADObject as well as Restore-ADObject' {
                    Assert-VerifiableMock
                }

                It 'Should throw an InvalidOperationException when object parent does not exist' {
                    Mock -CommandName Restore-ADObject -MockWith { throw (New-Object -TypeName Microsoft.ActiveDirectory.Management.ADException)}

                    {Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass} | Should -Throw -ExceptionType ([System.InvalidOperationException])
                }
            }

            Context 'When there are no objects in the recycle bin' {
                Mock -CommandName Get-ADObject
                Mock -CommandName Get-ADCommonParameters -MockWith { return $getAdCommonParameterReturnValue}
                Mock -CommandName Restore-ADObject

                It 'Should return $null' {
                    Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass | Should -Be $null
                }

                It 'Should not call Restore-ADObject' {
                    Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass
                    Assert-MockCalled -CommandName Restore-ADObject -Exactly -Times 0 -Scope It
                }
            }
        }
        #endregion

        #region Get-ADDomainNameFromDistinguishedName
        Describe "$($Global:DSCResourceName)\Get-ADDomainNameFromDistinguishedName" {
            $validDistinguishedNames = @(
                @{
                    DN     = 'CN=group1,OU=Group,OU=Wacken,DC=contoso,DC=com'
                    Domain = 'contoso.com'
                }
                @{
                    DN     = 'CN=group1,OU=Group,OU=Wacken,DC=sub,DC=contoso,DC=com'
                    Domain = 'sub.contoso.com'
                }
                @{
                    DN     = 'CN=group1,OU=Group,OU=Wacken,DC=child,DC=sub,DC=contoso,DC=com'
                    Domain = 'child.sub.contoso.com'
                }
            )
            $invalidDistinguishedNames = @(
                'Group1'
                'contoso\group1'
                'user1@contoso.com'
            )

            Context 'The distinguished name is valid' {
                foreach ($name in $validDistinguishedNames)
                {
                    It "Should match domain $($name.Domain)" {
                        Get-ADDomainNameFromDistinguishedName -DistinguishedName $name.Dn | Should -Be $name.Domain
                    }
                }
            }

            Context 'The distinguished name is invalid' {
                foreach ($name in $invalidDistinguishedNames)
                {
                    It "Should return `$null for $name" {
                        Get-ADDomainNameFromDistinguishedName -DistinguishedName $name | Should -Be $null
                    }
                }
            }
        }
        #endregion

        #region Add-AdCommonGroupMember
        Describe "$($Global:DSCResourceName)\Add-ADCommonGroupMember" {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            $memberData = @(
                [pscustomobject]@{
                    Name = 'CN=Account1,DC=contoso,DC=com'
                    Domain = 'contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Group1,DC=contoso,DC=com'
                    Domain = 'contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Computer1,DC=contoso,DC=com'
                    Domain = 'contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Account1,DC=a,DC=contoso,DC=com'
                    Domain = 'a.contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Group1,DC=a,DC=contoso,DC=com'
                    Domain = 'a.contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Computer1,DC=a,DC=contoso,DC=com'
                    Domain = 'a.contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Account1,DC=b,DC=contoso,DC=com'
                    Domain = 'b.contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Group1,DC=b,DC=contoso,DC=com'
                    Domain = 'b.contoso.com'
                }
                [pscustomobject]@{
                    Name = 'CN=Computer1,DC=b,DC=contoso,DC=com'
                    Domain = 'b.contoso.com'
                }
            )

            $invalidMemberData = @(
                'contoso.com\group1'
                'user1@contoso.com'
                'computer1.contoso.com'
            )

            $fakeParameters = @{
                Identity = 'SomeGroup'
            }

            Context 'When all members are in the same domain' {
                Mock -CommandName Add-ADGroupMember
                $groupCount = 0
                foreach ($domainGroup in ($memberData | Group-Object -Property Domain))
                {
                    $groupCount ++
                    It 'Should not throw an error when calling Add-ADCommonGroupMember' {
                        Add-ADCommonGroupMember -Members $domainGroup.Group.Name -Parameters $fakeParameters
                    }
                }

                It "Should have called Add-ADGroupMember $groupCount times" {
                    Assert-MockCalled -CommandName Add-ADGroupMember -Exactly -Times $groupCount
                }
            }

            Context 'When members are in different domains' {
                Mock -CommandName Add-ADGroupMember
                Mock -CommandName Get-ADObject -MockWith {
                    param (
                        [Parameter()]
                        [string]
                        $Identity,

                        [Parameter()]
                        [string]
                        $Server,

                        [Parameter()]
                        [string[]]
                        $Properties
                    )

                    $objectClass = switch ($Identity)
                    {
                        {$Identity -match 'Group'} { 'group' }
                        {$Identity -match 'Account'} { 'user' }
                        {$Identity -match 'Computer'} { 'computer' }
                    }

                    return ([PSCustomObject]@{
                            objectClass = $objectClass
                        })
                }
                # Mocks should return something that is used with Add-ADGroupMember
                Mock -CommandName Get-ADComputer -MockWith { return 'placeholder' }
                Mock -CommandName Get-ADGroup -MockWith { return 'placeholder' }
                Mock -CommandName Get-ADUser -MockWith { return 'placeholder' }

                It 'Should not throw an error' {
                    {Add-ADCommonGroupMember -Members $memberData.Name -Parameters $fakeParameters -MembersInMultipleDomains} | Should -Not -Throw
                }

                It 'Should have called all mocked cmdlets' {
                    Assert-MockCalled -CommandName Get-ADComputer -Exactly -Times $memberData.Where( {$_.Name -like '*Computer*'}).Count
                    Assert-MockCalled -CommandName Get-ADUser -Exactly -Times $memberData.Where( {$_.Name -like '*Account*'}).Count
                    Assert-MockCalled -CommandName Get-ADGroup -Exactly -Times $memberData.Where( {$_.Name -like '*Group*'}).Count
                    Assert-MockCalled -CommandName Add-ADGroupMember -Exactly -Times $memberData.Count
                }
            }

            Context 'When the domain name cannot be determined' {
                It 'Should throw an InvalidArgumentException' {
                    {Add-ADCommonGroupMember -Members $invalidMemberData  -Parameters $fakeParameters -MembersInMultipleDomains} | Should -Throw -ExceptionType ([System.ArgumentException])
                }
            }
        }
        #endregion

        Describe "$($Global:DSCResourceName)\Get-DomainControllerObject" {
            Context 'When domain name cannot be reached' {
                BeforeAll {
                    Mock -CommandName Get-ADDomainController -MockWith {
                        throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADServerDownException'
                    }
                }

                It 'Should throw the correct error' {
                    { Get-DomainControllerObject -DomainName 'contoso.com' -Verbose } | Should -Throw $localizedString.FailedEvaluatingDomainController

                    Assert-MockCalled -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
                }
            }

            Context 'When current node is not a domain controller' {
                BeforeAll {
                    Mock -CommandName Get-ADDomainController
                    Mock -CommandName Test-IsDomainController -MockWith {
                        return $false
                    }
                }

                It 'Should return $null' {
                    $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com' -Verbose
                    $getDomainControllerObjectResult | Should -BeNullOrEmpty

                    Assert-MockCalled -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
                }
            }

            Context 'When current node is not a domain controller, but operating system information says it should be' {
                BeforeAll {
                    Mock -CommandName Get-ADDomainController
                    Mock -CommandName Test-IsDomainController -MockWith {
                        return $true
                    }
                }

                It 'Should throw the correct error' {
                    { Get-DomainControllerObject -DomainName 'contoso.com' -Verbose } | Should -Throw $script:localizedData.WasExpectingDomainController

                    Assert-MockCalled -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
                }
            }

            Context 'When current node is a domain controller' {
                BeforeAll {
                    Mock -CommandName Get-ADDomainController -MockWith {
                        return @{
                            Site            = 'MySite'
                            Domain          = 'contoso.com'
                            IsGlobalCatalog = $true
                        }
                    }
                }

                It 'Should return the correct values for each property' {
                    $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com' -Verbose

                    $getDomainControllerObjectResult.Site | Should -Be 'MySite'
                    $getDomainControllerObjectResult.Domain | Should -Be 'contoso.com'
                    $getDomainControllerObjectResult.IsGlobalCatalog | Should -BeTrue

                    Assert-MockCalled -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
                }
            }

            Context 'When current node is a domain controller, and using specific credential' {
                BeforeAll {
                    Mock -CommandName Get-ADDomainController -MockWith {
                        return @{
                            Site            = 'MySite'
                            Domain          = 'contoso.com'
                            IsGlobalCatalog = $true
                        }
                    }

                    $mockAdministratorUser = 'admin@contoso.com'
                    $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force
                    $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @($mockAdministratorUser, $mockAdministratorPassword)
                }

                It 'Should return the correct values for each property' {
                    $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com' -Credential $mockAdministratorCredential -Verbose

                    $getDomainControllerObjectResult.Site | Should -Be 'MySite'
                    $getDomainControllerObjectResult.Domain | Should -Be 'contoso.com'
                    $getDomainControllerObjectResult.IsGlobalCatalog | Should -BeTrue

                    Assert-MockCalled -CommandName Get-ADDomainController -ParameterFilter {
                        $PSBoundParameters.ContainsKey('Credential') -eq $true
                    } -Exactly -Times 1 -Scope It
                }
            }
        }

        Describe "$($Global:DSCResourceName)\Test-IsDomainController" {
            Context 'When operating system information says the node is a domain controller' {
                BeforeAll {
                    Mock -CommandName Get-CimInstance -MockWith {
                        return @{
                            ProductType = 2
                        }
                    }
                }

                It 'Should return $true' {
                    $testIsDomainControllerResult = Test-IsDomainController
                    $testIsDomainControllerResult | Should -BeTrue

                    Assert-MockCalled -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
                }
            }

            Context 'When operating system information says the node is not a domain controller' {
                BeforeAll {
                    Mock -CommandName Get-CimInstance -MockWith {
                        return @{
                            ProductType = 3
                        }
                    }
                }

                It 'Should return $false' {
                    $testIsDomainControllerResult = Test-IsDomainController
                    $testIsDomainControllerResult | Should -BeFalse

                    Assert-MockCalled -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
                }
            }
        }

        Describe "$($Global:DSCResourceName)\Convert-PropertyMapToObjectProperties" {
            Context 'When a property map should be converted to object properties' {
                BeforeAll {
                    $propertyMapValue = @(
                        @{
                            ParameterName = 'ComputerName'
                            PropertyName = 'cn'
                        },
                        @{
                            ParameterName = 'Location'
                        }
                    )
                }

                It 'Should return the correct values' {
                    $convertPropertyMapToObjectPropertiesResult = Convert-PropertyMapToObjectProperties $propertyMapValue
                    $convertPropertyMapToObjectPropertiesResult | Should -HaveCount 2
                    $convertPropertyMapToObjectPropertiesResult[0] | Should -Be 'cn'
                    $convertPropertyMapToObjectPropertiesResult[1] | Should -Be 'Location'
                }
            }

            Context 'When a property map contains a wrong type' {
                BeforeAll {
                    $propertyMapValue = @(
                        @{
                            ParameterName = 'ComputerName'
                            PropertyName = 'cn'
                        },
                        'Location'
                    )
                }

                It 'Should throw the correct error' {
                    {
                        Convert-PropertyMapToObjectProperties $propertyMapValue
                    } | Should -Throw $localizedString.PropertyMapArrayIsWrongType
                }
            }
        }

        Describe 'DscResource.Common\Test-DscPropertyState' -Tag 'TestDscPropertyState' {
            Context 'When comparing tables' {
                It 'Should return true for two identical tables' {
                    $mockValues = @{
                        CurrentValue = 'Test'
                        DesiredValue = 'Test'
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When comparing strings' {
                It 'Should return false when a value is different for [System.String]' {
                    $mockValues = @{
                        CurrentValue = [System.String] 'something'
                        DesiredValue = [System.String] 'test'
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }

                It 'Should return false when a String value is missing' {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.String] 'Something'
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When comparing integers' {
                It 'Should return false when a value is different for [System.Int32]' {
                    $mockValues = @{
                        CurrentValue = [System.Int32] 1
                        DesiredValue = [System.Int32] 2
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }

                It 'Should return false when a value is different for [Int16]' {
                    $mockValues = @{
                        CurrentValue = [System.Int16] 1
                        DesiredValue = [System.Int16] 2
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }

                It 'Should return false when a value is different for [UInt16]' {
                    $mockValues = @{
                        CurrentValue = [System.UInt16] 1
                        DesiredValue = [System.UInt16] 2
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }

                It 'Should return false when a Integer value is missing' {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.Int32] 1
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When comparing booleans' {
                It 'Should return false when a value is different for [Boolean]' {
                    $mockValues = @{
                        CurrentValue = [System.Boolean] $true
                        DesiredValue = [System.Boolean] $false
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }

                It 'Should return false when a Boolean value is missing' {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.Boolean] $true
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When comparing arrays' {
                It 'Should return true when evaluating an array' {
                    $mockValues = @{
                        CurrentValue = @('1','2')
                        DesiredValue = @('1','2')
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }

                It 'Should return false when evaluating an array with wrong values' {
                    $mockValues = @{
                        CurrentValue = @('CurrentValueA','CurrentValueB')
                        DesiredValue = @('DesiredValue1','DesiredValue2')
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }

                It 'Should return false when evaluating an array, but the current value is $null' {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = @('1','2')
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context -Name 'When passing invalid types for DesiredValue' {
                It 'Should write a warning when DesiredValue contain an unsupported type' {
                    Mock -CommandName Write-Warning -Verifiable

                    # This is a dummy type to test with a type that could never be a correct one.
                    class MockUnknownType
                    {
                        [ValidateNotNullOrEmpty()]
                        [System.String]
                        $Property1

                        [ValidateNotNullOrEmpty()]
                        [System.String]
                        $Property2

                        MockUnknownType()
                        {
                        }
                    }

                    $mockValues = @{
                        CurrentValue = New-Object -TypeName MockUnknownType
                        DesiredValue = New-Object -TypeName MockUnknownType
                    }

                    Test-DscPropertyState -Values $mockValues | Should -Be $false

                    Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
                }
            }

            Assert-VerifiableMock
        }

        Describe "$($Global:DSCResourceName)\Compare-ResourcePropertyState" {
            Context 'When one property is in desired state' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 1
                    $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult.Expected | Should -Be 'DC01'
                    $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult.InDesiredState | Should -BeTrue
                }
            }

            Context 'When two properties are in desired state' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                        Location = 'Sweden'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                        Location = 'Sweden'
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 2
                    $compareTargetResourceStateResult[0].ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult[0].Expected | Should -Be 'DC01'
                    $compareTargetResourceStateResult[0].Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult[0].InDesiredState | Should -BeTrue
                    $compareTargetResourceStateResult[1].ParameterName | Should -Be 'Location'
                    $compareTargetResourceStateResult[1].Expected | Should -Be 'Sweden'
                    $compareTargetResourceStateResult[1].Actual | Should -Be 'Sweden'
                    $compareTargetResourceStateResult[1].InDesiredState | Should -BeTrue
                }
            }

            Context 'When passing just one property and that property is not in desired state' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'APP01'
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 1
                    $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult.Expected | Should -Be 'APP01'
                    $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult.InDesiredState | Should -BeFalse
                }
            }

            Context 'When passing two properties and one property is not in desired state' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                        Location = 'Sweden'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                        Location = 'Europe'
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 2
                    $compareTargetResourceStateResult[0].ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult[0].Expected | Should -Be 'DC01'
                    $compareTargetResourceStateResult[0].Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult[0].InDesiredState | Should -BeTrue
                    $compareTargetResourceStateResult[1].ParameterName | Should -Be 'Location'
                    $compareTargetResourceStateResult[1].Expected | Should -Be 'Europe'
                    $compareTargetResourceStateResult[1].Actual | Should -Be 'Sweden'
                    $compareTargetResourceStateResult[1].InDesiredState | Should -BeFalse
                }
            }

            Context 'When passing a common parameter set to desired value' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                        Verbose = $true
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 1
                    $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult.Expected | Should -Be 'DC01'
                    $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult.InDesiredState | Should -BeTrue
                }
            }

            Context 'When using parameter Properties to compare desired values' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                        Location = 'Sweden'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                        Location = 'Europe'
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                        Properties = @(
                            'ComputerName'
                        )
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 1
                    $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult.Expected | Should -Be 'DC01'
                    $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult.InDesiredState | Should -BeTrue
                }
            }

            Context 'When using parameter Properties and IgnoreProperties to compare desired values' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                        Location = 'Sweden'
                        Ensure = 'Present'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                        Location = 'Europe'
                        Ensure = 'Absent'
                    }
                }

                It 'Should return the correct values' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                        IgnoreProperties = @(
                            'Ensure'
                        )
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -HaveCount 2
                    $compareTargetResourceStateResult[0].ParameterName | Should -Be 'ComputerName'
                    $compareTargetResourceStateResult[0].Expected | Should -Be 'DC01'
                    $compareTargetResourceStateResult[0].Actual | Should -Be 'DC01'
                    $compareTargetResourceStateResult[0].InDesiredState | Should -BeTrue
                    $compareTargetResourceStateResult[1].ParameterName | Should -Be 'Location'
                    $compareTargetResourceStateResult[1].Expected | Should -Be 'Europe'
                    $compareTargetResourceStateResult[1].Actual | Should -Be 'Sweden'
                    $compareTargetResourceStateResult[1].InDesiredState | Should -BeFalse
                }
            }

            Context 'When using parameter Properties and IgnoreProperties to compare desired values' {
                BeforeAll {
                    $mockCurrentValues = @{
                        ComputerName = 'DC01'
                        Location = 'Sweden'
                        Ensure = 'Present'
                    }

                    $mockDesiredValues = @{
                        ComputerName = 'DC01'
                        Location = 'Europe'
                        Ensure = 'Absent'
                    }
                }

                It 'Should return and empty array' {
                    $compareTargetResourceStateParameters = @{
                        CurrentValues = $mockCurrentValues
                        DesiredValues = $mockDesiredValues
                        Properties = @(
                            'ComputerName'
                        )
                        IgnoreProperties = @(
                            'ComputerName'
                        )
                    }

                    $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                    $compareTargetResourceStateResult | Should -BeNullOrEmpty
                }
            }
        }
        #region Function Assert-ADPSDrive
        Describe "$($Global:DSCResourceName)\Assert-ADPSDrive" {
            Mock -CommandName Assert-Module

            Context 'When the AD PS Drive does not exist and the New-PSDrive function is successful' {
                Mock -CommandName Get-PSDrive -MockWith { throw 'Error' }
                Mock -CommandName New-PSDrive

                It 'Should not throw' {
                    { Assert-ADPSDrive } | Should -Not -Throw
                }

                It 'Should have called Assert-Module' {
                    Assert-MockCalled -CommandName Assert-Module -Exactly -Times 1 -Scope Context
                }

                It 'Should have called Get-PSDrive only once' {
                    Assert-MockCalled -CommandName Get-PSDrive -Exactly -Times 1 -Scope Context
                }

                It 'Should have called New-PSDrive only once' {
                    Assert-MockCalled -CommandName New-PSDrive -Exactly -Times 1 -Scope Context
                }
            }

            Context 'When the AD PS Drive does not exist and the New-PSDrive function is not successful' {
                Mock -CommandName Get-PSDrive -MockWith { throw 'Error' }
                Mock -CommandName New-PSDrive -MockWith { throw }

                It 'Should throw the correct error' {
                    { Assert-ADPSDrive } | Should -Throw $script:localizedString.CreatingNewADPSDriveError
                }

                It 'Should call Assert-Module' {
                    Assert-MockCalled -CommandName Assert-Module -Exactly -Times 1 -Scope Context
                }

                It 'Should call Get-PSDrive once' {
                    Assert-MockCalled -CommandName Get-PSDrive -Exactly -Times 1 -Scope Context
                }

                It 'Should call New-PSDrive once' {
                    Assert-MockCalled -CommandName New-PSDrive -Exactly -Times 1 -Scope Context
                }
            }

            Context 'When the AD PS Drive already exists' {
                Mock -CommandName Get-PSDrive
                Mock -CommandName New-PSDrive

                It 'Should not throw' {
                  { Assert-ADPSDrive } | Should -Not -Throw
                }

                It 'Should call Assert-Module only once' {
                    Assert-MockCalled -CommandName Assert-Module -Exactly -Times 1 -Scope Context
                }

                It 'Should call Get-PSDrive only once' {
                    Assert-MockCalled -CommandName Get-PSDrive -Exactly -Times 1 -Scope Context
                }

                It 'Should not call New-PSDrive' {
                    Assert-MockCalled -CommandName New-PSDrive -Exactly -Times 0 -Scope Context
                }
            }
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
