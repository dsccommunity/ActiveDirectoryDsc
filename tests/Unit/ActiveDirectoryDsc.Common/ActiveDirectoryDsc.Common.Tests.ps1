# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies has not been resolved, this will throw an error.
            Import-Module -Name 'DscResource.Test' -Force -ErrorAction 'Stop'
        }
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -ResolveDependency -Tasks build" first.'
    }
}

BeforeAll {
    $script:dscModuleName = 'ActiveDirectoryDsc'
    $script:subModuleName = 'ActiveDirectoryDsc.Common'

    $script:parentModule = Get-Module -Name $script:dscModuleName -ListAvailable | Select-Object -First 1
    $script:subModulesFolder = Join-Path -Path $script:parentModule.ModuleBase -ChildPath 'Modules'

    $script:subModulePath = Join-Path -Path $script:subModulesFolder -ChildPath $script:subModuleName

    Import-Module -Name $script:subModulePath -Force -ErrorAction 'Stop'

    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Stubs\ActiveDirectory_2019.psm1') -Force
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Stubs\ADDSDeployment_2019.psm1') -Force

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:subModuleName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:subModuleName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:subModuleName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    # Unload stub module
    Remove-Module -Name ActiveDirectory_2019 -Force
    Remove-Module -Name ADDSDeployment_2019 -Force

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:subModuleName -All | Remove-Module -Force
}

Describe 'DscResource.Common\Start-ProcessWithTimeout' {
    Context 'When starting a process successfully' {
        It 'Should return exit code 0' {
            $startProcessWithTimeoutParameters = @{
                FilePath     = 'powershell.exe'
                ArgumentList = '-Command &{Start-Sleep -Seconds 2}'
                Timeout      = 300
            }

            $processExitCode = Start-ProcessWithTimeout @startProcessWithTimeoutParameters
            $processExitCode | Should -BeExactly 0
        }
    }

    Context 'When starting a process and the process does not finish before the timeout period' {
        It 'Should throw an error message' {
            $startProcessWithTimeoutParameters = @{
                FilePath     = 'powershell.exe'
                ArgumentList = '-Command &{Start-Sleep -Seconds 4}'
                Timeout      = 2
            }

            { Start-ProcessWithTimeout @startProcessWithTimeoutParameters } | Should -Throw -ErrorId 'ProcessNotTerminated,Microsoft.PowerShell.Commands.WaitProcessCommand'
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Test-DomainMember' {
    Context 'When a domain member' {
        BeforeAll {
            Mock -CommandName Get-CimInstance -MockWith {
                return @{
                    Name         = $env:COMPUTERNAME
                    PartOfDomain = $true
                }
            }
        }

        It 'Should return "True"' {

            Test-DomainMember | Should -BeTrue
        }
    }

    Context 'When a workgroup member' {
        BeforeAll {
            Mock -CommandName Get-CimInstance -MockWith {
                return @{
                    Name = $env:COMPUTERNAME
                }
            }
        }

        It 'Should return "False"' {

            Test-DomainMember | Should -BeFalse
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Get-DomainName' {
    BeforeAll {
        Mock -CommandName Get-CimInstance -MockWith {
            return @{
                Name   = $env:COMPUTERNAME
                Domain = 'contoso.com'
            }
        }
    }

    It 'Should return the expected domain name' {
        Get-DomainName | Should -Be 'contoso.com'
    }
}

Describe 'ActiveDirectoryDsc.Common\Get-ADObjectParentDN' {
    It 'Should return the CN object parent path' {
        Get-ADObjectParentDN -DN 'CN=Administrator,CN=Users,DC=contoso,DC=com' | Should -Be 'CN=Users,DC=contoso,DC=com'
    }

    It 'Should return the OU object parent path' {
        Get-ADObjectParentDN -DN 'CN=Administrator,OU=Custom Organizational Unit,DC=contoso,DC=com' | Should -Be 'OU=Custom Organizational Unit,DC=contoso,DC=com'
    }
}

Describe 'ActiveDirectoryDsc.Common\Remove-DuplicateMembers' {
    It 'Should remove one duplicate' {
        $members = Remove-DuplicateMembers -Members 'User1', 'User2', 'USER1'

        $members.Count | Should -Be 2
        $members -contains 'User1' | Should -BeTrue
        $members -contains 'User2' | Should -BeTrue
        $members -is [System.Array] | Should -BeTrue
    }

    It 'Should remove two duplicates' {
        $members = Remove-DuplicateMembers -Members 'User1', 'User2', 'USER1', 'USER2'

        $members.Count | Should -Be 2
        $members -contains 'User1' | Should -BeTrue
        $members -contains 'User2' | Should -BeTrue
        $members -is [System.Array] | Should -BeTrue
    }

    It 'Should remove double duplicates' {
        $members = Remove-DuplicateMembers -Members 'User1', 'User2', 'USER1', 'user1'

        $members.Count | Should -Be 2
        $members -contains 'User1' | Should -BeTrue
        $members -contains 'User2' | Should -BeTrue
        $members -is [System.Array] | Should -BeTrue
    }

    It 'Should return a string array with one one entry' {
        $members = Remove-DuplicateMembers -Members 'User1', 'USER1', 'user1'

        $members.Count | Should -Be 1
        $members -contains 'User1' | Should -BeTrue
        $members -is [System.Array] | Should -BeTrue
    }

    It 'Should return an empty collection when passed a $null value' {
        $members = Remove-DuplicateMembers -Members $null

        $members.Count | Should -Be 0
        $members -is [System.Array] | Should -BeTrue
    }

    It 'Should return an empty collection when passed an empty collection' {
        $members = Remove-DuplicateMembers -Members @()

        $members.Count | Should -Be 0
        $members -is [System.Array] | Should -BeTrue
    }
}

Describe 'ActiveDirectoryDsc.Common\Test-Members' {
    It 'Passes when nothing is passed' {
        Test-Members -ExistingMembers $null | Should -BeTrue
    }

    It 'Passes when there are existing members but members are required' {
        $testExistingMembers = @('USER1', 'USER2')

        Test-Members -ExistingMembers $testExistingMembers | Should -BeTrue
    }

    It 'Passes when existing members match required members' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembers = @('USER2', 'USER1')

        Test-Members -ExistingMembers $testExistingMembers -Members $testMembers | Should -BeTrue
    }

    It 'Fails when there are no existing members and members are required' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembers = @('USER1', 'USER3')

        Test-Members -ExistingMembers $null -Members $testMembers | Should -BeFalse
    }

    It 'Fails when there are more existing members than the members required' {
        $testExistingMembers = @('USER1', 'USER2', 'USER3')
        $testMembers = @('USER1', 'USER3')

        Test-Members -ExistingMembers $null -Members $testMembers | Should -BeFalse
    }

    It 'Fails when there are more existing members than the members required' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembers = @('USER1', 'USER3', 'USER2')

        Test-Members -ExistingMembers $null -Members $testMembers | Should -BeFalse
    }

    It 'Fails when existing members do not match required members' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembers = @('USER1', 'USER3')

        Test-Members -ExistingMembers $testExistingMembers -Members $testMembers | Should -BeFalse
    }

    It 'Passes when existing members include required member' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToInclude = @('USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeTrue
    }

    It 'Passes when existing members include required members' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToInclude = @('USER2', 'USER1')

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeTrue
    }

    It 'Fails when existing members is missing a required member' {
        $testExistingMembers = @('USER1')
        $testMembersToInclude = @('USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeFalse
    }

    It 'Fails when existing members is missing a required member' {
        $testExistingMembers = @('USER1', 'USER3')
        $testMembersToInclude = @('USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeFalse
    }

    It 'Fails when existing members is missing a required members' {
        $testExistingMembers = @('USER3')
        $testMembersToInclude = @('USER1', 'USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeFalse
    }

    It 'Passes when existing member does not include excluded member' {
        $testExistingMembers = @('USER1')
        $testMembersToExclude = @('USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToExclude | Should -BeTrue
    }

    It 'Passes when existing member does not include excluded members' {
        $testExistingMembers = @('USER1')
        $testMembersToExclude = @('USER2', 'USER3')

        Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToExclude | Should -BeTrue
    }

    It 'Passes when existing members does not include excluded member' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToExclude = @('USER3')

        Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToExclude | Should -BeTrue
    }

    It 'Should fail when an existing members is include as an excluded member' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToExclude = @('USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToExclude | Should -BeFalse
    }

    It 'Should pass when MembersToExclude is set to $null' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToExclude = $null

        Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToExclude | Should -BeTrue
    }

    It 'Should pass when MembersToInclude is set to $null' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToInclude = $null

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeTrue
    }

    It 'Should fail when Members is set to $null' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembers = $null

        Test-Members -ExistingMembers $testExistingMembers -Members $testMembers | Should -BeFalse
    }

    It 'Should fail when multiple Members are the wrong members' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembers = @('USER3', 'USER4')

        Test-Members -ExistingMembers $testExistingMembers -Members $testMembers | Should -BeFalse
    }

    It 'Should fail when multiple MembersToInclude are not present in existing members' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToInclude = @('USER3', 'USER4')

        Test-Members -ExistingMembers $testExistingMembers -MembersToInclude $testMembersToInclude | Should -BeFalse
    }

    It 'Should fail when multiple MembersToExclude are present in existing members' {
        $testExistingMembers = @('USER1', 'USER2')
        $testMembersToExclude = @('USER1', 'USER2')

        Test-Members -ExistingMembers $testExistingMembers -MembersToExclude $testMembersToExclude | Should -BeFalse
    }
}

Describe 'ActiveDirectoryDsc.Common\Assert-MemberParameters' {
    Context 'When only the Members parameter is specified' {
        It 'Should not throw' {
            $assertMemberParameters = @{
                Members = 'User1'
            }

            { Assert-MemberParameters @AssertMemberParameters } | Should -Not -Throw
        }
    }

    Context 'When both the Members and MembersToInclude parameters are specified' {
        It 'Should throw the expected error' {
            $assertMemberParameters = @{
                Members          = 'User1', 'User2'
                MembersToInclude = 'User2', 'User3'
            }

            $expectedError = ($script:localizedData.MembersAndIncludeExcludeError -f
                'Members', 'MembersToInclude', 'MembersToExclude')

            { Assert-MemberParameters @AssertMemberParameters } | Should -Throw $expectedError
        }
    }

    Context 'When both the Members and MembersToExclude parameters are specified' {
        It 'Should throw the expected error' {
            $assertMemberParameters = @{
                Members          = 'User1', 'User2'
                MembersToExclude = 'User3', 'User4'
            }

            $expectedError = ($script:localizedData.MembersAndIncludeExcludeError -f
                'Members', 'MembersToInclude', 'MembersToExclude')

            { Assert-MemberParameters @AssertMemberParameters } |
                Should -Throw $expectedError
        }
    }

    Context 'When both the MembersToInclude and MembersToExclude parameters contain different members' {
        It 'Should not throw' {
            $assertMemberParameters = @{
                MembersToInclude = 'User1', 'User2'
                MembersToExclude = 'User3', 'User4'
            }

            { Assert-MemberParameters @AssertMemberParameters } |
                Should -Not -Throw
        }
    }

    Context 'When both the MembersToInclude and MembersToExclude parameters contain the same member' {
        It 'Should throw the expected error' {
            $testMember = 'user1'
            $assertMemberParameters = @{
                MembersToInclude = $testMember
                MembersToExclude = $testMember
            }

            $expectedError = ($script:localizedData.IncludeAndExcludeConflictError -f
                $testMember, 'MembersToInclude', 'MembersToExclude')

            { Assert-MemberParameters @AssertMemberParameters } | Should -Throw $expectedError
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\ConvertTo-Timespan' {
    It "Returns 'System.TimeSpan' object type" {
        $testIntTimeSpan = 60

        $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Minutes

        $result -is [System.TimeSpan] | Should -BeTrue
    }

    It 'Creates TimeSpan from seconds' {
        $testIntTimeSpan = 60

        $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Seconds

        $result.TotalSeconds | Should -Be $testIntTimeSpan
    }

    It 'Creates TimeSpan from minutes' {
        $testIntTimeSpan = 60

        $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Minutes

        $result.TotalMinutes | Should -Be $testIntTimeSpan
    }

    It 'Creates TimeSpan from hours' {
        $testIntTimeSpan = 60

        $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Hours

        $result.TotalHours | Should -Be $testIntTimeSpan
    }

    It 'Creates TimeSpan from days' {
        $testIntTimeSpan = 60

        $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Days

        $result.TotalDays | Should -Be $testIntTimeSpan
    }
}

Describe 'ActiveDirectoryDsc.Common\ConvertFrom-Timespan' {
    It "Returns 'System.UInt32' object type" {
        $testIntTimeSpan = 60
        $testTimeSpan = New-TimeSpan -Seconds $testIntTimeSpan

        $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Seconds

        $result -is [System.UInt32] | Should -BeTrue
    }

    It 'Converts TimeSpan to total seconds' {
        $testIntTimeSpan = 60
        $testTimeSpan = New-TimeSpan -Seconds $testIntTimeSpan

        $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Seconds

        $result | Should -Be $testTimeSpan.TotalSeconds
    }

    It 'Converts TimeSpan to total minutes' {
        $testIntTimeSpan = 60
        $testTimeSpan = New-TimeSpan -Minutes $testIntTimeSpan

        $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Minutes

        $result | Should -Be $testTimeSpan.TotalMinutes
    }

    It 'Converts TimeSpan to total hours' {
        $testIntTimeSpan = 60
        $testTimeSpan = New-TimeSpan -Hours $testIntTimeSpan

        $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Hours

        $result | Should -Be $testTimeSpan.TotalHours
    }

    It 'Converts TimeSpan to total days' {
        $testIntTimeSpan = 60
        $testTimeSpan = New-TimeSpan -Days $testIntTimeSpan

        $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Days

        $result | Should -Be $testTimeSpan.TotalDays
    }
}

Describe 'ActiveDirectoryDsc.Common\Get-ADCommonParameters' {
    It "Returns 'System.Collections.Hashtable' object type" {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity

        $result -is [System.Collections.Hashtable] | Should -BeTrue
    }

    It "Returns 'Identity' key by default" {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity

        $result['Identity'] | Should -Be $testIdentity
    }

    It "Returns 'Name' key when 'UseNameParameter' is specified" {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity -UseNameParameter

        $result['Name'] | Should -Be $testIdentity
    }

    It "Returns 'Identity' key when <_> alias is specified" -ForEach @('UserName', 'GroupName', 'ComputerName') {
        $testIdentity = 'contoso.com'
        $getADCommonParameters = @{
            $_ = $testIdentity
        }

        $result = Get-ADCommonParameters @getADCommonParameters

        $result['Identity'] | Should -Be $testIdentity
    }

    It "Returns 'Identity' key by default when 'Identity' and 'CommonName' are specified" {
        $testIdentity = 'contoso.com'
        $testCommonName = 'Test Common Name'

        $result = Get-ADCommonParameters -Identity $testIdentity -CommonName $testCommonName

        $result['Identity'] | Should -Be $testIdentity
    }

    It "Returns 'Identity' key with 'CommonName' when 'Identity', 'CommonName' and 'PreferCommonName' are specified" {
        $testIdentity = 'contoso.com'
        $testCommonName = 'Test Common Name'

        $result = Get-ADCommonParameters -Identity $testIdentity -CommonName $testCommonName -PreferCommonName

        $result['Identity'] | Should -Be $testCommonName
    }

    It "Returns 'Identity' key with 'Identity' when 'Identity' and 'PreferCommonName' are specified" {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity -PreferCommonName

        $result['Identity'] | Should -Be $testIdentity
    }

    it "Returns 'Name' key when 'UseNameParameter' and 'PreferCommonName' are supplied" {
        $testIdentity = 'contoso.com'
        $testCommonName = 'Test Common Name'

        $result = Get-ADCommonParameters -Identity $testIdentity -UseNameParameter -CommonName $testCommonName -PreferCommonName

        $result['Name'] | Should -Be $testCommonName
    }

    It "Does not return 'Credential' key by default" {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity

        $result.ContainsKey('Credential') | Should -BeFalse
    }

    It "Returns 'Credential' key when specified" {
        $testIdentity = 'contoso.com'
        $testCredential = [System.Management.Automation.PSCredential]::Empty

        $result = Get-ADCommonParameters -Identity $testIdentity -Credential $testCredential

        $result['Credential'] | Should -Be $testCredential
    }

    It "Does not return 'Server' key by default" {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity

        $result.ContainsKey('Server') | Should -BeFalse
    }

    It "Returns 'Server' key when specified" {
        $testIdentity = 'contoso.com'
        $testServer = 'testserver.contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity -Server $testServer

        $result['Server'] | Should -Be $testServer
    }

    It "Converts 'DomainController' parameter to 'Server' key" {
        $testIdentity = 'contoso.com'
        $testServer = 'testserver.contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity -DomainController $testServer

        $result['Server'] | Should -Be $testServer
    }

    It 'Accepts remaining arguments' {
        $testIdentity = 'contoso.com'

        $result = Get-ADCommonParameters -Identity $testIdentity -UnexpectedParameter 42

        $result['Identity'] | Should -Be $testIdentity
    }
}

Describe 'ActiveDirectoryDsc.Common\ConvertTo-DeploymentForestMode' {
    It 'Converts an Microsoft.ActiveDirectory.Management.ForestMode to Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
        ConvertTo-DeploymentForestMode -Mode Windows2012Forest | Should -BeOfType [Microsoft.DirectoryServices.Deployment.Types.ForestMode]
    }

    It 'Converts an Microsoft.ActiveDirectory.Management.ForestMode to the correct Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
        ConvertTo-DeploymentForestMode -Mode Windows2012Forest | Should -Be ([Microsoft.DirectoryServices.Deployment.Types.ForestMode]::Win2012)
    }

    It 'Converts valid integer to Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
        ConvertTo-DeploymentForestMode -ModeId 5 | Should -BeOfType [Microsoft.DirectoryServices.Deployment.Types.ForestMode]
    }

    It 'Converts a valid integer to the correct Microsoft.DirectoryServices.Deployment.Types.ForestMode' {
        ConvertTo-DeploymentForestMode -ModeId 5 | Should -Be ([Microsoft.DirectoryServices.Deployment.Types.ForestMode]::Win2012)
    }

    It 'Throws an exception when an invalid forest mode is selected' {
        { ConvertTo-DeploymentForestMode -Mode Nonexistant } | Should -Throw
    }

    It 'Throws no exception when a null value is passed' {
        { ConvertTo-DeploymentForestMode -Mode $null } | Should -Not -Throw
    }

    It 'Throws no exception when an invalid mode id is selected' {
        { ConvertTo-DeploymentForestMode -ModeId 666 } | Should -Not -Throw
    }

    It 'Returns $null when a null value is passed' {
        ConvertTo-DeploymentForestMode -Mode $null | Should -Be $null
    }

    It 'Returns $null when an invalid mode id is selected' {
        ConvertTo-DeploymentForestMode -ModeId 666 | Should -Be $null
    }
}

Describe 'ActiveDirectoryDsc.Common\ConvertTo-DeploymentDomainMode' {
    It 'Converts an Microsoft.ActiveDirectory.Management.DomainMode to Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
        ConvertTo-DeploymentDomainMode -Mode Windows2012Domain | Should -BeOfType [Microsoft.DirectoryServices.Deployment.Types.DomainMode]
    }

    It 'Converts an Microsoft.ActiveDirectory.Management.DomainMode to the correct Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
        ConvertTo-DeploymentDomainMode -Mode Windows2012Domain | Should -Be ([Microsoft.DirectoryServices.Deployment.Types.DomainMode]::Win2012)
    }

    It 'Converts valid integer to Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
        ConvertTo-DeploymentDomainMode -ModeId 5 | Should -BeOfType [Microsoft.DirectoryServices.Deployment.Types.DomainMode]
    }

    It 'Converts a valid integer to the correct Microsoft.DirectoryServices.Deployment.Types.DomainMode' {
        ConvertTo-DeploymentDomainMode -ModeId 5 | Should -Be ([Microsoft.DirectoryServices.Deployment.Types.DomainMode]::Win2012)
    }

    It 'Throws an exception when an invalid domain mode is selected' {
        { ConvertTo-DeploymentDomainMode -Mode Nonexistant } | Should -Throw
    }

    It 'Throws no exception when a null value is passed' {
        { ConvertTo-DeploymentDomainMode -Mode $null } | Should -Not -Throw
    }

    It 'Throws no exception when an invalid mode id is selected' {
        { ConvertTo-DeploymentDomainMode -ModeId 666 } | Should -Not -Throw
    }

    It 'Returns $null when a null value is passed' {
        ConvertTo-DeploymentDomainMode -Mode $null | Should -Be $null
    }

    It 'Returns $null when an invalid mode id is selected' {
        ConvertTo-DeploymentDomainMode -ModeId 666 | Should -Be $null
    }
}

Describe 'ActiveDirectoryDsc.Common\Restore-ADCommonObject' {
    BeforeAll {
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

        $restoreAdObjectReturnValue = [PSCustomObject] @{
            DistinguishedName = 'CN=a375347,CN=Accounts,DC=contoso,DC=com'
            Name              = 'a375347'
            ObjectClass       = 'user'
            ObjectGUID        = 'd3c8b8c1-c42b-4533-af7d-3aa73ecd2216'
        }

        $getAdCommonParameterReturnValue = @{Identity = 'something' }
        $restoreIdentity = 'SomeObjectName'
        $restoreObjectClass = 'user'
        $restoreObjectWrongClass = 'wrong'
    }

    Context 'When there are objects in the recycle bin' {
        BeforeAll {
            Mock -CommandName Get-ADObject -MockWith { return $getAdObjectReturnValue } -Verifiable
            Mock -CommandName Get-ADCommonParameters -MockWith { return $getAdCommonParameterReturnValue }
            Mock -CommandName Restore-ADObject -Verifiable
        }

        It 'Should not throw when called with the correct parameters' {
            { Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass } | Should -Not -Throw
        }

        It 'Should return the correct restored object' {
            Mock -CommandName Restore-ADObject -MockWith { return $restoreAdObjectReturnValue }
            $(Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass).ObjectClass | Should -Be 'user'
        }

        It 'Should throw the correct error when invalid parameters are used' {
            { Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectWrongClass } | Should -Throw ('Cannot validate argument on parameter ''ObjectClass''' + '*')
        }

        It 'Should call Get-ADObject as well as Restore-ADObject' {
            Assert-VerifiableMock
        }

        It 'Should throw an InvalidOperationException when object parent does not exist' {
            Mock -CommandName Restore-ADObject -MockWith {
                throw New-Object -TypeName Microsoft.ActiveDirectory.Management.ADException
            }

            {
                Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass
            } | Should -Throw ($script:localizedData.RecycleBinRestoreFailed -f $restoreIdentity, $restoreObjectClass)
        }
    }

    Context 'When there are no objects in the recycle bin' {
        BeforeAll {
            Mock -CommandName Get-ADObject
            Mock -CommandName Get-ADCommonParameters -MockWith { return $getAdCommonParameterReturnValue }
            Mock -CommandName Restore-ADObject
        }

        It 'Should return $null' {
            Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass | Should -Be $null
        }

        It 'Should not call Restore-ADObject' {
            Restore-ADCommonObject -Identity $restoreIdentity -ObjectClass $restoreObjectClass
            Should -Invoke -CommandName Restore-ADObject -Exactly -Times 0 -Scope It
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Get-ADDomainNameFromDistinguishedName' {
    BeforeDiscovery {
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
    }

    Context 'The distinguished name is valid' {
        It 'Should match domain <Domain>' -ForEach $validDistinguishedNames {
            Get-ADDomainNameFromDistinguishedName -DistinguishedName $DN | Should -Be $Domain
        }
    }

    Context 'The distinguished name is invalid' {
        It 'Should return ''$null'' for <_>' -ForEach $invalidDistinguishedNames {
            Get-ADDomainNameFromDistinguishedName -DistinguishedName $_ | Should -BeNullOrEmpty
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Set-ADCommonGroupMember' {
    BeforeAll {
        $mockADGroupMembersAsADObjects = @(
            [PSCustomObject] @{
                DistinguishedName = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                ObjectGUID        = 'a97cc867-0c9e-4928-8387-0dba0c883b8e'
                SamAccountName    = 'USER1'
                ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1106'
                ObjectClass       = 'user'
            }
            [PSCustomObject] @{
                DistinguishedName = 'CN=Group 1,CN=Users,DC=contoso,DC=com'
                ObjectGUID        = 'e2328767-2673-40b2-b3b7-ce9e6511df06'
                SamAccountName    = 'GROUP1'
                ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1206'
                ObjectClass       = 'group'
            }
            [PSCustomObject] @{
                DistinguishedName = 'CN=Computer 1,CN=Users,DC=contoso,DC=com'
                ObjectGUID        = '42f9d607-0934-4afc-bb91-bdf93e07cbfc'
                SamAccountName    = 'COMPUTER1'
                ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-6606'
                ObjectClass       = 'computer'
            }
            # This entry is used to represent a group member from a one-way trusted domain
            [PSCustomObject] @{
                DistinguishedName = 'CN=S-1-5-21-8562719340-2451078396-046517832-2106,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
                ObjectGUID        = '6df78e9e-c795-4e67-a626-e17f1b4a0d8b'
                SamAccountName    = 'ADATUM\USER1'
                ObjectSID         = 'S-1-5-21-8562719340-2451078396-046517832-2106'
                ObjectClass       = 'foreignSecurityPrincipal'
            }
        )

        $setADCommonGroupMemberParms = @{
            Members             = $mockADGroupMembersAsADObjects.DistinguishedName
            MembershipAttribute = 'DistinguishedName'
            Parameters          = @{
                Identity = 'CN=TestGroup,OU=Fake,DC=contoso,DC=com'
            }
        }

        $membershipSID = @{
            member = $mockADGroupMembersAsADObjects.ObjectSID | ForEach-Object -Process { "<SID=$($_)>" }
        }

        Mock -CommandName Assert-Module
        Mock -CommandName Resolve-MembersSecurityIdentifier -MockWith { $membershipSID['member'] }
        Mock -CommandName Set-ADGroup
    }

    Context "When the 'Action' parameter is specified as 'Add'" {
        BeforeAll {
            $setADCommonGroupMemberAddParms = $setADCommonGroupMemberParms.Clone()
            $setADCommonGroupMemberAddParms['Action'] = 'Add'
        }

        It 'Should call the expected mocks' {
            { Set-ADCommonGroupMember @setADCommonGroupMemberAddParms } | Should -Not -Throw

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-MembersSecurityIdentifier -Exactly -Times $setADCommonGroupMemberAddParms.Members.Count
            Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                $Add -ne $null -and
                $Identity -eq $setADCommonGroupMemberAddParms.Parameters.Identity
            } -Exactly -Times 1
        }
    }

    Context "When 'Action' parameter is specified as 'Remove'" {
        BeforeAll {
            $setADCommonGroupMemberRemoveParms = $setADCommonGroupMemberParms.Clone()
            $setADCommonGroupMemberRemoveParms['Action'] = 'Remove'
        }

        It 'Should call the expected mocks' {
            { Set-ADCommonGroupMember @setADCommonGroupMemberRemoveParms } | Should -Not -Throw

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-MembersSecurityIdentifier -Exactly -Times $setADCommonGroupMemberRemoveParms.Members.Count
            Should -Invoke -CommandName Set-ADGroup -ParameterFilter {
                $Remove -ne $null -and
                $Identity -eq $setADCommonGroupMemberRemoveParms.Parameters.Identity
            } -Exactly -Times 1
        }
    }

    Context "When 'Set-ADGroup' throws an exception" {
        BeforeAll {
            Mock -CommandName Set-ADGroup -MockWith { throw 'Error' }

            $errorMessage = $script:localizedData.FailedToSetADGroupMembership -f
            $setADCommonGroupMemberParms.Parameters.Identity
        }

        It 'Should throw the correct exception' {
            { Set-ADCommonGroupMember @setADCommonGroupMemberParms } |
                Should -Throw $errorMessage
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Get-DomainObject' {
    Context 'When Get-ADDomain throws an unexpected error with ErrorOnUnexpectedExceptions' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith { throw 'Unknown Error' }
        }

        It 'Should throw the correct error' {
            { Get-DomainObject -Identity 'contoso.com' -ErrorOnUnexpectedExceptions } |
                Should -Throw ($script:localizedData.GetAdDomainUnexpectedError -f 'contoso.com')

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
        }
    }

    Context 'When Get-ADDomain throws an unexpected error without ErrorOnUnexpectedExceptions' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith { throw 'Unknown Error' }
        }

        It 'Should return $null' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com'
            $getDomainObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
        }
    }

    Context 'When Get-ADDomain throws an ADServerDownException until timeout' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADServerDownException'
            }
            Mock -CommandName Start-Sleep
        }

        It 'Should return $null' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com' -MaximumRetries 3 -RetryIntervalInSeconds 3
            $getDomainObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 3 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 3 -Scope It
        }
    }

    Context 'When Get-ADDomain throws an ADServerDownException until timeout and ErrorOnMaxRetries' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADServerDownException'
            }
            Mock -CommandName Start-Sleep
        }

        It 'Should throw the correct error' {
            { Get-DomainObject -Identity 'contoso.com' -MaximumRetries 3 -RetryIntervalInSeconds 3 -ErrorOnMaxRetries } |
                Should -Throw ($script:localizedData.MaxDomainRetriesReachedError -f 'contoso.com')

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 3 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 3 -Scope It
        }
    }

    Context 'When Get-ADDomain throws an AuthenticationException until timeout' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                throw New-Object -TypeName 'System.Security.Authentication.AuthenticationException'
            }

            Mock -CommandName Start-Sleep
        }

        It 'Should return $null' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com' -MaximumRetries 3 -RetryIntervalInSeconds 3
            $getDomainObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 3 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 3 -Scope It
        }
    }

    Context 'When Get-ADDomain throws an InvalidOperationException until timeout' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                throw New-Object -TypeName 'System.InvalidOperationException'
            }
            Mock -CommandName Start-Sleep
        }

        It 'Should return $null' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com' -MaximumRetries 3 -RetryIntervalInSeconds 3
            $getDomainObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 3 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 3
        }
    }

    Context 'When Get-ADDomain throws an ArgumentException until timeout' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                throw New-Object -TypeName 'System.ArgumentException'
            }

            Mock -CommandName Start-Sleep
        }

        It 'Should return $null' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com' -MaximumRetries 3 -RetryIntervalInSeconds 3
            $getDomainObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 3 -Scope It
            Should -Invoke -CommandName Start-Sleep -Exactly -Times 3
        }
    }

    Context 'When domain cannot be found' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
            }
        }

        It 'Should return $null' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com'
            $getDomainObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
        }
    }

    Context 'When domain can be reached' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                return @{
                    Forest = 'contoso.com'
                }
            }
        }

        It 'Should return the correct values for each property' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com'

            $getDomainObjectResult.Forest | Should -Be 'contoso.com'

            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
        }
    }

    Context 'When domain can be reached, and using specific credential' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                return @{
                    Forest = 'contoso.com'
                }
            }

            $mockAdministratorUser = 'admin@contoso.com'
            $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force
            $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @($mockAdministratorUser, $mockAdministratorPassword)
        }

        It 'Should return the correct values for each property' {
            $getDomainObjectResult = Get-DomainObject -Identity 'contoso.com' -Credential $mockAdministratorCredential

            $getDomainObjectResult.Forest | Should -Be 'contoso.com'

            Should -Invoke -CommandName Get-ADDomain -ParameterFilter {
                $PesterBoundParameters.ContainsKey('Credential') -eq $true
            } -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Get-DomainControllerObject' {
    Context 'When domain name cannot be reached' {
        BeforeAll {
            Mock -CommandName Get-ADDomainController -MockWith {
                throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADServerDownException'
            }
        }

        It 'Should throw the correct error' {
            { Get-DomainControllerObject -DomainName 'contoso.com' } |
                Should -Throw $script:localizedData.FailedEvaluatingDomainController

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
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
            $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com'
            $getDomainControllerObjectResult | Should -BeNullOrEmpty

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
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
            { Get-DomainControllerObject -DomainName 'contoso.com' } | Should -Throw $script:localizedData.WasExpectingDomainController

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the domain controller object is a remote computer and local computer is a domain controller' {
        BeforeAll {
            Mock -CommandName Get-ADDomainController -MockWith {
                return @{
                    Site            = 'MySite'
                    Domain          = 'contoso.com'
                    IsGlobalCatalog = $true
                }
            }
            Mock -CommandName Test-IsDomainController -MockWith {
                return $true
            }

            $mockComputerName = "Mock-$($env:COMPUTERNAME)"
        }

        It 'Should not throw and call the correct mocks' {
            { Get-DomainControllerObject -DomainName 'contoso.com' -ComputerName $mockComputerName } | Should -Not -Throw

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Test-IsDomainController -Exactly -Times 0
        }

        It 'Should return the correct values for each property' {
            $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com' -ComputerName $mockComputerName

            $getDomainControllerObjectResult.Site | Should -Be 'MySite'
            $getDomainControllerObjectResult.Domain | Should -Be 'contoso.com'
            $getDomainControllerObjectResult.IsGlobalCatalog | Should -BeTrue
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
            $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com'

            $getDomainControllerObjectResult.Site | Should -Be 'MySite'
            $getDomainControllerObjectResult.Domain | Should -Be 'contoso.com'
            $getDomainControllerObjectResult.IsGlobalCatalog | Should -BeTrue

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
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
            $getDomainControllerObjectResult = Get-DomainControllerObject -DomainName 'contoso.com' -Credential $mockAdministratorCredential

            $getDomainControllerObjectResult.Site | Should -Be 'MySite'
            $getDomainControllerObjectResult.Domain | Should -Be 'contoso.com'
            $getDomainControllerObjectResult.IsGlobalCatalog | Should -BeTrue

            Should -Invoke -CommandName Get-ADDomainController -ParameterFilter {
                $PesterBoundParameters.ContainsKey('Credential') -eq $true
            } -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Test-IsDomainController' {
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

            Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
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

            Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Convert-PropertyMapToObjectProperties' {
    Context 'When a property map should be converted to object properties' {
        BeforeAll {
            $propertyMapValue = @(
                @{
                    ParameterName = 'ComputerName'
                    PropertyName  = 'cn'
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
                    PropertyName  = 'cn'
                },
                'Location'
            )
        }

        It 'Should throw the correct error' {
            {
                Convert-PropertyMapToObjectProperties $propertyMapValue
            } | Should -Throw $script:localizedData.PropertyMapArrayIsWrongType
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Assert-ADPSProvider' -Tag 'Private' {
    Context 'When the AD PS Provider is installed' {
        BeforeAll {
            $mockPSProviderResult = @{
                Name = 'ActiveDirectory'
            }

            Mock -CommandName Get-PSProvider -ParameterFilter {
                $PSProvider -eq 'ActiveDirectory'
            } -MockWith { $mockPSProviderResult }

            Mock -CommandName Import-Module
        }

        It 'Should call the expected mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                { Assert-ADPSProvider } | Should -Not -Throw
            }

            Should -Invoke -CommandName Get-PSProvider -ParameterFilter {
                $PSProvider -eq 'ActiveDirectory'
            } -Exactly -Times 1

            Should -Invoke -CommandName Import-Module -Exactly -Times 0
        }
    }

    Context 'When the AD PS Provider is not installed' {
        Context 'When the AD PS Provider is successfully installed by Import-Module' {
            BeforeAll {
                $mockPSProviderResult = @{
                    Name = 'ActiveDirectory'
                }

                Mock -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -eq 'SilentlyContinue' }
                Mock -CommandName Import-Module
                Mock -CommandName Get-PSProvider -ParameterFilter {
                    $ErrorAction -ne 'SilentlyContinue'
                } -MockWith { $mockPSProviderResult }
            }


            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    { Assert-ADPSProvider } | Should -Not -Throw
                }

                Should -Invoke -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -eq 'SilentlyContinue' } -Exactly -Times 1
                Should -Invoke -CommandName Import-Module -Exactly -Times 1
                Should -Invoke -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -ne 'SilentlyContinue' } -Exactly -Times 1
            }
        }

        Context 'When the AD PS Provider is not successfully installed by Import-Module' {
            BeforeAll {
                Mock -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -eq 'SilentlyContinue' }
                Mock -CommandName Import-Module
                Mock -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -ne 'SilentlyContinue' } -MockWith { Throw 'Error' }
            }

            It 'Should call the expected mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $errorRecord = Get-InvalidOperationRecord -Message $script:localizedData.AdPsProviderInstallFailureError

                    { Assert-ADPSProvider } | Should -Throw -ExpectedMessage $errorRecord.Message
                }

                Should -Invoke -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -eq 'SilentlyContinue' } -Exactly -Times 1
                Should -Invoke -CommandName Import-Module -Exactly -Times 1
                Should -Invoke -CommandName Get-PSProvider -ParameterFilter { $ErrorAction -ne 'SilentlyContinue' } -Exactly -Times 1
            }
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Assert-ADPSDrive' {
    BeforeAll {
        $defaultPSDriveRoot = '//RootDSE/'

        Mock -CommandName Assert-Module
        Mock -CommandName Assert-ADPSProvider
    }

    Context 'When the AD PS Drive does not exist' {
        BeforeAll {
            Mock -CommandName Get-PSDrive
        }

        Context 'When the New-PSDrive function is successful' {
            BeforeAll {
                Mock -CommandName New-PSDrive
            }

            It 'Should call the expected mocks' {
                { Assert-ADPSDrive } | Should -Not -Throw

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1
                Should -Invoke -CommandName Get-PSDrive -Exactly -Times 1
                Should -Invoke -CommandName New-PSDrive -ParameterFilter { $Root -eq $defaultPSDriveRoot } -Exactly -Times 1
            }
        }

        Context 'When the New-PSDrive function is not successful' {
            BeforeAll {
                Mock -CommandName New-PSDrive -MockWith { throw }
            }

            It 'Should call the expected mocks' {
                { Assert-ADPSDrive } | Should -Throw $script:localizedData.CreatingNewADPSDriveError

                Should -Invoke -CommandName Assert-Module -Exactly -Times 1
                Should -Invoke -CommandName Get-PSDrive -Exactly -Times 1
                Should -Invoke -CommandName New-PSDrive -ParameterFilter { $Root -eq $defaultPSDriveRoot } -Exactly -Times 1
            }
        }
    }

    Context 'When the AD PS Drive already exists' {
        BeforeAll {
            Mock -CommandName Get-PSDrive -MockWith { New-MockObject -Type System.Management.Automation.PSDriveInfo }
            Mock -CommandName New-PSDrive
        }

        It 'Should call the expected mocks' {
            { Assert-ADPSDrive } | Should -Not -Throw

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1
            Should -Invoke -CommandName Get-PSDrive -ParameterFilter { $Name -eq 'AD' } -Exactly -Times 1
            Should -Invoke -CommandName New-PSDrive -Exactly -Times 0
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Test-ADReplicationSite' {
    BeforeAll {
        $mockAdministratorUser = 'admin@contoso.com'
        $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12'
        $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockAdministratorUser,
                ($mockAdministratorPassword | ConvertTo-SecureString -AsPlainText -Force)
        )

        Mock -CommandName Get-ADDomainController -MockWith {
            return @{
                HostName = $env:COMPUTERNAME
            }
        }
    }

    Context 'When a replication site does not exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite -MockWith {
                throw New-Object -TypeName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
            }
        }

        It 'Should return $false' {
            $testADReplicationSiteResult = Test-ADReplicationSite -SiteName 'TestSite' -DomainName 'contoso.com' -Credential $mockAdministratorCredential
            $testADReplicationSiteResult | Should -BeFalse

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADReplicationSite -Exactly -Times 1 -Scope It
        }
    }

    Context 'When a replication site exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSite -MockWith {
                return 'site object'
            }
        }

        It 'Should return $true' {
            $testADReplicationSiteResult = Test-ADReplicationSite -SiteName 'TestSite' -DomainName 'contoso.com' -Credential $mockAdministratorCredential
            $testADReplicationSiteResult | Should -BeTrue

            Should -Invoke -CommandName Get-ADDomainController -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADReplicationSite -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\New-CimCredentialInstance' {
    Context 'When creating a new MSFT_Credential CIM instance credential object' {
        BeforeAll {
            $mockAdministratorUser = 'admin@contoso.com'
            $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12'
            $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                $mockAdministratorUser,
                    ($mockAdministratorPassword | ConvertTo-SecureString -AsPlainText -Force)
            )
        }

        It 'Should return the correct values' {
            $newCimCredentialInstanceResult = New-CimCredentialInstance -Credential $mockAdministratorCredential
            $newCimCredentialInstanceResult | Should -BeOfType 'Microsoft.Management.Infrastructure.CimInstance'
            $newCimCredentialInstanceResult.CimClass.CimClassName | Should -Be 'MSFT_Credential'
            $newCimCredentialInstanceResult.UserName | Should -Be $mockAdministratorUser
            $newCimCredentialInstanceResult.Password | Should -BeNullOrEmpty
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Add-TypeAssembly' {
    Context 'When assembly fails to load' {
        BeforeAll {
            Mock -CommandName Add-Type -MockWith {
                throw
            }

            $mockAssembly = 'MyAssembly'
        }

        It 'Should throw the correct error' {
            { Add-TypeAssembly -AssemblyName $mockAssembly } | Should -Throw ($script:localizedData.CouldNotLoadAssembly -f $mockAssembly)
        }
    }

    Context 'When loading an assembly into the session' {
        BeforeAll {
            Mock -CommandName Add-Type

            $mockAssembly = 'MyAssembly'
        }

        It 'Should not throw and call the correct mocks' {
            { Add-TypeAssembly -AssemblyName $mockAssembly } | Should -Not -Throw

            Should -Invoke -CommandName Add-Type -ParameterFilter {
                $AssemblyName -eq $mockAssembly
            } -Exactly -Times 1 -Scope It
        }

        Context 'When the type is already loaded into the session' {
            It 'Should not throw and not call any mocks' {
                { Add-TypeAssembly -AssemblyName $mockAssembly -TypeName 'System.String' } | Should -Not -Throw

                Should -Invoke -CommandName Add-Type -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the type is missing from the session' {
            It 'Should not throw and call the correct mocks' {
                { Add-TypeAssembly -AssemblyName $mockAssembly -TypeName 'My.Type' } | Should -Not -Throw

                Should -Invoke -CommandName Add-Type -ParameterFilter {
                    $AssemblyName -eq $mockAssembly
                } -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\New-ADDirectoryContext' {
    Context 'When creating a new Active Directory context' {
        BeforeAll {
            # This credential object must be created before we mock New-Object.
            $mockAdministratorUser = 'admin@contoso.com'
            $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12'
            $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                $mockAdministratorUser,
                    ($mockAdministratorPassword | ConvertTo-SecureString -AsPlainText -Force)
            )

            Mock -CommandName Add-TypeAssembly -Verifiable
            Mock -CommandName New-Object
        }

        Context 'When the calling with only parameter DirectoryContextType' {
            It 'Should not throw and call the correct mocks' {
                { Get-ADDirectoryContext -DirectoryContextType 'Domain' } | Should -Not -Throw

                Should -Invoke -CommandName New-Object -ParameterFilter {
                    $ArgumentList.Count -eq 1 `
                        -and $ArgumentList[0] -eq 'Domain'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the calling with parameters DirectoryContextType and Name' {
            It 'Should not throw and call the correct mocks' {
                {
                    Get-ADDirectoryContext -DirectoryContextType 'Domain' -Name 'my.domain'
                } | Should -Not -Throw

                Should -Invoke -CommandName New-Object -ParameterFilter {
                    $ArgumentList.Count -eq 2 `
                        -and $ArgumentList[0] -eq 'Domain' `
                        -and $ArgumentList[1] -eq 'my.domain'
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the calling with parameters DirectoryContextType, Name and Credential' {
            It 'Should not throw and call the correct mocks' {
                {
                    Get-ADDirectoryContext -DirectoryContextType 'Domain' -Name 'my.domain' -Credential $mockAdministratorCredential
                } | Should -Not -Throw

                Should -Invoke -CommandName New-Object -ParameterFilter {
                    $ArgumentList.Count -eq 4 `
                        -and $ArgumentList[0] -eq 'Domain' `
                        -and $ArgumentList[1] -eq 'my.domain' `
                        -and $ArgumentList[2] -eq $mockAdministratorUser `
                        -and $ArgumentList[3] -eq $mockAdministratorPassword
                } -Exactly -Times 1 -Scope It
            }
        }

        Assert-VerifiableMock
    }
}

Describe 'ActiveDirectoryDsc.Common\Find-DomainController' -Tag 'FindDomainController' {
    Context 'When a domain controller is found in a domain' {
        BeforeAll {
            $mockAdministratorUser = 'admin@contoso.com'
            $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12'
            $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                $mockAdministratorUser,
                    ($mockAdministratorPassword | ConvertTo-SecureString -AsPlainText -Force)
            )

            $mockDomainName = 'contoso.com'

            Mock -CommandName Find-DomainControllerFindOneInSiteWrapper
            Mock -CommandName Find-DomainControllerFindOneWrapper
            Mock -CommandName Get-ADDirectoryContext -MockWith {
                return New-Object `
                    -TypeName 'System.DirectoryServices.ActiveDirectory.DirectoryContext' `
                    -ArgumentList @('Domain', $mockDomainName)
            }
        }

        Context 'When the calling with only the parameter DomainName' {
            It 'Should not throw and call the correct mocks' {
                { Find-DomainController -DomainName $mockDomainName } | Should -Not -Throw

                Should -Invoke -CommandName Get-ADDirectoryContext -ParameterFilter {
                    $Name -eq $mockDomainName -and
                    -not $PesterBoundParameters.ContainsKey('Credential')
                } -Exactly -Times 1 -Scope It

                Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
                Should -Invoke -Command Find-DomainControllerFindOneInSiteWrapper -Exactly -Times 0 -Scope It
            }
        }

        Context 'When the calling with the parameter SiteName' {
            It 'Should not throw and call the correct mocks' {
                { Find-DomainController -DomainName $mockDomainName -SiteName 'Europe' } | Should -Not -Throw

                Should -Invoke -CommandName Get-ADDirectoryContext -ParameterFilter {
                    $Name -eq $mockDomainName -and
                    -not $PesterBoundParameters.ContainsKey('Credential')
                } -Exactly -Times 1 -Scope It

                Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 0 -Scope It
                Should -Invoke -Command Find-DomainControllerFindOneInSiteWrapper -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the calling with the parameter Credential' {
            It 'Should not throw and call the correct mocks' {
                { Find-DomainController -DomainName $mockDomainName -Credential $mockAdministratorCredential } | Should -Not -Throw

                Should -Invoke -CommandName Get-ADDirectoryContext -ParameterFilter {
                    $Name -eq $mockDomainName -and
                    $PesterBoundParameters.ContainsKey('Credential')
                } -Exactly -Times 1 -Scope It

                Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
                Should -Invoke -Command Find-DomainControllerFindOneInSiteWrapper -Exactly -Times 0 -Scope It
            }
        }

        Assert-VerifiableMock
    }

    Context 'When no domain controller is found' {
        BeforeAll {
            Mock -CommandName Get-ADDirectoryContext -MockWith {
                return New-Object `
                    -TypeName 'System.DirectoryServices.ActiveDirectory.DirectoryContext' `
                    -ArgumentList @('Domain', $mockDomainName)
            }

            $mockErrorMessage = 'Mocked error'
            $mockDomainName = 'contoso.com'

            Mock -CommandName Find-DomainControllerFindOneWrapper -MockWith {
                throw New-Object -TypeName 'System.Management.Automation.MethodInvocationException' `
                    -ArgumentList @(
                    $mockErrorMessage,
                        (New-Object -TypeName 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException')
                )
            }

            Mock -CommandName Write-Verbose -ParameterFilter {
                $Message -like 'Searching for a domain controller*'
            } -MockWith {
                Write-Verbose -Message ('VERBOSE OUTPUT FROM MOCK: {0}' -f $Message)
            }
        }

        It 'Should not throw and call the correct mocks' {
            { Find-DomainController -DomainName $mockDomainName } | Should -Not -Throw

            Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
            Should -Invoke -Command Write-Verbose -Exactly -Times 1 -Scope It
        }

        Assert-VerifiableMock
    }

    Context 'When the lookup for a domain controller fails' {
        BeforeAll {
            Mock -CommandName Get-ADDirectoryContext -MockWith {
                return New-Object `
                    -TypeName 'System.DirectoryServices.ActiveDirectory.DirectoryContext' `
                    -ArgumentList @('Domain', $mockDomainName)
            }

            $mockErrorMessage = 'Mocked error'
            $mockDomainName = 'contoso.com'

            Mock -CommandName Find-DomainControllerFindOneWrapper -MockWith {
                throw $mockErrorMessage
            }
        }

        It 'Should throw the correct error' {
            { Find-DomainController -DomainName $mockDomainName } | Should -Throw $mockErrorMessage

            Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
        }

        Assert-VerifiableMock
    }

    Context 'When the Find-DomainController throws an authentication exception' {
        BeforeAll {
            $mockErrorMessage = 'The user name or password is incorrect.'
            $mockDomainName = 'contoso.com'

            Mock -CommandName Find-DomainControllerFindOneWrapper -MockWith {
                $exceptionWithInnerException = New-Object -TypeName 'System.Management.Automation.MethodInvocationException' `
                    -ArgumentList @(
                    $mockErrorMessage,
                        (New-Object -TypeName 'System.Security.Authentication.AuthenticationException')
                )

                $newObjectParameters = @{
                    TypeName     = 'System.Management.Automation.ErrorRecord'
                    ArgumentList = @(
                        $exceptionWithInnerException,
                        'AuthenticationException',
                        'InvalidOperation',
                        $null
                    )
                }

                throw New-Object @newObjectParameters
            }
        }

        Context 'When the parameter WaitForValidCredentials is not specified' {
            It 'Should throw the correct error' {
                { Find-DomainController -DomainName $mockDomainName } | Should -Throw $mockErrorMessage

                Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the parameter WaitForValidCredentials is set to $false' {
            It 'Should throw the correct error' {
                { Find-DomainController -DomainName $mockDomainName -WaitForValidCredentials:$false } | Should -Throw $mockErrorMessage

                Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the parameter WaitForValidCredentials is set to $true' {
            BeforeAll {
                Mock -CommandName Write-Warning
            }

            It 'Should not throw an exception' {
                { Find-DomainController -DomainName $mockDomainName -WaitForValidCredentials } | Should -Not -Throw

                Should -Invoke -Command Find-DomainControllerFindOneWrapper -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Write-Warning -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Test-Password' {
    BeforeAll {
        $mockDomainName = 'contoso.com'
        $mockFQDN = 'DC=' + $mockDomainName.replace('.', ',DC=')
        $mockUserName = 'JohnDoe'
        $mockPassword = 'mockpassword'
        $mockPasswordCredential = [System.Management.Automation.PSCredential]::new(
            $mockUserName,
                (ConvertTo-SecureString -String $mockPassword -AsPlainText -Force)
        )
        $mockCredential = [System.Management.Automation.PSCredential]::new(
            $mockUserName,
                (ConvertTo-SecureString -String $mockPassword -AsPlainText -Force)
        )
        $principalContextTypeName = 'System.DirectoryServices.AccountManagement.PrincipalContext'

        Add-TypeAssembly -AssemblyName 'System.DirectoryServices.AccountManagement' `
            -TypeName $principalContextTypeName

        $mockPrincipalContext = New-MockObject -Type $principalContextTypeName

        $testPasswordParms = @{
            DomainName             = $mockDomainName
            UserName               = $mockUserName
            Password               = $mockPasswordCredential
            PasswordAuthentication = 'Default'
        }

        Mock -CommandName New-Object -MockWith { $mockPrincipalContext }
        Mock -CommandName Test-PrincipalContextCredentials
    }

    Context 'When the "DomainName" parameter is an FQDN' {
        BeforeAll {
            $testPasswordFQDNParms = $testPasswordParms.Clone()
            $testPasswordFQDNParms['DomainName'] = $mockFQDN
        }

        It 'Should call the expected mocks' {
            { Test-Password @testPasswordFQDNParms } | Should -Not -Throw

            Should -Invoke -CommandName New-Object -ParameterFilter {
                $TypeName -eq $principalContextTypeName -and
                $ArgumentList -contains $mockDomainName
            } -Exactly -Times 1

            Should -Invoke -CommandName Test-PrincipalContextCredentials -ParameterFilter {
                $UserName -eq $testPasswordFQDNParms.UserName
            } -Exactly -Times 1
        }
    }

    Context 'When the "Credential" parameter is not specified' {
        It 'Should call the expected mocks' {
            { Test-Password @testPasswordParms } | Should -Not -Throw

            Should -Invoke -CommandName New-Object -ParameterFilter {
                $TypeName -eq $principalContextTypeName -and
                $ArgumentList -contains $null
            } -Exactly -Times 1

            Should -Invoke -CommandName Test-PrincipalContextCredentials -ParameterFilter {
                $UserName -eq $testPasswordParms.UserName
            } -Exactly -Times 1
        }
    }

    Context 'When the "Credential" parameter is specified' {
        BeforeAll {
            $testPasswordCredentialParms = $testPasswordParms.Clone()
            $testPasswordCredentialParms['Credential'] = $mockCredential
        }

        It 'Should call the expected mocks' {
            { Test-Password @testPasswordCredentialParms } | Should -Not -Throw

            Should -Invoke -CommandName New-Object -ParameterFilter {
                $TypeName -eq $principalContextTypeName -and
                $ArgumentList -contains $testPasswordCredentialParms.Credential.UserName
            } -Exactly -Times 1

            Should -Invoke -CommandName Test-PrincipalContextCredentials -ParameterFilter {
                $UserName -eq $testPasswordCredentialParms.UserName
            } -Exactly -Times 1
        }
    }
}

Describe 'ActiveDirectoryDsc.Common\Resolve-MembersSecurityIdentifier' {
    BeforeAll {
        $mockADGroupMembersAsADObjects = @(
            [PSCustomObject] @{
                DistinguishedName = 'CN=User 1,CN=Users,DC=contoso,DC=com'
                ObjectGUID        = 'a97cc867-0c9e-4928-8387-0dba0c883b8e'
                SamAccountName    = 'USER1'
                ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1106'
                ObjectClass       = 'user'
            }
            [PSCustomObject] @{
                DistinguishedName = 'CN=Group 1,CN=Users,DC=contoso,DC=com'
                ObjectGUID        = 'e2328767-2673-40b2-b3b7-ce9e6511df06'
                SamAccountName    = 'GROUP1'
                ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-1206'
                ObjectClass       = 'group'
            }
            [PSCustomObject] @{
                DistinguishedName = 'CN=Computer 1,CN=Users,DC=contoso,DC=com'
                ObjectGUID        = '42f9d607-0934-4afc-bb91-bdf93e07cbfc'
                SamAccountName    = 'COMPUTER1'
                ObjectSID         = 'S-1-5-21-1131554080-2861379300-292325817-6606'
                ObjectClass       = 'computer'
            }
            # This entry is used to represent a group member from a one-way trusted domain
            [PSCustomObject] @{
                DistinguishedName = 'CN=S-1-5-21-8562719340-2451078396-046517832-2106,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'
                ObjectGUID        = '6df78e9e-c795-4e67-a626-e17f1b4a0d8b'
                SamAccountName    = 'ADATUM\USER1'
                ObjectSID         = 'S-1-5-21-8562719340-2451078396-046517832-2106'
                ObjectClass       = 'foreignSecurityPrincipal'
            }
        )

        $script:memberIndex = 0

        Mock -CommandName Assert-Module

        Mock -CommandName Resolve-SecurityIdentifier -MockWith {
            $memberADObjectSID = $mockADGroupMembersAsADObjects[($script:memberIndex)].ObjectSID
            $script:memberIndex++
            return $memberADObjectSID
        }

        Mock -CommandName Get-ADObject -MockWith {
            $memberADObject = $mockADGroupMembersAsADObjects[$script:memberIndex]
            $script:memberIndex++
            return $memberADObject
        }
    }

    Context "When 'Server' is passed as part of the 'Parameters' parameter" {
        BeforeAll {
            $testServer = 'TESTDC'
            $membershipAttribute = 'ObjectGUID'

            $script:memberIndex = 0

            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects.$membershipAttribute
                MembershipAttribute = $membershipAttribute
                Parameters          = @{
                    Server = $testServer
                }
            }
        }

        It 'Should call the expected mocks' {
            { Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms } | Should -Not -Throw

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-SecurityIdentifier -Exactly -Times 0
            Should -Invoke -CommandName Get-ADObject -ParameterFilter { $Server -eq $testServer } -Exactly -Times $mockADGroupMembersAsADObjects.Count
        }
    }

    Context "When 'Credential' is passed as part of the 'Parameters' parameter" {
        BeforeAll {
            $testCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                'DummyUser',
                    (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
            )
            $membershipAttribute = 'ObjectGUID'

            $script:memberIndex = 0

            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects.$membershipAttribute
                MembershipAttribute = $membershipAttribute
                Parameters          = @{
                    Credential = $testCredentials
                }
            }
        }

        It 'Should call the expected mocks' {
            { Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms } | Should -Not -Throw

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-SecurityIdentifier -Exactly -Times 0
            Should -Invoke -CommandName Get-ADObject -ParameterFilter {
                $Credential -eq $testCredentials
            } -Exactly -Times $mockADGroupMembersAsADObjects.Count
        }
    }

    Context "When 'Get-ADObject' returns no value" {
        BeforeAll {
            $membershipAttribute = 'ObjectGUID'

            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects[0].$membershipAttribute
                MembershipAttribute = $membershipAttribute
            }

            $errorMessage = ($script:localizedData.UnableToResolveMembershipAttribute -f
                'ObjectSID', $membershipAttribute, $mockADGroupMembersAsADObjects[0].$membershipAttribute)

            Mock -CommandName Resolve-SecurityIdentifier
            Mock -CommandName Get-ADObject
        }

        It 'Should throw the correct exception' {
            { Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms } |
                Should -Throw $errorMessage
        }
    }

    Context "When MembershipAttribute 'SamAccountName' is specified" {
        BeforeAll {
            $membershipAttribute = 'SamAccountName'

            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects.$membershipAttribute
                MembershipAttribute = $membershipAttribute
            }

            $resolveSecurityIdentifierCount = @($mockADGroupMembersAsADObjects |
                    Where-Object -Property $membershipAttribute -Match '\\').Count

            $getADObjectCount = @($mockADGroupMembersAsADObjects |
                    Where-Object -Property $membershipAttribute -NotMatch '\\').Count

            $script:memberIndex = 0
        }

        It 'Should return the correct result' {
            $result = Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms

            for ($i = 0; $i -lt $result.Count; $i++)
            {
                $result[$i] | Should -Be $mockADGroupMembersAsADObjects[$i].ObjectSID
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-SecurityIdentifier -Exactly -Times $resolveSecurityIdentifierCount
            Should -Invoke -CommandName Get-ADObject -Exactly -Times $getADObjectCount
        }
    }

    Context "When MembershipAttribute 'DistinguishedName' is specified" {
        BeforeAll {
            $membershipAttribute = 'DistinguishedName'

            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects.$membershipAttribute
                MembershipAttribute = $membershipAttribute
            }

            $getADObjectCount = @($mockADGroupMembersAsADObjects |
                    Where-Object -Property $membershipAttribute -NotMatch 'CN=ForeignSecurityPrincipals').Count

            $script:memberIndex = 0
        }

        It 'Should return the correct result' {
            $result = Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms

            for ($i = 0; $i -lt $result.Count; $i++)
            {
                $result[$i] | Should -Be $mockADGroupMembersAsADObjects[$i].ObjectSID
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-SecurityIdentifier -Exactly -Times 0
            Should -Invoke -CommandName Get-ADObject -Exactly -Times $getADObjectCount
        }
    }

    Context "When MembershipAttribute 'ObjectGUID' is specified" {
        BeforeAll {
            $membershipAttribute = 'ObjectGUID'

            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects.$membershipAttribute
                MembershipAttribute = $membershipAttribute
            }

            $script:memberIndex = 0
        }

        It 'Should Return the correct result' {
            $result = Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms

            for ($i = 0; $i -lt $result.Count; $i++)
            {
                $result[$i] | Should -Be $mockADGroupMembersAsADObjects[$i].ObjectSID
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-SecurityIdentifier -Exactly -Times 0
            Should -Invoke -CommandName Get-ADObject -Exactly -Times $mockADGroupMembersAsADObjects.Count
        }
    }

    Context "When MembershipAttribute 'SID' is specified" {
        BeforeAll {
            $resolveMembersSecurityIdentifierParms = @{
                Members             = $mockADGroupMembersAsADObjects.ObjectSID
                MembershipAttribute = 'SID'
            }

            $script:memberIndex = 0
        }

        It 'Should return the correct result' {
            $result = Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms

            for ($i = 0; $i -lt $result.Count; $i++)
            {
                $result[$i] | Should -Be $mockADGroupMembersAsADObjects[$i].ObjectSID
            }

            Should -Invoke -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Exactly -Times 1
            Should -Invoke -CommandName Resolve-SecurityIdentifier -Exactly -Times 0
            Should -Invoke -CommandName Get-ADObject -Exactly -Times 0
        }
    }

    Context "When 'PrepareForMembership' is specified" {
        Context "When the MembershipAttribute specified is not 'SID'" {
            BeforeAll {
                $membershipAttribute = 'ObjectGUID'

                $resolveMembersSecurityIdentifierParms = @{
                    Members              = $mockADGroupMembersAsADObjects.$membershipAttribute
                    MembershipAttribute  = $membershipAttribute
                    PrepareForMembership = $true
                }
            }

            It 'Should return the correct result' {
                $result = Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms

                for ($i = 0; $i -lt $result.Count; $i++)
                {
                    $result[$i] | Should -Be "<SID=$($mockADGroupMembersAsADObjects[$i].ObjectSID)>"
                }
            }
        }

        Context "When MembershipAttribute specified is 'SID'" {
            BeforeAll {
                $resolveMembersSecurityIdentifierParms = @{
                    Members              = $mockADGroupMembersAsADObjects.ObjectSID
                    MembershipAttribute  = 'SID'
                    PrepareForMembership = $true
                }
            }

            It 'Should return the correct result' {
                $result = Resolve-MembersSecurityIdentifier @resolveMembersSecurityIdentifierParms

                for ($i = 0; $i -lt $result.Count; $i++)
                {
                    $result[$i] | Should -Be "<SID=$($mockADGroupMembersAsADObjects[$i].ObjectSID)>"
                }
            }
        }
    }
}
