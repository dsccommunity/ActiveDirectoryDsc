# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies have been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies have not been resolved, this will throw an error.
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
    $script:dscResourceName = 'MSFT_ADReplicationSiteLink'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    # Load stub cmdlets and classes.
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1')

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscResourceName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscResourceName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    Restore-TestEnvironment -TestEnvironment $script:testEnvironment

    # Unload stub module
    Remove-Module -Name ActiveDirectory_2019 -Force

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_ADReplicationSiteLink\Get-TargetResource' -Tag 'Get' {
    Context 'When sites are included' {
        BeforeAll {
            $mockGetADReplicationSiteLinkReturn = @{
                Name                          = 'HQSiteLink'
                Cost                          = 100
                Description                   = 'HQ Site'
                ReplicationFrequencyInMinutes = 180
                SitesIncluded                 = @(
                    'CN=site1,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com',
                    'CN=site2,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com'
                )
            }

            Mock -CommandName Get-ADReplicationSiteLink -MockWith { $mockGetADReplicationSiteLinkReturn }
            Mock -CommandName Resolve-SiteLinkName -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[0] } -MockWith { 'site1' }
            Mock -CommandName Resolve-SiteLinkName -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[1] } -MockWith { 'site2' }
        }

        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'HQSiteLink'
                }

                $result = Get-TargetResource @mockParameters

                $result.Name | Should -Be $mockParameters.Name
                $result.Cost | Should -Be 100
                $result.Description | Should -Be 'HQ Site'
                $result.ReplicationFrequencyInMinutes | Should -Be 180
                $result.SitesIncluded | Should -Be 'site1', 'site2'
                $result.SitesExcluded | Should -BeNullOrEmpty
                $result.Ensure | Should -Be 'Present'
                $result.OptionChangeNotification | Should -BeFalse
                $result.OptionTwoWaySync | Should -BeFalse
                $result.OptionDisableCompression | Should -BeFalse
            }

            Should -Invoke -CommandName Get-ADReplicationSiteLink -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Resolve-SiteLinkName -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[0] } -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Resolve-SiteLinkName -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[1] } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When site link options are enabled' {
        BeforeAll {
            $mockGetADReplicationSiteLinkOptionsReturn = @{
                Name                          = 'HQSiteLink'
                Cost                          = 100
                Description                   = 'HQ Site'
                ReplicationFrequencyInMinutes = 180
                SitesIncluded                 = @(
                    'CN=site1,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com',
                    'CN=site2,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com'
                )
                Options                       = 7
            }

            Mock -CommandName Get-ADReplicationSiteLink -MockWith { $mockGetADReplicationSiteLinkOptionsReturn }
            Mock -CommandName Resolve-SiteLinkName -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkOptionsReturn.SitesIncluded[0] } -MockWith { 'site1' }
            Mock -CommandName Resolve-SiteLinkName -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkOptionsReturn.SitesIncluded[1] } -MockWith { 'site2' }
        }

        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'HQSiteLink'
                }

                $result = Get-TargetResource @mockParameters

                $result.Name | Should -Be $mockParameters.Name
                $result.Cost | Should -Be 100
                $result.Description | Should -Be 'HQ Site'
                $result.ReplicationFrequencyInMinutes | Should -Be 180
                $result.SitesIncluded | Should -Be 'site1', 'site2'
                $result.SitesExcluded | Should -BeNullOrEmpty
                $result.Ensure | Should -Be 'Present'
                $result.OptionChangeNotification | Should -BeTrue
                $result.OptionTwoWaySync | Should -BeTrue
                $result.OptionDisableCompression | Should -BeTrue
            }
        }
    }

    Context 'When AD Replication Sites do not exist' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new() }
        }

        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'HQSiteLink'
                }

                $result = Get-TargetResource @mockParameters

                $result.Name | Should -Be $mockParameters.Name
                $result.Cost | Should -BeNullOrEmpty
                $result.Description | Should -BeNullOrEmpty
                $result.ReplicationFrequencyInMinutes | Should -BeNullOrEmpty
                $result.SitesIncluded | Should -BeNullOrEmpty
                $result.SitesExcluded | Should -BeNullOrEmpty
                $result.Ensure | Should -Be 'Absent'
                $result.OptionChangeNotification | Should -BeFalse
                $result.OptionTwoWaySync | Should -BeFalse
                $result.OptionDisableCompression | Should -BeFalse
            }
        }
    }

    Context 'When Get-ADReplicationSiteLink throws an unexpected error' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { throw }
        }

        It 'Should throw the correct exception' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name = 'HQSiteLink'
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.GetSiteLinkUnexpectedError -f $mockParameters.Name)

                { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }
        }
    }

    Context 'When Sites are excluded' {
        BeforeAll {
            Mock -CommandName Get-ADReplicationSiteLink -MockWith {
                @{
                    Name                          = 'HQSiteLink'
                    Cost                          = 100
                    Description                   = 'HQ Site'
                    ReplicationFrequencyInMinutes = 180
                    SitesIncluded                 = $null
                }
            }
        }

        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    Name          = 'HQSiteLink'
                    SitesExcluded = 'site3', 'site4'
                }

                $result = Get-TargetResource @mockParameters

                $result.Name | Should -Be $mockParameters.Name
                $result.Cost | Should -Be 100
                $result.Description | Should -Be 'HQ Site'
                $result.ReplicationFrequencyInMinutes | Should -Be 180
                $result.SitesIncluded | Should -BeNullOrEmpty
                $result.SitesExcluded | Should -Be $mockParameters.SitesExcluded
                $result.Ensure | Should -Be 'Present'
                $result.OptionChangeNotification | Should -BeFalse
                $result.OptionTwoWaySync | Should -BeFalse
                $result.OptionDisableCompression | Should -BeFalse
            }
        }
    }
}

Describe 'MSFT_ADReplicationSiteLink\Test-TargetResource' -Tag 'Test' {
    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                          = 'HQSiteLink'
                    Cost                          = 100
                    Description                   = 'HQ Site'
                    ReplicationFrequencyInMinutes = 180
                    SitesIncluded                 = 'site1', 'site2'
                    SitesExcluded                 = @()
                    OptionChangeNotification      = $false
                    OptionTwoWaySync              = $false
                    OptionDisableCompression      = $false
                    Ensure                        = 'Present'
                }
            }
        }

        Context 'When the Resource should be Present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'Cost'
                        Value    = 1
                    }
                    @{
                        Property = 'Description'
                        Value    = 'My Changed Description'
                    }
                    @{
                        Property = 'ReplicationFrequencyInMinutes'
                        Value    = 1
                    }
                    @{
                        Property = 'SitesIncluded'
                        Value    = 'site3'
                    }
                    @{
                        Property = 'SitesExcluded'
                        Value    = 'site1'
                    }
                    @{
                        Property = 'OptionChangeNotification'
                        Value    = $true
                    }
                    @{
                        Property = 'OptionTwoWaySync'
                        Value    = $true
                    }
                    @{
                        Property = 'OptionDisableCompression'
                        Value    = $true
                    }
                )
            }

            Context 'When the resource is in the desired state' {
                It 'Should return the expected result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                          = 'HQSiteLink'
                            Cost                          = 100
                            Description                   = 'HQ Site'
                            ReplicationFrequencyInMinutes = 180
                            SitesIncluded                 = 'site1', 'site2'
                            SitesExcluded                 = @()
                            OptionChangeNotification      = $false
                            OptionTwoWaySync              = $false
                            OptionDisableCompression      = $false
                            Ensure                        = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }
                }

                Context 'When the "SitesExcluded" property is specified' {
                    It 'Should return the expected result' {
                        InModuleScope -ScriptBlock {
                            Set-StrictMode -Version 1.0

                            $mockParameters = @{
                                Name                          = 'HQSiteLink'
                                Cost                          = 100
                                Description                   = 'HQ Site'
                                ReplicationFrequencyInMinutes = 180
                                SitesIncluded                 = $null
                                SitesExcluded                 = 'site3', 'site4'
                                OptionChangeNotification      = $false
                                OptionTwoWaySync              = $false
                                OptionDisableCompression      = $false
                                Ensure                        = 'Present'
                            }
                            Test-TargetResource @mockParameters | Should -BeTrue
                        }
                    }
                }
            }

            Context 'When the <Property> resource property is not in the desired state' -ForEach $testCases {
                It 'Should return the expected result' {
                    InModuleScope -Parameters $_ -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                          = 'HQSiteLink'
                            Cost                          = 100
                            Description                   = 'HQ Site'
                            ReplicationFrequencyInMinutes = 180
                            SitesIncluded                 = 'site1', 'site2'
                            SitesExcluded                 = @()
                            OptionChangeNotification      = $false
                            OptionTwoWaySync              = $false
                            OptionDisableCompression      = $false
                            Ensure                        = 'Present'
                        }

                        $mockParameters.$Property = $Value

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should return the desired result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                          = 'HQSiteLink'
                        Cost                          = 100
                        Description                   = 'HQ Site'
                        ReplicationFrequencyInMinutes = 180
                        SitesIncluded                 = 'site1', 'site2'
                        SitesExcluded                 = @()
                        OptionChangeNotification      = $false
                        OptionTwoWaySync              = $false
                        OptionDisableCompression      = $false
                        Ensure                        = 'Absent'
                    }

                    Test-TargetResource @mockParameters | Should -BeFalse
                }

                Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'HQSiteLink' } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the Resource is Absent' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith {
                    @{
                        Name                          = 'HQSiteLink'
                        Cost                          = 100
                        Description                   = 'HQ Site'
                        ReplicationFrequencyInMinutes = 180
                        SitesIncluded                 = 'site1', 'site2'
                        SitesExcluded                 = @()
                        OptionChangeNotification      = $false
                        OptionTwoWaySync              = $false
                        OptionDisableCompression      = $false
                        Ensure                        = 'Absent'
                    }
                }
            }

            Context 'When the Resource should be Present' {
                It 'Should return the desired result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                          = 'HQSiteLink'
                            Cost                          = 100
                            Description                   = 'HQ Site'
                            ReplicationFrequencyInMinutes = 180
                            SitesIncluded                 = 'site1', 'site2'
                            SitesExcluded                 = @()
                            OptionChangeNotification      = $false
                            OptionTwoWaySync              = $false
                            OptionDisableCompression      = $false
                            Ensure                        = 'Present'
                        }

                        Test-TargetResource @mockParameters | Should -BeFalse
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'HQSiteLink' } -Exactly -Times 1 -Scope It
                }
            }

            Context 'When the Resource should be Absent' {
                It 'Should return the desired result' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                          = 'HQSiteLink'
                            Cost                          = 100
                            Description                   = 'HQ Site'
                            ReplicationFrequencyInMinutes = 180
                            SitesIncluded                 = 'site1', 'site2'
                            SitesExcluded                 = @()
                            OptionChangeNotification      = $false
                            OptionTwoWaySync              = $false
                            OptionDisableCompression      = $false
                            Ensure                        = 'Absent'
                        }

                        Test-TargetResource @mockParameters | Should -BeTrue
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq 'HQSiteLink' } -Exactly -Times 1
                }
            }
        }
    }
}

Describe 'MSFT_ADReplicationSiteLink\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName New-ADReplicationSiteLink
        Mock -CommandName Set-ADReplicationSiteLink
        Mock -CommandName Remove-ADReplicationSiteLink
    }

    Context 'When the Resource is Present' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                          = 'HQSiteLink'
                    Cost                          = 100
                    Description                   = 'HQ Site'
                    ReplicationFrequencyInMinutes = 180
                    SitesIncluded                 = 'site1', 'site2'
                    SitesExcluded                 = @()
                    OptionChangeNotification      = $false
                    OptionTwoWaySync              = $false
                    OptionDisableCompression      = $false
                    Ensure                        = 'Present'
                }
            }
        }

        Context 'When the Resource should be Present' {
            BeforeDiscovery {
                $testCases = @(
                    @{
                        Property = 'Cost'
                        Value    = 1
                    }
                    @{
                        Property = 'Description'
                        Value    = 'My Changed Description'
                    }
                    @{
                        Property = 'ReplicationFrequencyInMinutes'
                        Value    = 1
                    }
                    @{
                        Property = 'SitesIncluded'
                        Value    = 'site3'
                    }
                    @{
                        Property = 'SitesExcluded'
                        Value    = 'site1'
                    }
                    @{
                        Property = 'OptionChangeNotification'
                        Value    = $true
                    }
                    @{
                        Property = 'OptionTwoWaySync'
                        Value    = $true
                    }
                    @{
                        Property = 'OptionDisableCompression'
                        Value    = $true
                    }
                )
            }

            Context 'When <Property> has changed' -ForEach $testCases {
                BeforeAll {
                    $setTargetResourceParametersChangedProperty = @{
                        Name                          = 'HQSiteLink'
                        Cost                          = 100
                        Description                   = 'HQ Site'
                        ReplicationFrequencyInMinutes = 180
                        SitesIncluded                 = 'site1', 'site2'
                        SitesExcluded                 = @()
                        OptionChangeNotification      = $false
                        OptionTwoWaySync              = $false
                        OptionDisableCompression      = $false
                        Ensure                        = 'Present'
                    }

                    $setTargetResourceParametersChangedProperty.$Property = $Value

                    if ($Property -eq 'Cost')
                    {
                        $setParameterFilter = { $Cost -eq $setTargetResourceParametersChangedProperty.Cost }
                    }
                    elseif ($Property -eq 'Description')
                    {
                        $setParameterFilter = { $Description -eq
                            $setTargetResourceParametersChangedProperty.Description }
                    }
                    elseif ($Property -eq 'ReplicationFrequencyInMinutes')
                    {
                        $setParameterFilter = { $ReplicationFrequencyInMinutes -eq
                            $setTargetResourceParametersChangedProperty.ReplicationFrequencyInMinutes }
                    }
                    elseif ($Property -eq 'SitesIncluded')
                    {
                        $setParameterFilter = { $SitesIncluded.Add -eq
                            $setTargetResourceParametersChangedProperty.SitesIncluded }
                    }
                    elseif ($Property -eq 'SitesExcluded')
                    {
                        $setTargetResourceParametersChangedProperty['SitesIncluded'] = ''
                        $setParameterFilter = { $SitesIncluded.Remove -eq
                            $setTargetResourceParametersChangedProperty.SitesExcluded }
                    }
                    elseif ($Property -eq 'OptionChangeNotification')
                    {
                        $setParameterFilter = { $Replace.Options -eq 1 }
                    }
                    elseif ($Property -eq 'OptionTwoWaySync')
                    {
                        $setParameterFilter = { $Replace.Options -eq 2 }
                    }
                    elseif ($Property -eq 'OptionDisableCompression')
                    {
                        $setParameterFilter = { $Replace.Options -eq 4 }
                    }
                }

                It 'Should not throw' {
                    InModuleScope -Parameters @{
                        mockParameters = $setTargetResourceParametersChangedProperty
                    } -ScriptBlock {
                        Set-StrictMode -Version 1.0
                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName Get-TargetResource -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADReplicationSiteLink -ParameterFilter $setParameterFilter -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName New-ADReplicationSiteLink  -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                          = 'HQSiteLink'
                        Cost                          = 100
                        Description                   = 'HQ Site'
                        ReplicationFrequencyInMinutes = 180
                        SitesIncluded                 = 'site1', 'site2'
                        SitesExcluded                 = @()
                        OptionChangeNotification      = $false
                        OptionTwoWaySync              = $false
                        OptionDisableCompression      = $false
                        Ensure                        = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADReplicationSiteLink -ParameterFilter { $Identity -eq 'HQSiteLink' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADReplicationSiteLink -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADReplicationSiteLink -Exactly -Times 0 -Scope It
            }
        }
    }

    Context 'When the Resource is Absent' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    Name                          = 'HQSiteLink'
                    Cost                          = 100
                    Description                   = 'HQ Site'
                    ReplicationFrequencyInMinutes = 180
                    SitesIncluded                 = 'site1', 'site2'
                    SitesExcluded                 = @()
                    OptionChangeNotification      = $false
                    OptionTwoWaySync              = $false
                    OptionDisableCompression      = $false
                    Ensure                        = 'Absent'
                }
            }
        }

        Context 'When the Resource should be Present' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                          = 'HQSiteLink'
                        Cost                          = 100
                        Description                   = 'HQ Site'
                        ReplicationFrequencyInMinutes = 180
                        SitesIncluded                 = 'site1', 'site2'
                        SitesExcluded                 = @()
                        OptionChangeNotification      = $false
                        OptionTwoWaySync              = $false
                        OptionDisableCompression      = $false
                        Ensure                        = 'Present'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName New-ADReplicationSiteLink -ParameterFilter { $Name -eq 'HQSiteLink' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Set-ADReplicationSiteLink -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADReplicationSiteLink -Exactly -Times 0 -Scope It
            }

            Context 'When an Option parameter has been specified' {
                It 'Should not throw' {
                    InModuleScope -ScriptBlock {
                        Set-StrictMode -Version 1.0

                        $mockParameters = @{
                            Name                          = 'HQSiteLink'
                            Cost                          = 100
                            Description                   = 'HQ Site'
                            ReplicationFrequencyInMinutes = 180
                            SitesIncluded                 = 'site1', 'site2'
                            SitesExcluded                 = @()
                            OptionChangeNotification      = $true
                            OptionTwoWaySync              = $false
                            OptionDisableCompression      = $false
                            Ensure                        = 'Present'
                        }

                        { Set-TargetResource @mockParameters } | Should -Not -Throw
                    }

                    Should -Invoke -CommandName New-ADReplicationSiteLink -ParameterFilter { $Name -eq 'HQSiteLink' } -Exactly -Times 1 -Scope It
                    Should -Invoke -CommandName Set-ADReplicationSiteLink -Exactly -Times 0 -Scope It
                    Should -Invoke -CommandName Remove-ADReplicationSiteLink -Exactly -Times 0 -Scope It
                }
            }
        }

        Context 'When the Resource should be Absent' {
            It 'Should not throw' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        Name                          = 'HQSiteLink'
                        Cost                          = 100
                        Description                   = 'HQ Site'
                        ReplicationFrequencyInMinutes = 180
                        SitesIncluded                 = 'site1', 'site2'
                        SitesExcluded                 = @()
                        OptionChangeNotification      = $false
                        OptionTwoWaySync              = $false
                        OptionDisableCompression      = $false
                        Ensure                        = 'Absent'
                    }

                    { Set-TargetResource @mockParameters } | Should -Not -Throw
                }

                Should -Invoke -CommandName Remove-ADReplicationSiteLink -ParameterFilter { $Identity -eq 'HQSiteLink' } -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName New-ADReplicationSiteLink -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Set-ADReplicationSiteLink -Exactly -Times 0 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADReplicationSiteLink\ResolveSiteLinkName' -Tag 'Helper' {
    BeforeAll {
        Mock -CommandName Get-ADReplicationSite
    }

    It 'Should not throw' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            $resolveSiteLinkParams = @{
                SiteName = 'site1'
            }

            { Resolve-SiteLinkName @resolveSiteLinkParams } | Should -Not -Throw
        }

        Should -Invoke -CommandName Get-ADReplicationSite -ParameterFilter { $Identity -eq 'site1' } -Exactly -Times 1 -Scope It
    }
}

Describe 'MSFT_ADReplicationSiteLink\Get-EnabledOptions' -Tag 'Helper' {
    Context 'When all options are disabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 0

                $result.USE_NOTIFY | Should -BeFalse
                $result.TWOWAY_SYNC | Should -BeFalse
                $result.DISABLE_COMPRESSION | Should -BeFalse
            }
        }
    }

    Context 'When Change Notification Replication is enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 1

                $result.USE_NOTIFY | Should -BeTrue
                $result.TWOWAY_SYNC | Should -BeFalse
                $result.DISABLE_COMPRESSION | Should -BeFalse
            }
        }
    }

    Context 'When Two Way Sync Replication is enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 2

                $result.USE_NOTIFY | Should -BeFalse
                $result.TWOWAY_SYNC | Should -BeTrue
                $result.DISABLE_COMPRESSION | Should -BeFalse
            }
        }
    }

    Context 'When Change Notification and Two Way Sync Replication are enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 3

                $result.USE_NOTIFY | Should -BeTrue
                $result.TWOWAY_SYNC | Should -BeTrue
                $result.DISABLE_COMPRESSION | Should -BeFalse
            }
        }
    }

    Context 'When Disable Compression is enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 4

                $result.USE_NOTIFY | Should -BeFalse
                $result.TWOWAY_SYNC | Should -BeFalse
                $result.DISABLE_COMPRESSION | Should -BeTrue
            }
        }
    }

    Context 'When Change Notification and Disable Compression Replication are enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 5

                $result.USE_NOTIFY | Should -BeTrue
                $result.TWOWAY_SYNC | Should -BeFalse
                $result.DISABLE_COMPRESSION | Should -BeTrue
            }
        }
    }

    Context 'When Disable Compression and Two Way Sync Replication are enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 6

                $result.USE_NOTIFY | Should -BeFalse
                $result.TWOWAY_SYNC | Should -BeTrue
                $result.DISABLE_COMPRESSION | Should -BeTrue
            }
        }
    }

    Context 'When all options are enabled' {
        It 'Should return the expected results' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $result = Get-EnabledOptions -OptionValue 7

                $result.USE_NOTIFY | Should -BeTrue
                $result.TWOWAY_SYNC | Should -BeTrue
                $result.DISABLE_COMPRESSION | Should -BeTrue
            }
        }
    }
}

Describe 'MSFT_ADReplicationSiteLink\ConvertTo-EnabledOptions' -Tag 'Helper' {
    Context 'When all options are disabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $false
                    OptionTwoWaySync         = $false
                    OptionDisableCompression = $false
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 0
            }
        }
    }

    Context 'When Change Notification Replication is enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $true
                    OptionTwoWaySync         = $false
                    OptionDisableCompression = $false
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 1
            }
        }
    }

    Context 'When Two Way Sync is enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $false
                    OptionTwoWaySync         = $true
                    OptionDisableCompression = $false
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 2
            }
        }
    }

    Context 'When Change Notification Replication and Two Way Sync are enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $true
                    OptionTwoWaySync         = $true
                    OptionDisableCompression = $false
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 3
            }
        }
    }

    Context 'When Disable Compression is enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $false
                    OptionTwoWaySync         = $false
                    OptionDisableCompression = $true
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 4
            }
        }
    }

    Context 'When Change Notification Replication and Disable Compression are enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $true
                    OptionTwoWaySync         = $false
                    OptionDisableCompression = $true
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 5
            }
        }
    }

    Context 'When Disable Compression and Two Way Sync are enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $false
                    OptionTwoWaySync         = $true
                    OptionDisableCompression = $true
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 6
            }
        }
    }

    Context 'When all options are enabled' {
        It 'Should return the expected result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testParameters = @{
                    OptionChangeNotification = $true
                    OptionTwoWaySync         = $true
                    OptionDisableCompression = $true
                }

                ConvertTo-EnabledOptions @testParameters | Should -Be 7
            }
        }
    }
}
