$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADReplicationSiteLink'

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

# Begin Testing

Invoke-TestSetup

try
{
    InModuleScope $script:dscResourceName {
        Set-StrictMode -Version 1.0

        # Load stub cmdlets and classes.
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1') -Force

        $mockSiteName = 'HQSiteLink'
        $mockSite1 = 'site1'
        $mockSite2 = 'site2'
        $mockSite3 = 'site3'
        $mockSite4 = 'site4'

        $mockResource = @{
            Name                          = $mockSiteName
            Cost                          = 100
            Description                   = 'HQ Site'
            ReplicationFrequencyInMinutes = 180
            SitesIncluded                 = $mockSite1, $mockSite2
            SitesExcluded                 = @()
            OptionChangeNotification      = $false
            OptionTwoWaySync              = $false
            OptionDisableCompression      = $false
        }

        $mockChangedResource = @{
            Cost                          = 1
            Description                   = 'My Changed Description'
            ReplicationFrequencyInMinutes = 1
            SitesIncluded                 = $mockSite3
            SitesExcluded                 = $mockSite1
            OptionChangeNotification      = $true
            OptionTwoWaySync              = $true
            OptionDisableCompression      = $true
        }

        $mockGetADReplicationSiteLinkReturn = @{
            Name                          = $mockResource.Name
            Cost                          = $mockResource.Cost
            Description                   = $mockResource.Description
            ReplicationFrequencyInMinutes = $mockResource.ReplicationFrequencyInMinutes
            SitesIncluded                 = @(
                "CN=$mockSite1,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com",
                "CN=$mockSite2,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com"
            )
        }

        $mockGetADReplicationSiteLinkOptionsReturn = $mockGetADReplicationSiteLinkReturn.Clone()
        $mockGetADReplicationSiteLinkOptionsReturn['Options'] = 7

        $mockGetTargetResourcePresentResult = $mockResource.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockResource.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        $mockADReplicationSiteLinkSitesExcluded = $mockGetADReplicationSiteLinkReturn.Clone()
        $mockADReplicationSiteLinkSitesExcluded['SitesIncluded'] = $null

        Describe 'ADReplicationSiteLink\Get-TargetResource' {
            Context 'When sites are included' {
                BeforeAll {
                    Mock -CommandName Get-ADReplicationSiteLink `
                        -MockWith { $mockGetADReplicationSiteLinkReturn }
                    Mock -CommandName Resolve-SiteLinkName `
                        -MockWith { $mockSite1 } `
                        -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[0] }
                    Mock -CommandName Resolve-SiteLinkName `
                        -MockWith { $mockSite2 } `
                        -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[1] }
                }

                It 'Should return the expected results' {
                    $getResult = Get-TargetResource -Name $mockSiteName

                    $getResult.Name | Should -Be $mockGetADReplicationSiteLinkReturn.Name
                    $getResult.Cost | Should -Be $mockGetADReplicationSiteLinkReturn.Cost
                    $getResult.Description | Should -Be $mockGetADReplicationSiteLinkReturn.Description
                    $getResult.ReplicationFrequencyInMinutes |
                        Should -Be $mockGetADReplicationSiteLinkReturn.ReplicationFrequencyInMinutes
                    $getResult.SitesIncluded | Should -Be $mockSite1, $mockSite2
                    $getResult.SitesExcluded | Should -BeNullOrEmpty
                    $getResult.Ensure | Should -Be 'Present'
                    $getResult.OptionChangeNotification | Should -BeFalse
                    $getResult.OptionTwoWaySync | Should -BeFalse
                    $getResult.OptionDisableCompression | Should -BeFalse
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-ADReplicationSiteLink `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Resolve-SiteLinkName `
                        -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[0] } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Resolve-SiteLinkName `
                        -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkReturn.SitesIncluded[1] } `
                        -Exactly -Times 1
                }
            }

            Context 'When site link options are enabled' {
                BeforeAll {
                    Mock -CommandName Get-ADReplicationSiteLink `
                        -MockWith { $mockGetADReplicationSiteLinkOptionsReturn }
                    Mock -CommandName Resolve-SiteLinkName `
                        -MockWith { $mockSite1 } `
                        -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkOptionsReturn.SitesIncluded[0] }
                    Mock -CommandName Resolve-SiteLinkName `
                        -MockWith { $mockSite2 } `
                        -ParameterFilter { $SiteName -eq $mockGetADReplicationSiteLinkOptionsReturn.SitesIncluded[1] }
                }

                It 'Should return the expected results' {
                    $getResult = Get-TargetResource -Name $mockSiteName

                    $getResult.Name | Should -Be $mockGetADReplicationSiteLinkOptionsReturn.Name
                    $getResult.Cost | Should -Be $mockGetADReplicationSiteLinkOptionsReturn.Cost
                    $getResult.Description | Should -Be $mockGetADReplicationSiteLinkOptionsReturn.Description
                    $getResult.ReplicationFrequencyInMinutes |
                        Should -Be $mockGetADReplicationSiteLinkOptionsReturn.ReplicationFrequencyInMinutes
                    $getResult.SitesIncluded | Should -Be $mockSite1, $mockSite2
                    $getResult.SitesExcluded | Should -BeNullOrEmpty
                    $getResult.Ensure | Should -Be 'Present'
                    $getResult.OptionChangeNotification | Should -BeTrue
                    $getResult.OptionTwoWaySync | Should -BeTrue
                    $getResult.OptionDisableCompression | Should -BeTrue
                }
            }

            Context 'When AD Replication Sites do not exist' {
                BeforeAll {
                    $ADIdentityNotFoundException = New-Object `
                        -TypeName Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                    Mock -CommandName Get-ADReplicationSiteLink `
                        -MockWith { throw $ADIdentityNotFoundException }
                }

                It 'Should return the expected results' {
                    $getResult = Get-TargetResource -Name $mockSiteName

                    $getResult.Name | Should -Be $mockSiteName
                    $getResult.Cost | Should -BeNullOrEmpty
                    $getResult.Description | Should -BeNullOrEmpty
                    $getResult.ReplicationFrequencyInMinutes | Should -BeNullOrEmpty
                    $getResult.SitesIncluded | Should -BeNullOrEmpty
                    $getResult.SitesExcluded | Should -BeNullOrEmpty
                    $getResult.Ensure | Should -Be 'Absent'
                    $getResult.OptionChangeNotification | Should -BeFalse
                    $getResult.OptionTwoWaySync | Should -BeFalse
                    $getResult.OptionDisableCompression | Should -BeFalse
                }
            }

            Context 'When Get-ADReplicationSiteLink throws an unexpected error' {
                BeforeAll {
                    Mock -CommandName Get-ADReplicationSiteLink -MockWith { throw }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource -Name $mockSiteName } | `
                            Should -Throw ($script:localizedData.GetSiteLinkUnexpectedError -f $mockSiteName)
                }
            }

            Context 'When Sites are excluded' {
                BeforeAll {
                    Mock -CommandName Get-ADReplicationSiteLink `
                        -MockWith { $mockADReplicationSiteLinkSitesExcluded }
                }

                It 'Should return the expected results' {
                    $getResult = Get-TargetResource -Name $mockSiteName -SitesExcluded $mockSite3, $mockSite4

                    $getResult.Name | Should -Be $mockADReplicationSiteLinkSitesExcluded.Name
                    $getResult.Cost | Should -Be $mockADReplicationSiteLinkSitesExcluded.Cost
                    $getResult.Description | Should -Be $mockADReplicationSiteLinkSitesExcluded.Description
                    $getResult.ReplicationFrequencyInMinutes |
                        Should -Be $mockADReplicationSiteLinkSitesExcluded.ReplicationFrequencyInMinutes
                    $getResult.SitesIncluded | Should -BeNullOrEmpty
                    $getResult.SitesExcluded | Should -Be $mockSite3, $mockSite4
                    $getResult.Ensure | Should -Be 'Present'
                    $getResult.OptionChangeNotification | Should -Be $false
                    $getResult.OptionTwoWaySync | Should -Be $false
                    $getResult.OptionDisableCompression | Should -Be $false
                }
            }
        }

        Describe 'ADReplicationSiteLink\Test-TargetResource' {
            BeforeAll {
                $testTargetResourcePresentParameters = $mockResource.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $mockResource.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {

                    Context 'When the resource is in the desired state' {

                        It 'Should return the expected result' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -BeTrue
                        }

                        Context 'When the "SitesExcluded" property is specified' {
                            BeforeAll {
                                $testtargetResourcePresentSitesExcludedParameters = `
                                    $testTargetResourcePresentParameters.Clone()
                                $testtargetResourcePresentSitesExcludedParameters['SitesIncluded'] = $null
                                $testtargetResourcePresentSitesExcludedParameters['SitesExcluded'] = `
                                    $mockSite3, $mockSite4
                            }

                            It 'Should return the expected result' {
                                Test-TargetResource @testtargetResourcePresentSitesExcludedParameters | Should -BeTrue
                            }
                        }
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            BeforeAll {
                                $testTargetResourceNotInDesiredStateParameters = `
                                    $testTargetResourcePresentParameters.clone()
                                $testTargetResourceNotInDesiredStateParameters[$property] = `
                                    $mockChangedResource.$property
                            }

                            It 'Should return the expected result' {
                                Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -BeFalse
                            }
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resource is Absent' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                    }

                    Context 'When the Resource should be Present' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the Resource should be Absent' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                                -Exactly -Times 1
                        }
                    }
                }
            }
        }

        Describe 'ADReplicationSiteLink\Set-TargetResource' {
            BeforeAll {

                $setTargetResourcePresentParameters = $mockResource.Clone()
                $setTargetResourcePresentParameters['Ensure'] = 'Present'

                $setTargetResourceAbsentParameters = $mockResource.Clone()
                $setTargetResourceAbsentParameters['Ensure'] = 'Absent'

                Mock -CommandName New-ADReplicationSiteLink
                Mock -CommandName Set-ADReplicationSiteLink
                Mock -CommandName Remove-ADReplicationSiteLink
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When $property has changed" {
                            BeforeAll {
                                $setTargetResourceParametersChangedProperty = `
                                    $setTargetResourcePresentParameters.Clone()
                                $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property

                                if ($property -eq 'Cost')
                                {
                                    $setParameterFilter = `
                                    { $Cost -eq $setTargetResourceParametersChangedProperty.Cost }
                                }
                                elseif ($property -eq 'Description')
                                {
                                    $setParameterFilter = { $Description -eq
                                        $setTargetResourceParametersChangedProperty.Description }
                                }
                                elseif ($property -eq 'ReplicationFrequencyInMinutes')
                                {
                                    $setParameterFilter = { $ReplicationFrequencyInMinutes -eq
                                        $setTargetResourceParametersChangedProperty.ReplicationFrequencyInMinutes }
                                }
                                elseif ($property -eq 'SitesIncluded')
                                {
                                    $setParameterFilter = { $SitesIncluded.Add -eq
                                        $setTargetResourceParametersChangedProperty.SitesIncluded }
                                }
                                elseif ($property -eq 'SitesExcluded')
                                {
                                    $setTargetResourceParametersChangedProperty['SitesIncluded'] = ''
                                    $setParameterFilter = { $SitesIncluded.Remove -eq
                                        $setTargetResourceParametersChangedProperty.SitesExcluded }
                                }
                                elseif ($property -eq 'OptionChangeNotification')
                                {
                                    $setParameterFilter = { $Replace.Options -eq 1 }
                                }
                                elseif ($property -eq 'OptionTwoWaySync')
                                {
                                    $setParameterFilter = { $Replace.Options -eq 2 }
                                }
                                elseif ($property -eq 'OptionDisableCompression')
                                {
                                    $setParameterFilter = { $Replace.Options -eq 4 }
                                }
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                            }

                            It 'Should call the correct mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { `
                                        $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Set-ADReplicationSiteLink `
                                    -ParameterFilter $setParameterFilter `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName New-ADReplicationSiteLink  `
                                    -Exactly -Times 0
                            }
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADReplicationSiteLink `
                            -ParameterFilter { $Identity -eq $mockSiteName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADReplicationSiteLink  `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADReplicationSiteLink `
                            -Exactly -Times 0
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName New-ADReplicationSiteLink `
                            -ParameterFilter { $Name -eq $mockSiteName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Set-ADReplicationSiteLink `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADReplicationSiteLink `
                            -Exactly -Times 0
                    }

                    Context 'When an Option parameter has been specified' {
                        BeforeAll {
                            $setTargetResourcePresentOptionParameters = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourcePresentOptionParameters['OptionChangeNotification'] = $true
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentOptionParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName New-ADReplicationSiteLink `
                                -ParameterFilter { $Name -eq $mockSiteName } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADReplicationSiteLink `
                                -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADReplicationSiteLink `
                                -Exactly -Times 0
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-ADReplicationSiteLink `
                            -ParameterFilter { $Identity -eq $mockSiteName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADReplicationSiteLink `
                            -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADReplicationSiteLink `
                            -Exactly -Times 0
                    }
                }
            }
        }

        Describe 'ADReplicationSiteLink\ResolveSiteLinkName' {
            BeforeAll {
                $mockSiteName = $mockSite1
                $resolveSiteLinkParms = @{
                    SiteName = $mockSiteName
                }
                Mock -CommandName Get-ADReplicationSite
            }

            It 'Should not throw' {
                { Resolve-SiteLinkName @resolveSiteLinkParms } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-ADReplicationSite `
                    -ParameterFilter { $Identity -eq $resolveSiteLinkParms.SiteName } `
                    -Exactly -Times 1
            }
        }

        Describe 'ADReplicationSiteLink\Get-EnabledOptions' {

            Context 'When all options are disabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 0

                    $result.USE_NOTIFY | Should -BeFalse
                    $result.TWOWAY_SYNC | Should -BeFalse
                    $result.DISABLE_COMPRESSION | Should -BeFalse
                }
            }

            Context 'When Change Notification Replication is enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 1

                    $result.USE_NOTIFY | Should -BeTrue
                    $result.TWOWAY_SYNC | Should -BeFalse
                    $result.DISABLE_COMPRESSION | Should -BeFalse
                }
            }

            Context 'When Two Way Sync Replication is enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 2

                    $result.USE_NOTIFY | Should -BeFalse
                    $result.TWOWAY_SYNC | Should -BeTrue
                    $result.DISABLE_COMPRESSION | Should -BeFalse
                }
            }

            Context 'When Change Notification and Two Way Sync Replication are enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 3

                    $result.USE_NOTIFY | Should -BeTrue
                    $result.TWOWAY_SYNC | Should -BeTrue
                    $result.DISABLE_COMPRESSION | Should -BeFalse
                }
            }

            Context 'When Disable Compression is enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 4

                    $result.USE_NOTIFY | Should -BeFalse
                    $result.TWOWAY_SYNC | Should -BeFalse
                    $result.DISABLE_COMPRESSION | Should -BeTrue
                }
            }

            Context 'When Change Notification and Disable Compression Replication are enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 5

                    $result.USE_NOTIFY | Should -BeTrue
                    $result.TWOWAY_SYNC | Should -BeFalse
                    $result.DISABLE_COMPRESSION | Should -BeTrue
                }
            }

            Context 'When Disable Compression and Two Way Sync Replication are enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 6

                    $result.USE_NOTIFY | Should -BeFalse
                    $result.TWOWAY_SYNC | Should -BeTrue
                    $result.DISABLE_COMPRESSION | Should -BeTrue
                }
            }

            Context 'When all options are enabled' {
                It 'Should return the expected results' {
                    $result = Get-EnabledOptions -optionValue 7

                    $result.USE_NOTIFY | Should -BeTrue
                    $result.TWOWAY_SYNC | Should -BeTrue
                    $result.DISABLE_COMPRESSION | Should -BeTrue
                }
            }
        }

        Describe 'ADReplicationSiteLink\ConvertTo-EnabledOptions' {

            Context 'When all options are disabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $false
                        OptionTwoWaySync         = $false
                        OptionDisableCompression = $false
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 0
                }
            }

            Context 'When Change Notification Replication is enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $true
                        OptionTwoWaySync         = $false
                        OptionDisableCompression = $false
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 1
                }
            }

            Context 'When Two Way Sync is enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $false
                        OptionTwoWaySync         = $true
                        OptionDisableCompression = $false
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 2
                }
            }

            Context 'When Change Notification Replication and Two Way Sync are enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $true
                        OptionTwoWaySync         = $true
                        OptionDisableCompression = $false
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 3
                }
            }

            Context 'When Disable Compression is enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $false
                        OptionTwoWaySync         = $false
                        OptionDisableCompression = $true
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 4
                }
            }

            Context 'When Change Notification Replication and Disable Compression are enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $true
                        OptionTwoWaySync         = $false
                        OptionDisableCompression = $true
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 5
                }
            }

            Context 'When Disable Compression and Two Way Sync are enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $false
                        OptionTwoWaySync         = $true
                        OptionDisableCompression = $true
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 6
                }
            }

            Context 'When all options are enabled' {
                BeforeAll {
                    $testParameters = @{
                        OptionChangeNotification = $true
                        OptionTwoWaySync         = $true
                        OptionDisableCompression = $true
                    }
                }

                It 'Should return the expected result' {
                    $result = ConvertTo-EnabledOptions @testParameters

                    $result | Should -Be 7
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
