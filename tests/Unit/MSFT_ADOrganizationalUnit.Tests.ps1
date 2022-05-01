$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADOrganizationalUnit'

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

        $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'DummyUser',
            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
        )

        $testPresentParams = @{
            Name        = 'TestOU'
            Path        = 'OU=Fake,DC=contoso,DC=com'
            Description = 'Test AD OU description'
            Ensure      = 'Present'
        }

        $testAbsentParams = $testPresentParams.Clone()
        $testAbsentParams['Ensure'] = 'Absent'

        $mockName = 'TestOU'
        $mockPath = 'OU=Fake,DC=contoso,DC=com'
        $mockDistinguishedName = 'OU=' + $mockName + ',' + $mockPath

        $mockResource = @{
            Name                            = $mockName
            Path                            = $mockPath
            Description                     = 'Test AD OU description'
            ProtectedFromAccidentalDeletion = $false
            DistinguishedName               = $mockDistinguishedName
            Ensure                          = 'Present'
        }

        $mockAbsentResource = @{
            Name                            = $mockResource.Name
            Path                            = $mockResource.Path
            Description                     = $null
            ProtectedFromAccidentalDeletion = $null
            DistinguishedName               = $null
            Ensure                          = 'Absent'
        }

        $mockChangedResource = @{
            Description                     = 'Changed Test AD OU description'
            ProtectedFromAccidentalDeletion = $true
        }

        $mockProtectedAdOu = $mockResource.Clone()
        $mockProtectedAdOu['ProtectedFromAccidentalDeletion'] = $true

        $mockGetTargetResourcePresentResult = $mockResource.Clone()
        $mockGetTargetResourcePresentResult['Ensure'] = 'Present'

        $mockGetTargetResourceAbsentResult = $mockResource.Clone()
        $mockGetTargetResourceAbsentResult['Ensure'] = 'Absent'

        #region Function Get-TargetResource
        Describe 'ADOrganizationalUnit\Get-TargetResource' {
            BeforeAll {
                $getTargetResourceParams = @{
                    Name = $mockResource.Name
                    Path = $mockResource.Path
                }

                $mockGetADOrganizationUnitResult = @{
                    Name                            = $mockResource.Name
                    Path                            = $mockResource.Path
                    Description                     = $mockResource.Description
                    ProtectedFromAccidentalDeletion = $mockResource.ProtectedFromAccidentalDeletion
                    DistinguishedName               = $mockResource.DistinguishedName
                }

                Mock -CommandName Assert-Module
            }

            Context 'When the resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-ADOrganizationalUnit -MockWith { $mockGetADOrganizationUnitResult }

                    $result = Get-TargetResource @getTargetResourceParams
                }

                foreach ($property in $mockResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockResource.$property
                    }
                }

                Context 'When the OU has apostrophe' {
                    BeforeAll {
                        $mockGetADOrganizationUnitProtectedResult = $mockGetADOrganizationUnitResult.Clone()
                        $mockGetADOrganizationUnitProtectedResult['Name'] = "Jones's OU"

                        Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                            return $mockGetADOrganizationUnitProtectedResult
                         }
                    }

                    It 'Should return the desired result' {
                        $getTargetResourceParamsWithApostrophe = $getTargetResourceParams.Clone()
                        $getTargetResourceParamsWithApostrophe['Name'] = "Jones's OU"

                        $targetResource = Get-TargetResource @getTargetResourceParamsWithApostrophe

                        $targetResource.Name | Should -Be "Jones's OU"

                        # Regression tests for issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/674.
                        Assert-MockCalled -CommandName Get-ADOrganizationalUnit -ParameterFilter {
                             $Filter -eq ('Name -eq "{0}"' -f "Jones's OU")
                         }
                    }
                }

                Context 'When the OU is protected' {
                    BeforeAll {

                        $mockGetADOrganizationUnitProtectedResult = $mockGetADOrganizationUnitResult.Clone()
                        $mockGetADOrganizationUnitProtectedResult['ProtectedFromAccidentalDeletion'] = $true

                        Mock -CommandName Get-ADOrganizationalUnit -MockWith { $mockGetADOrganizationUnitProtectedResult }
                    }

                    It 'Should return the desired result' {
                        $targetResource = Get-TargetResource @getTargetResourceParams

                        $targetResource.ProtectedFromAccidentalDeletion | Should -BeTrue
                    }
                }
            }

            Context 'When the resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-ADOrganizationalUnit

                    $result = Get-TargetResource @getTargetResourceParams
                }

                foreach ($property in $mockAbsentResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }
            }

            Context 'When the OU parent path does not exist' {
                It 'Returns the correct result' {
                    Mock -CommandName Get-ADOrganizationalUnit -MockWith {
                        throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new()
                    }

                    $targetResource = Get-TargetResource @getTargetResourceParams
                    $targetResource.Ensure | Should -Be 'Absent'
                }
            }

            Context 'When "Get-ADOrganizationUnit" throws an unexpected error' {
                It 'Should throw the correct exception' {
                    Mock -CommandName Get-ADOrganizationalUnit -MockWith { throw 'error' }

                    { Get-TargetResource @getTargetResourceParams } |
                        Should -Throw ($script:localizedData.GetResourceError -f $getTargetResourceParams.Name)
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADOrganizationalUnit\Test-TargetResource' {
            BeforeAll {
                $testTargetResourceParams = @{
                    Name                            = $mockResource.Name
                    Path                            = $mockResource.Path
                    Description                     = $mockResource.Description
                    ProtectedFromAccidentalDeletion = $mockResource.ProtectedFromAccidentalDeletion
                }

                $testTargetResourcePresentParams = $testTargetResourceParams.Clone()
                $testTargetResourcePresentParams['Ensure'] = 'Present'

                $testTargetResourceAbsentParams = $testTargetResourceParams.Clone()
                $testTargetResourceAbsentParams['Ensure'] = 'Absent'

                Mock -CommandName Assert-Module
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {

                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParams } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name -and `
                                $Path -eq $testTargetResourcePresentParams.Path } `
                            -Exactly -times 1
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            BeforeAll {
                                $testTargetResourceNotInDesiredStateParams = $testTargetResourcePresentParams.Clone()
                                $testTargetResourceNotInDesiredStateParams.$property = $mockChangedResource.$property
                            }

                            It 'Should return $false' {
                                Test-TargetResource @testTargetResourceNotInDesiredStateParams | Should -Be $false
                            }
                        }
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return $true' {
                            Test-TargetResource @testTargetResourcePresentParams | Should -BeTrue
                        }
                    }

                    # Regression test for issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/624.
                    Context 'When parameter RestoreFromRecycleBin is specified' {
                        It 'Should return $true' {
                            $mockTestTargetResourceParameters = @{
                                Name                            = $mockResource.Name
                                Path                            = $mockResource.Path
                                Description                     = $mockResource.Description
                                ProtectedFromAccidentalDeletion = $mockResource.ProtectedFromAccidentalDeletion
                                RestoreFromRecycleBin           = $true
                            }

                            Test-TargetResource @mockTestTargetResourceParameters | Should -BeTrue
                        }
                    }
                }

                Context 'When the Resource should be Absent' {

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceAbsentParams | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParams.Name -and `
                                $Path -eq $testTargetResourceAbsentParams.Path } `
                            -Exactly -times 1
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourcePresentParams | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParams.Name -and `
                                $Path -eq $testTargetResourcePresentParams.Path } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceAbsentParams | Should -Be $true
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParams.Name -and `
                                $Path -eq $testTargetResourceAbsentParams.Path } `
                            -Exactly -times 1
                    }
                }
            }
        }
        #endregion

        #region Function Set-TargetResource

        Describe 'ADOrganizationalUnit\Set-TargetResource' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name                            = $mockResource.Name
                    Path                            = $mockResource.Path
                    Description                     = $mockResource.Description
                    ProtectedFromAccidentalDeletion = $mockResource.ProtectedFromAccidentalDeletion
                }

                $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourcePresentParameters.Ensure = 'Present'

                $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceAbsentParameters.Ensure = 'Absent'

                Mock -CommandName New-ADOrganizationalUnit
                Mock -CommandName Set-ADOrganizationalUnit
                Mock -CommandName Remove-ADOrganizationalUnit
                Mock -CommandName Restore-ADCommonObject
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
                                $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                                $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                            }

                            It 'Should call the correct mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Set-ADOrganizationalUnit `
                                    -ParameterFilter { $Identity -eq $mockDistinguishedName } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                            }
                        }
                    }

                    Context 'When the "Credential" parameter is specified' {
                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParameters -Credential $testCredential } |
                                Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit `
                                -ParameterFilter { $Credential -eq $testCredential } -Exactly -Times 1
                        }
                    }

                    Context 'When Set-ADOrganizationalUnit throws an exception' {
                        BeforeAll {
                            Mock -CommandName Set-ADOrganizationalUnit -MockWith { throw $mockError }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourcePresentParameters } |
                                Should -Throw ($script:localizedData.SetResourceError -f
                                    $setTargetResourcePresentParameters.Name)
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit `
                                -ParameterFilter { $Identity -eq $mockDistinguishedName } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-ADOrganizationalUnit `
                            -ParameterFilter { $Identity -eq $mockDistinguishedName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                    }

                    Context 'When the OrganizationalUnit is protected from deletion' {
                        BeforeAll {
                            $mockGetTargetResourcePresentProtectedResult = $mockGetTargetResourcePresentResult.Clone()
                            $mockGetTargetResourcePresentProtectedResult['ProtectedFromAccidentalDeletion'] = $true

                            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentProtectedResult }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit `
                                -ParameterFilter { $Identity -eq $mockDistinguishedName -and `
                                    $ProtectedFromAccidentalDeletion -eq $false } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit `
                                -ParameterFilter { $Identity -eq $mockDistinguishedName } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                        }

                        Context 'When the "Credential" parameter is specified' {
                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourceAbsentParameters -Credential $testCredential } |
                                    Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Set-ADOrganizationalUnit `
                                    -ParameterFilter { $Identity -eq $mockDistinguishedName -and `
                                        $ProtectedFromAccidentalDeletion -eq $false -and `
                                        $Credential -eq $testCredential } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Remove-ADOrganizationalUnit `
                                    -ParameterFilter { $Identity -eq $mockDistinguishedName -and `
                                        $Credential -eq $testCredential } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                            }
                        }

                        Context 'When Set-ADOrganizationalUnit throws an exception' {
                            BeforeAll {
                                Mock -CommandName Set-ADOrganizationalUnit -MockWith { throw 'error' }
                            }

                            It 'Should throw the correct exception' {
                                { Set-TargetResource @setTargetResourceAbsentParameters } | `
                                        Should -Throw ($script:localizedData.SetResourceError -f
                                        $setTargetResourceAbsentParameters.Name)
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Set-ADOrganizationalUnit `
                                    -ParameterFilter { $Identity -eq $mockDistinguishedName -and `
                                        $ProtectedFromAccidentalDeletion -eq $false } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                            }
                        }
                    }

                    Context 'When Remove-ADOrganizationalUnit throws an exception' {
                        BeforeAll {
                            Mock -CommandName Remove-ADOrganizationalUnit -MockWith { throw 'error' }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceAbsentParameters } | `
                                    Should -Throw ($script:localizedData.RemoveResourceError -f
                                    $setTargetResourceAbsentParameters.Name)
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit `
                                -ParameterFilter { $Identity -eq $mockDistinguishedName } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                        }
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
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADOrganizationalUnit `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                    }

                    Context 'When the "RestoreFromRecycleBin" parameter is specified' {
                        BeforeAll {
                            $setTargetResourcePresentRecycleBinParameters = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourcePresentRecycleBinParameters['RestoreFromRecycleBin'] = $true

                            Mock -CommandName Restore-ADCommonObject -MockWith { $true }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentRecycleBinParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentRecycleBinParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Restore-ADCommonObject `
                                -ParameterFilter { $Identity -eq $setTargetResourcePresentRecycleBinParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                        }

                        Context 'When the "Credential" parameter is specified' {
                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentRecycleBinParameters `
                                        -Credential $testCredential } | Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentRecycleBinParameters.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Restore-ADCommonObject `
                                    -ParameterFilter { `
                                        $Identity -eq $setTargetResourcePresentRecycleBinParameters.Name -and `
                                        $Credential -eq $testCredential } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                            }
                        }

                        Context 'When Restore from Recycle Bin was unsuccessful' {
                            BeforeAll {
                                Mock -CommandName Restore-ADCommonObject -MockWith { $false }
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourcePresentRecycleBinParameters } | Should -Not -Throw
                            }

                            It 'Should call the expected mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentRecycleBinParameters.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Restore-ADCommonObject `
                                    -ParameterFilter { $Identity -eq $setTargetResourcePresentRecycleBinParameters.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName New-ADOrganizationalUnit `
                                    -ParameterFilter { $Name -eq $setTargetResourcePresentRecycleBinParameters.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                                Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                            }
                        }
                    }

                    Context 'When the "Credential" parameter is specified' {
                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentParameters `
                                    -Credential $testCredential } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name -and `
                                    $Credential -eq $testCredential } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                        }
                    }

                    Context 'When New-ADOrganizationalUnit throws ADIdentityNotFoundException' {
                        BeforeAll {
                            $ADIdentityNotFoundException = `
                                [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new()

                            Mock -CommandName New-ADOrganizationalUnit -MockWith { throw $ADIdentityNotFoundException }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourcePresentParameters } |
                                Should -Throw ($script:localizedData.PathNotFoundError -f
                                    $setTargetResourcePresentParameters.Path)
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                        }
                    }

                    Context 'When New-ADOrganizationalUnit throws an unexpected exception' {
                        BeforeAll {
                            Mock -CommandName New-ADOrganizationalUnit -MockWith { throw $mockError }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourcePresentParameters } |
                                Should -Throw ($script:localizedData.NewResourceError -f
                                    $setTargetResourcePresentParameters.Name)
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName New-ADOrganizationalUnit `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                            Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters -Verbose } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName New-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Set-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Remove-ADOrganizationalUnit -Exactly -Times 0
                        Assert-MockCalled -CommandName Restore-ADCommonObject -Exactly -Times 0
                    }
                }
            }
        }
        #endregion
    }
    #endregion
}
finally
{
    Invoke-TestCleanup
}
