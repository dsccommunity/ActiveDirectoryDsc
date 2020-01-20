$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADForestProperties'

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

        $mockUserName = 'admin@contoso.com'
        $mockPassword = 'P@ssw0rd-12P@ssw0rd-12' | ConvertTo-SecureString -AsPlainText -Force
        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' `
            -ArgumentList @($mockUserName, $mockPassword)
        $mockCimCredential = New-CimCredentialInstance -Credential $mockCredential

        $mockResource = @{
            ForestName                 = 'contoso.com'
            ServicePrincipalNameSuffix = 'test.com'
            UserPrincipalNameSuffix    = 'pester.net'
            TombstoneLifetime          = 180
        }

        $forestDN = 'DC=' + $mockResource.ForestName.replace('.', ',DC=')

        $mockChangedResource = @{
            ServicePrincipalNameSuffix         = 'test.net'
            UserPrincipalNameSuffix            = 'cloudapp.net', 'fabrikam.com'
            TombstoneLifetime                  = 200
            ServicePrincipalNameSuffixToRemove = $mockResource.ServicePrincipalNameSuffix
            ServicePrincipalNameSuffixToAdd    = 'test.net'
            UserPrincipalNameSuffixToRemove    = $mockResource.UserPrincipalNameSuffix
            UserPrincipalNameSuffixToAdd       = 'cloudapp.net', 'fabrikam.com'
        }

        $mockChangedReplaceResource = @{
            ServicePrincipalNameSuffix = $mockChangedResource.ServicePrincipalNameSuffix
            UserPrincipalNameSuffix    = $mockChangedResource.UserPrincipalNameSuffix
            TombstoneLifetime          = $mockChangedResource.TombstoneLifetime
        }

        $mockChangedAddRemoveResource = @{
            ServicePrincipalNameSuffixToRemove = $mockResource.ServicePrincipalNameSuffix
            ServicePrincipalNameSuffixToAdd    = $mockChangedResource.ServicePrincipalNameSuffix
            UserPrincipalNameSuffixToRemove    = $mockResource.UserPrincipalNameSuffix
            UserPrincipalNameSuffixToAdd       = $mockChangedResource.UserPrincipalNameSuffix
        }

        $mockADrootDSE = @{
            configurationNamingContext = "CN=Configuration,$forestDN"
        }

        $mockDirectoryPartition = @{
            tombstonelifetime = $mockResource.TombstoneLifetime
        }

        $mockGetTargetResourceResult = @{
            Credential                         = $mockCimCredential
            ForestName                         = $mockResource.forestName
            ServicePrincipalNameSuffix         = $mockResource.ServicePrincipalNameSuffix
            ServicePrincipalNameSuffixToAdd    = @()
            ServicePrincipalNameSuffixToRemove = @()
            TombstoneLifetime                  = $mockResource.tombstoneLifetime
            UserPrincipalNameSuffix            = $mockResource.UserPrincipalNameSuffix
            UserPrincipalNameSuffixToAdd       = @()
            UserPrincipalNameSuffixToRemove    = @()
        }

        Mock -CommandName Assert-Module
        Mock -CommandName Get-ADRootDSE -MockWith { $mockADRootDSE }

        Describe 'MSFT_ADForestProperties\Get-TargetResource' {

            BeforeAll {
                $getTargetResourceParameters = @{
                    ForestName = $mockResource.ForestName
                }

                $mockGetADForestResult = @{
                    Name        = $mockResource.ForestName
                    SpnSuffixes = $mockResource.ServicePrincipalNameSuffix
                    UpnSuffixes = $mockResource.UserPrincipalNameSuffix
                }

                Mock -CommandName Get-ADForest -MockWith { $mockGetADForestResult }
                Mock -CommandName Get-ADObject -ParameterFilter { $Properties -eq 'tombstonelifetime' } `
                    -MockWith { $mockDirectoryPartition }

                $targetResource = Get-TargetResource @getTargetResourceParameters
            }

            foreach ($property in $mockResource.Keys)
            {
                It "Should return the correct $property property" {
                    $targetResource.$property | Should -Be $mockResource.$property
                }
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Assert-Module `
                    -ParameterFilter { $ModuleName -eq $script:psModuleName } `
                    -Exactly -Times 1

                Assert-MockCalled Get-ADRootDSE `
                    -Exactly -Times 1

                Assert-MockCalled Get-ADObject `
                    -ParameterFilter { $Properties -eq 'tombstonelifetime' } `
                    -Exactly -Times 1
            }

            Context 'When the Credential parameter is specified' {
                $getTargetResourceParameters = @{
                    Credential = $mockCredential
                    ForestName = $mockResource.ForestName
                }

                It 'Should not throw' {
                    { $targetResource = Get-TargetResource @getTargetResourceParameters } | Should -Not -Throw
                }
            }
        }

        Describe 'MSFT_ADForestProperties\Test-TargetResource' {

            BeforeAll {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            Context 'When the target resource is in the desired state' {
                Context 'When using add/remove parameters' {
                    BeforeAll {
                        $testTargetResourceAddRemoveParameters = @{
                            ForestName                         = $mockResource.ForestName
                            ServicePrincipalNameSuffixToRemove = $mockChangedResource.ServicePrincipalNameSuffix
                            ServicePrincipalNameSuffixToAdd    = $mockResource.ServicePrincipalNameSuffix
                            UserPrincipalNameSuffixToRemove    = $mockChangedResource.UserPrincipalNameSuffix
                            UserPrincipalNameSuffixToAdd       = $mockResource.UserPrincipalNameSuffix
                        }
                    }

                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceAddRemoveParameters -Verbose | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq $script:psModuleName } `
                            -Exactly -Times 1

                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $ForestName -eq $testTargetResourceAddRemoveParameters.ForestName } `
                            -Exactly -Times 1
                    }
                }

                Context 'When using replace parameters' {
                    BeforeAll {
                        $testTargetResourceReplaceParameters = @{
                            ForestName                 = $mockResource.ForestName
                            ServicePrincipalNameSuffix = $mockResource.ServicePrincipalNameSuffix
                            UserPrincipalNameSuffix    = $mockResource.UserPrincipalNameSuffix
                            TombstoneLifetime          = $mockResource.TombstoneLifetime
                            Credential                 = $mockCredential
                        }
                    }

                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceReplaceParameters -Verbose | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq $script:psModuleName } `
                            -Exactly -Times 1

                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $ForestName -eq $testTargetResourceAddRemoveParameters.ForestName } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the target resource is not in the desired state' {

                foreach ($property in $mockChangedResource.Keys)
                {
                    Context "When the $property resource property is not in the desired state" {
                        BeforeAll {
                            $testTargetResourceNotInDesiredStateParameters = @{
                                ForestName = $mockResource.forestName
                                Credential = $mockCredential
                            }
                            $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                        }

                        It 'Should return $false' {
                            Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -BeFalse
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Assert-Module `
                                -ParameterFilter { $ModuleName -eq $script:psModuleName } `
                                -Exactly -Times 1

                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $ForestName -eq `
                                    $testTargetResourceNotInDesiredStateParameters.ForestName } `
                                -Exactly -Times 1
                        }
                    }
                }
            }
        }

        Describe 'MSFT_ADForestProperties\Set-TargetResource' {

            BeforeAll {
                $setTargetResourceParameters = @{
                    ForestName = $mockResource.ForestName
                    Credential = $mockCredential
                }

                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
                Mock -CommandName Set-ADForest
                Mock -CommandName Set-ADObject
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When $property has changed" {
                    BeforeAll {
                        $setChangedTargetResourceParametersProperty = $setTargetResourceParameters.Clone()
                        $setChangedTargetResourceParametersProperty.$property = $mockChangedResource.$property
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setChangedTargetResourceParametersProperty } | Should -Not -Throw
                    }

                    It 'Should call the correct mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $ForestName -eq $setChangedTargetResourceParametersProperty.ForestName } `
                            -Exactly -Times 1

                        if ($property -eq 'TombstoneLifeTime')
                        {
                            Assert-MockCalled -CommandName Set-ADForest `
                                -Exactly -Times 0

                            Assert-MockCalled -CommandName Set-ADObject `
                                -Exactly -Times 1
                        }
                        else
                        {
                            Assert-MockCalled -CommandName Set-ADForest `
                                -Exactly -Times 1

                            Assert-MockCalled -CommandName Set-ADObject `
                                -Exactly -Times 0
                        }
                    }
                }
            }

            Context 'When both ServicePrincipalNameSuffixAdd and ServicePrincipalNameSuffixRemove have been specified' {
                BeforeAll {
                    $setChangedTargetResourceParametersProperty = $setTargetResourceParameters.Clone()
                    $setChangedTargetResourceParametersProperty.ServicePrincipalNameSuffixToAdd = `
                        $mockChangedAddRemoveResource.ServicePrincipalNameSuffixToAdd
                    $setChangedTargetResourceParametersProperty.ServicePrincipalNameSuffixToRemove = `
                        $mockChangedAddRemoveResource.ServicePrincipalNameSuffixToRemove
                }

                It 'Should not throw' {
                    { Set-TargetResource @setChangedTargetResourceParametersProperty } | Should -Not -Throw
                }

                It 'Should call the correct mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { $ForestName -eq $setChangedTargetResourceParametersProperty.ForestName } `
                        -Exactly -Times 1

                    Assert-MockCalled -CommandName Set-ADForest  `
                        -Exactly -Times 1
                }
            }

            Context 'When both UserPrincipalNameSuffixAdd and UserPrincipalNameSuffixRemove have been specified' {
                BeforeAll {
                    $setChangedTargetResourceParametersProperty = $setTargetResourceParameters.Clone()
                    $setChangedTargetResourceParametersProperty.UserPrincipalNameSuffixToAdd = `
                        $mockChangedAddRemoveResource.UserPrincipalNameSuffixToAdd
                    $setChangedTargetResourceParametersProperty.UserPrincipalNameSuffixToRemove = `
                        $mockChangedAddRemoveResource.UserPrincipalNameSuffixToRemove
                }

                It 'Should not throw' {
                    { Set-TargetResource @setChangedTargetResourceParametersProperty } | Should -Not -Throw
                }

                It 'Should call the correct mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { $ForestName -eq $setChangedTargetResourceParametersProperty.ForestName } `
                        -Exactly -Times 1

                    Assert-MockCalled -CommandName Set-ADForest  `
                        -Exactly -Times 1
                }
            }

            foreach ($property in $mockChangedReplaceResource.Keys)
            {
                Context "When $property has changed to an empty value" {
                    BeforeAll {
                        $setChangedTargetResourceParametersProperty = $setTargetResourceParameters.Clone()
                        $setChangedTargetResourceParametersProperty.$property = ''
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setChangedTargetResourceParametersProperty } | Should -Not -Throw
                    }

                    It 'Should call the correct mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $ForestName -eq $setChangedTargetResourceParametersProperty.ForestName } `
                            -Exactly -Times 1

                        if ($property -eq 'TombstoneLifeTime')
                        {
                            Assert-MockCalled -CommandName Set-ADForest `
                                -Exactly -Times 0

                            Assert-MockCalled -CommandName Set-ADObject `
                                -Exactly -Times 1
                        }
                        else
                        {
                            Assert-MockCalled -CommandName Set-ADForest `
                                -Exactly -Times 1

                            Assert-MockCalled -CommandName Set-ADObject `
                                -Exactly -Times 0
                        }
                    }
                }
            }

            Context 'When Set-ADObject throws an exception' {
                BeforeAll {
                    $setTargetResourceTombstoneParameters = @{
                        ForestName        = $mockResource.ForestName
                        TombstoneLifetime = $mockChangedResource.TombstoneLifetime
                        Credential        = $mockCredential
                    }
                    Mock -CommandName Set-ADObject -MockWith { throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceTombstoneParameters } | Should -Throw (
                        $script:localizedData.SetTombstoneLifetimeError -f
                        $setTargetResourceTombstoneParameters.TombstoneLifetime,
                        $setTargetResourceTombstoneParameters.ForestName )
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
