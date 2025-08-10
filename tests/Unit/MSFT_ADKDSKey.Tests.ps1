# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
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
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
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
    $script:dscResourceName = 'MSFT_ADKDSKey'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    # Load stub cmdlets and classes.
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1')
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\Kds.psm1')

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
    Remove-Module -Name Kds -Force

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_ADKDSKey\Assert-HasDomainAdminRights' -Tag 'Helper' {
    Context 'When Assert-HasDomainAdminRights returns true' {
        Context 'When the user has proper permissions' {
            BeforeAll {
                Mock -CommandName New-Object -MockWith {
                    $object = New-MockObject -Type 'System.Security.Principal.WindowsPrincipal'
                    $object | Add-Member -MemberType ScriptMethod -Name 'IsInRole' -Force -Value { return $true }
                    return $object
                }

                Mock -CommandName Get-CimInstance -MockWith {
                    @{
                        ProductType = 0
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                    Assert-HasDomainAdminRights -User $currentUser | Should -BeTrue
                }

                Should -Invoke -CommandName New-Object -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the resource is run on a domain controller' {
            BeforeAll {
                Mock -CommandName New-Object -MockWith {
                    $object = New-MockObject -Type 'System.Security.Principal.WindowsPrincipal'
                    $object | Add-Member -MemberType ScriptMethod -Name 'IsInRole' -Force -Value { return $false }
                    return $object
                }

                Mock -CommandName Get-CimInstance -MockWith {
                    @{
                        ProductType = 2
                    }
                }
            }

            It 'Should call the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                    Assert-HasDomainAdminRights -User $currentUser | Should -BeTrue
                }

                Should -Invoke -CommandName New-Object -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When Assert-HasDomainAdminRights returns false' {
        Context 'When the user does NOT have proper permissions' {
            BeforeAll {
                Mock -CommandName New-Object -MockWith {
                    $object = New-MockObject -Type 'System.Security.Principal.WindowsPrincipal'
                    $object | Add-Member -MemberType ScriptMethod -Name 'IsInRole' -Force -Value { return $false }
                    return $object
                }

                Mock -CommandName Get-CimInstance -MockWith {
                    @{
                        ProductType = 0
                    }
                }
            }

            It "Should Call 'New-Object' and 'Get-CimInstance'" {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                    Assert-HasDomainAdminRights -User $currentUser | Should -BeFalse
                }

                Should -Invoke -CommandName New-Object -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the resource is NOT run on a domain controller' {
            BeforeAll {
                Mock -CommandName New-Object -MockWith {
                    $object = New-MockObject -Type 'System.Security.Principal.WindowsPrincipal'
                    $object | Add-Member -MemberType ScriptMethod -Name 'IsInRole' -Force -Value { return $false }
                    return $object
                }

                Mock -CommandName Get-CimInstance -MockWith {
                    @{
                        ProductType = 0
                    }
                }
            }

            It 'Should the correct mocks' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                    Assert-HasDomainAdminRights -User $currentUser | Should -BeFalse
                }

                Should -Invoke -CommandName New-Object -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-CimInstance -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADKDSKey\Get-ADRootDomainDN' -Tag 'Helper' {
    BeforeAll {
        Mock -CommandName New-Object -MockWith {
            $object = [PSCustomObject] @{ }
            $object | Add-Member -MemberType ScriptMethod -Name 'Get' -Value { return 'OU=Fake,DC=contoso,DC=com' }

            return $object
        }
    }

    It 'Should return domain distinguished name' {
        InModuleScope -ScriptBlock {
            Set-StrictMode -Version 1.0

            Get-ADRootDomainDN | Should -Be 'OU=Fake,DC=contoso,DC=com'
        }
    }
}

Describe 'MSFT_ADKDSKey\Get-TargetResource' -Tag 'Get' {
    BeforeAll {
        Mock -CommandName Assert-Module -ParameterFilter {
            $ModuleName -eq 'ActiveDirectory'
        }

        Mock -CommandName Get-ADRootDomainDN -MockWith {
            return 'OU=Fake,DC=contoso,DC=com'
        }

        Mock -CommandName Assert-HasDomainAdminRights -MockWith {
            return $true
        }

        Mock -CommandName Get-KdsRootKey
    }

    Context 'When the system uses specific parameters' {
        It 'Should call the expected mocks' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                }

                { Get-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Assert-Module -Exactly -Times 1 -Scope It
        }
    }

    Context "When 'EffectiveTime' is not parsable by DateTime" {
        It 'Should throw the correct error' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = 'Useless Time'
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.EffectiveTimeInvalid -f
                    $mockParameters.EffectiveTime)

                { Get-TargetResource  @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }

            Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 0 -Scope It
        }
    }

    Context 'When the Current User does not have proper permissions' {
        BeforeAll {
            Mock -CommandName Assert-HasDomainAdminRights -MockWith { return $false }
        }

        It 'Should throw the correct error' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                }

                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                $errorRecord = Get-InvalidResultRecord -Message ($script:localizedData.IncorrectPermissions -f
                    $currentUser.Name)

                { Get-TargetResource  @mockParameters } | Should -Throw -ExpectedMessage $errorRecord
            }

            Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 0 -Scope It
        }
    }

    Context "When 'Get-KdsRootKey' throws an error" {
        BeforeAll {
            Mock -CommandName Get-KdsRootKey -MockWith {
                throw 'Microsoft.ActiveDirectory.Management.ADServerDownException'
            }
        }

        It 'Should throw the correct error' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.RetrievingKDSRootKeyError -f
                    $mockParameters.EffectiveTime)

                { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }

            Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is in desired state' {
        BeforeAll {
            $script:mockKDSRootKeyFuture = [PSCustomObject] @{
                AttributeOfWrongFormat = $null
                KeyValue               = $null #Byte[], not currently needed
                EffectiveTime          = [DateTime]::Parse('1/1/3000 13:00')
                CreationTime           = [DateTime]::Parse('1/1/3000 08:00')
                IsFormatValid          = $true
                DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                ServerConfiguration    = [PSCustomObject] @{
                    AttributeOfWrongFormat          = $null
                    KdfParameters                   = $null #Byte[], not currently needed
                    SecretAgreementParameters       = $null #Byte[], not currently needed
                    IsValidFormat                   = $true
                    SecretAgreementAlgorithm        = 'DH'
                    KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                    SecretAgreementPublicKeyLength  = 2048
                    SecretAgreementPrivateKeyLength = 512
                    VersionNumber                   = 1
                }
                KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                VersionNumber          = 1
            }

            Mock -CommandName Get-KdsRootKey -MockWith {
                return , @($mockKDSRootKeyFuture)
            }
        }

        It 'Should return the correct result' {
            InModuleScope -Parameters @{
                mockKDSRootKeyFuture = $script:mockKDSRootKeyFuture
            } -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                }

                $dn = ('CN={0},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{1}' -f
                    $mockKDSRootKeyFuture.KeyId, 'OU=Fake,DC=contoso,DC=com')

                $result = Get-TargetResource @mockParameters

                # TODO: Should this not match the mockParameters.EffectiveTime?
                $result.EffectiveTime | Should -Be $mockKDSRootKeyFuture.EffectiveTime
                $result.CreationTime | Should -Be $mockKDSRootKeyFuture.CreationTime
                $result.KeyId | Should -Be $mockKDSRootKeyFuture.KeyId
                $result.DistinguishedName | Should -Be $dn
                $result.Ensure | Should -Be 'Present'
            }

            Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
        }

        Context 'When system has two or more KDS keys with the same effective date' {
            BeforeAll {
                $mockKDSRootKeyFuture = [PSCustomObject] @{
                    AttributeOfWrongFormat = $null
                    KeyValue               = $null #Byte[], not currently needed
                    EffectiveTime          = [DateTime]::Parse('1/1/3000 13:00')
                    CreationTime           = [DateTime]::Parse('1/1/3000 08:00')
                    IsFormatValid          = $true
                    DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                    ServerConfiguration    = [PSCustomObject] @{
                        AttributeOfWrongFormat          = $null
                        KdfParameters                   = $null #Byte[], not currently needed
                        SecretAgreementParameters       = $null #Byte[], not currently needed
                        IsValidFormat                   = $true
                        SecretAgreementAlgorithm        = 'DH'
                        KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                        SecretAgreementPublicKeyLength  = 2048
                        SecretAgreementPrivateKeyLength = 512
                        VersionNumber                   = 1
                    }
                    KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                    VersionNumber          = 1
                }

                Mock -CommandName Write-Warning
                Mock -CommandName Get-KdsRootKey -MockWith {
                    return @($mockKDSRootKeyFuture, $mockKDSRootKeyFuture)
                }
            }

            It 'Should return Warning that more than one key exists and Error that two keys exist with the same dates' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.FoundKDSRootKeySameEffectiveTime -f
                        $mockParameters.EffectiveTime)

                    { Get-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord
                }

                Should -Invoke -CommandName Write-Warning -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is NOT in the desired state' {
        Context 'When no KDS root keys exists' {
            BeforeAll {
                Mock -CommandName Get-KdsRootKey -MockWith {
                    return $null
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    }

                    $result = Get-TargetResource @mockParameters

                    $result.Ensure | Should -Be 'Absent'
                }

                Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
            }
        }

        Context 'When the KDS root key does not exist' {
            BeforeAll {
                $mockKDSRootKeyPast = [PSCustomObject] @{
                    AttributeOfWrongFormat = $null
                    KeyValue               = $null #Byte[], not currently needed
                    EffectiveTime          = [DateTime]::Parse('1/1/2000 13:00')
                    CreationTime           = [DateTime]::Parse('1/1/2000 08:00')
                    IsFormatValid          = $true
                    DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                    ServerConfiguration    = [PSCustomObject] @{
                        AttributeOfWrongFormat          = $null
                        KdfParameters                   = $null #Byte[], not currently needed
                        SecretAgreementParameters       = $null #Byte[], not currently needed
                        IsValidFormat                   = $true
                        SecretAgreementAlgorithm        = 'DH'
                        KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                        SecretAgreementPublicKeyLength  = 2048
                        SecretAgreementPrivateKeyLength = 512
                        VersionNumber                   = 1
                    }
                    KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                    VersionNumber          = 1
                }

                Mock -CommandName Get-KdsRootKey -MockWith {
                    return , @($mockKDSRootKeyPast)
                }
            }

            It 'Should return the correct result' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    }

                    $result = Get-TargetResource @mockParameters
                    $result.Ensure | Should -Be 'Absent'
                }

                Should -Invoke -CommandName Assert-HasDomainAdminRights -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
            }
        }
    }
}

Describe 'MSFT_ADKDSKey\Compare-TargetResourceState' -Tag 'Compare' {
    Context 'When the system is in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    EffectiveTime     = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    CreationTime      = ([DateTime]::Parse('1/1/3000 08:00'))
                    KeyId             = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                    Ensure            = 'Present'
                    DistinguishedName = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        BeforeDiscovery {
            $testCases = @(
                @{ Parameter = 'EffectiveTime' }
                @{ Parameter = 'Ensure' }
                @{ Parameter = 'DistinguishedName' }
            )
        }

        It 'Should return identical information for <Parameter>' -TestCases $testCases {
            InModuleScope -Parameters $_ -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    Ensure        = 'Present'
                }

                $result = Compare-TargetResourceState @mockParameters

                $filteredResult = $result | Where-Object -FilterScript { $_.Parameter -eq $Parameter }

                $filteredResult.Expected | Should -BeExactly $filteredResult.Actual
                $filteredResult.Pass | Should -BeTrue
            }
        }
    }

    Context 'When the system is NOT in the desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    EffectiveTime     = ([DateTime]::Parse('1/1/2000 13:00')).ToString()
                    CreationTime      = ([DateTime]::Parse('1/1/3000 08:00'))
                    KeyId             = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                    Ensure            = 'Present'
                    DistinguishedName = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                }
            }
        }

        BeforeDiscovery {
            $testCases = @(
                @{ Parameter = 'EffectiveTime' }
                @{ Parameter = 'Ensure' }
            )
        }

        It 'Should return false for <Parameter>' -TestCases $testCases {
            InModuleScope -Parameters $_ -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    Ensure        = 'Absent'
                }

                $result = Compare-TargetResourceState @mockParameters

                $filteredResult = $result | Where-Object -FilterScript { $_.Parameter -eq $Parameter }

                $filteredResult.Expected | Should -Not -Be $filteredResult.Actual
                $filteredResult.Pass | Should -BeFalse
            }
        }
    }
}

Describe 'MSFT_ADKDSKey\Test-TargetResource' -Tag 'Test' {
    Context "When the system is in the desired state and 'Ensure' is 'Present'" {
        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                return @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Present'
                        Actual    = 'Present'
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        It 'Should pass when the Parameters are properly set' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                }

                Test-TargetResource @mockParameters | Should -BeTrue
            }

            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
            } -Exactly -Times 1 -Scope It
        }
    }

    Context "When the system is in the desired state and 'Ensure' is 'Absent'" {
        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Present'
                        Actual    = 'Present'
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        It 'Should return the correct result' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    Ensure        = 'Absent'
                }

                Test-TargetResource @mockParameters | Should -BeTrue
            }

            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
            } -Exactly -Times 1 -Scope It
        }
    }

    Context "When the system is NOT in the desired state and 'Ensure' is 'Absent'" {
        BeforeDiscovery {
            $testCases = @(
                @{
                    Parameter = 'Ensure'
                    Value     = 'Absent'
                }
            )
        }

        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Absent'
                        Actual    = 'Present'
                        Pass      = $false
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        It 'Should return ''$false'' when <Parameter> is incorrect' -TestCases $testCases {
            InModuleScope -Parameters $_ -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    Ensure        = 'Present'
                }

                $mockParameters.$Parameter = $Value
                Test-TargetResource @mockParameters | Should -BeFalse
            }

            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
            } -Exactly -Times 1 -Scope It
        }
    }
}

Describe 'MSFT_ADKDSKey\Set-TargetResource' -Tag 'Set' {
    BeforeAll {
        Mock -CommandName Add-KDSRootKey
        Mock -CommandName Remove-ADObject
        Mock -CommandName Write-Warning
    }

    Context 'When the system is in the desired state and KDS Root Key is Present' {
        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Present'
                        Actual    = 'Present'
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        It 'Should NOT take any action when all parameters are correct' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Remove-ADObject -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Write-Warning -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is in the desired state and KDS Root Key is Absent' {
        BeforeAll {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Absent'
                        Actual    = 'Present'
                        Pass      = $false
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        It 'Should NOT take any action when all parameters are correct' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    Ensure        = 'Present'
                }

                { Set-TargetResource @mockParameters } | Should -Not -Throw
            }

            Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Remove-ADObject -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Write-Warning -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
            } -Exactly -Times 1 -Scope It
        }
    }

    Context 'When the system is NOT in the desired state and need to remove KDS Root Key' {
        BeforeEach {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Present'
                        Actual    = 'Present'
                        Pass      = $false
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        Context 'When more than one KDS root key exists' {
            BeforeAll {
                Mock -CommandName Get-KdsRootKey -MockWith {
                    return @(
                        [PSCustomObject] @{
                            AttributeOfWrongFormat = $null
                            KeyValue               = $null #Byte[], not currently needed
                            EffectiveTime          = [DateTime]::Parse('1/1/3000 13:00')
                            CreationTime           = [DateTime]::Parse('1/1/3000 08:00')
                            IsFormatValid          = $true
                            DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                            ServerConfiguration    = [PSCustomObject] @{
                                AttributeOfWrongFormat          = $null
                                KdfParameters                   = $null #Byte[], not currently needed
                                SecretAgreementParameters       = $null #Byte[], not currently needed
                                IsValidFormat                   = $true
                                SecretAgreementAlgorithm        = 'DH'
                                KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                                SecretAgreementPublicKeyLength  = 2048
                                SecretAgreementPrivateKeyLength = 512
                                VersionNumber                   = 1
                            }
                            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                            VersionNumber          = 1
                        },
                        [PSCustomObject] @{
                            AttributeOfWrongFormat = $null
                            KeyValue               = $null #Byte[], not currently needed
                            EffectiveTime          = [DateTime]::Parse('1/1/2000 13:00')
                            CreationTime           = [DateTime]::Parse('1/1/2000 08:00')
                            IsFormatValid          = $true
                            DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                            ServerConfiguration    = [PSCustomObject] @{
                                AttributeOfWrongFormat          = $null
                                KdfParameters                   = $null #Byte[], not currently needed
                                SecretAgreementParameters       = $null #Byte[], not currently needed
                                IsValidFormat                   = $true
                                SecretAgreementAlgorithm        = 'DH'
                                KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                                SecretAgreementPublicKeyLength  = 2048
                                SecretAgreementPrivateKeyLength = 512
                                VersionNumber                   = 1
                            }
                            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                            VersionNumber          = 1
                        }
                    )
                }
            }

            It "Should call 'Remove-ADObject' when 'Ensure' is set to 'Present'" {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Ensure        = 'Absent'
                    }

                    Set-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Write-Warning -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                    ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When only one KDS root key exists' {
            BeforeAll {
                Mock -CommandName Get-KdsRootKey -MockWith {
                    return , @(
                        [PSCustomObject] @{
                            AttributeOfWrongFormat = $null
                            KeyValue               = $null #Byte[], not currently needed
                            EffectiveTime          = [DateTime]::Parse('1/1/3000 13:00')
                            CreationTime           = [DateTime]::Parse('1/1/3000 08:00')
                            IsFormatValid          = $true
                            DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                            ServerConfiguration    = [PSCustomObject] @{
                                AttributeOfWrongFormat          = $null
                                KdfParameters                   = $null #Byte[], not currently needed
                                SecretAgreementParameters       = $null #Byte[], not currently needed
                                IsValidFormat                   = $true
                                SecretAgreementAlgorithm        = 'DH'
                                KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                                SecretAgreementPublicKeyLength  = 2048
                                SecretAgreementPrivateKeyLength = 512
                                VersionNumber                   = 1
                            }
                            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                            VersionNumber          = 1
                        }
                    )
                }
            }

            It "Should call NOT 'Remove-ADObject' when 'Ensure' is set to 'Present' and 'ForceRemove' is 'False'" {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Ensure        = 'Absent'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.NotEnoughKDSRootKeysPresentNoForce -f
                        $mockParameters.EffectiveTime)

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord
                }

                Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADObject -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Write-Warning -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                    ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
                } -Exactly -Times 1 -Scope It
            }


            It "Should call 'Remove-ADObject' when 'Ensure' is set to 'Present' and 'ForceRemove' is 'True'" {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Ensure        = 'Absent'
                        ForceRemove   = $true
                    }

                    Set-TargetResource @mockParameters
                }

                Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 0 -Scope It
                Should -Invoke -CommandName Remove-ADObject -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Write-Warning -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-KdsRootKey -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                    ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When calling Remove-ADObject fails' {
            BeforeAll {
                Mock -CommandName Get-KdsRootKey -MockWith {
                    @(
                        [PSCustomObject] @{
                            AttributeOfWrongFormat = $null
                            KeyValue               = $null #Byte[], not currently needed
                            EffectiveTime          = [DateTime]::Parse('1/1/3000 13:00')
                            CreationTime           = [DateTime]::Parse('1/1/3000 08:00')
                            IsFormatValid          = $true
                            DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                            ServerConfiguration    = [PSCustomObject] @{
                                AttributeOfWrongFormat          = $null
                                KdfParameters                   = $null #Byte[], not currently needed
                                SecretAgreementParameters       = $null #Byte[], not currently needed
                                IsValidFormat                   = $true
                                SecretAgreementAlgorithm        = 'DH'
                                KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                                SecretAgreementPublicKeyLength  = 2048
                                SecretAgreementPrivateKeyLength = 512
                                VersionNumber                   = 1
                            }
                            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                            VersionNumber          = 1
                        },
                        [PSCustomObject] @{
                            AttributeOfWrongFormat = $null
                            KeyValue               = $null #Byte[], not currently needed
                            EffectiveTime          = [DateTime]::Parse('1/1/2000 13:00')
                            CreationTime           = [DateTime]::Parse('1/1/2000 08:00')
                            IsFormatValid          = $true
                            DomainController       = 'CN=MockDC,OU=Fake,DC=contoso,DC=com'
                            ServerConfiguration    = [PSCustomObject] @{
                                AttributeOfWrongFormat          = $null
                                KdfParameters                   = $null #Byte[], not currently needed
                                SecretAgreementParameters       = $null #Byte[], not currently needed
                                IsValidFormat                   = $true
                                SecretAgreementAlgorithm        = 'DH'
                                KdfAlgorithm                    = 'SP800_108_CTR_HMAC'
                                SecretAgreementPublicKeyLength  = 2048
                                SecretAgreementPrivateKeyLength = 512
                                VersionNumber                   = 1
                            }
                            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
                            VersionNumber          = 1
                        }
                    )
                }

                Mock -CommandName Remove-ADObject -MockWith {
                    throw 'Microsoft.ActiveDirectory.Management.ADServerDownException'
                }
            }

            It "Should call 'Remove-ADObject' and throw an error when catching any errors" {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Ensure        = 'Absent'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.KDSRootKeyRemoveError -f
                        $mockParameters.EffectiveTime)

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Remove-ADObject -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When the system is NOT in the desired state and need to add KDS Root Key' {
        BeforeEach {
            Mock -CommandName Compare-TargetResourceState -MockWith {
                @(
                    [PSCustomObject] @{
                        Parameter = 'EffectiveTime'
                        Expected  = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Actual    = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Pass      = $true
                    }
                    [PSCustomObject] @{
                        Parameter = 'Ensure'
                        Expected  = 'Present'
                        Actual    = 'Absent'
                        Pass      = $false
                    }
                    [PSCustomObject] @{
                        Parameter = 'DistinguishedName'
                        Expected  = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Actual    = 'CN=92051014-f6c5-4a09-8f7a-f747728d1b9a,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,OU=Fake,DC=contoso,DC=com'
                        Pass      = $true
                    }
                )
            }
        }

        It "Should call 'Add-KDSRootKey' when 'Ensure' is set to 'Present'" {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                    Ensure        = 'Present'
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Remove-ADObject -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Write-Warning -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/3000 13:00')) -eq $EffectiveTime
            } -Exactly -Times 1 -Scope It
        }

        It "Should NOT call 'Add-KDSRootKey' when 'EffectiveTime' is past date and 'AllowUnsafeEffectiveTime' is 'False'" {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = ([DateTime]::Parse('1/1/2000 13:00')).ToString()
                    Ensure        = 'Present'
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.AddingKDSRootKeyError -f
                    $mockParameters.EffectiveTime)

                { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage $errorRecord
            }

            Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Remove-ADObject -Exactly -Times 0 -Scope It
-            Should -Invoke -CommandName Write-Warning -Exactly -Times 0
+            Should -Invoke -CommandName Write-Warning -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/2000 13:00'))
            } -Exactly -Times 1 -Scope It
        }

        It "Should call 'Add-KDSRootKey' when 'EffectiveTime' is past date and 'AllowUnsafeEffectiveTime' is 'True'" {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime            = ([DateTime]::Parse('1/1/2000 13:00')).ToString()
                    Ensure                   = 'Present'
                    AllowUnsafeEffectiveTime = $true
                }

                Set-TargetResource @mockParameters
            }

            Should -Invoke -CommandName Add-KDSRootKey -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Remove-ADObject -Exactly -Times 0 -Scope It
            Should -Invoke -CommandName Write-Warning -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                ([DateTime]::Parse('1/1/2000 13:00'))
            } -Exactly -Times 1 -Scope It
        }

        It 'Should call throw an error if EffectiveTime cannot be parsed' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $mockParameters = @{
                    EffectiveTime = 'Useless Time'
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.EffectiveTimeInvalid -f
                    $mockParameters.EffectiveTime)

                { Set-TargetResource  @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }

            Should -Invoke -CommandName Compare-TargetResourceState -ParameterFilter {
                [DateTime]::Parse('1/1/3000 13:00')
            } -Exactly -Times 1 -Scope It
        }

        Context 'When calling Add-KDSRootKey fails' {
            BeforeAll {
                Mock -CommandName Add-KDSRootKey -MockWith {
                    throw 'Microsoft.ActiveDirectory.Management.ADServerDownException'
                }
            }

            It "Should call 'Add-KdsRootKey' and throw an error when catching any errors" {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $mockParameters = @{
                        EffectiveTime = ([DateTime]::Parse('1/1/3000 13:00')).ToString()
                        Ensure        = 'Present'
                    }

                    $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.KDSRootKeyAddError -f
                        $mockParameters.EffectiveTime)

                    { Set-TargetResource @mockParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }

                Should -Invoke -CommandName Add-KdsRootKey -Exactly -Times 1 -Scope It
            }
        }
    }
}
