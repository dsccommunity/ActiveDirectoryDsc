[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]

#region HEADER
$script:DSCModuleName      = 'xActiveDirectory'
$script:DSCResourceName    = 'MSFT_xADKDSKey'

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment  `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit
#endregion HEADER

function Invoke-TestSetup
{
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}


# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope $script:DSCResourceName {
        # Need to do a deep copy of the Array of objects that compare returns
        function Copy-ArrayObjects
        {
            param(
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [System.Array]
                $DeepCopyObject
            )

            $memStream = New-Object IO.MemoryStream
            $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter
            $formatter.Serialize($memStream,$DeepCopyObject)
            $memStream.Position = 0
            $formatter.Deserialize($memStream)
        }

        $mockADDomain = 'OU=Fake,DC=contoso,DC=com'

        $mockKDSServerConfiguration = [pscustomobject] @{
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

        $mockKDSRootKeyFuture = [pscustomobject] @{
            AttributeOfWrongFormat = $null
            KeyValue               = $null #Byte[], not currently needed
            EffectiveTime          = [DateTime]::Parse('1/1/3000 13:00')
            CreationTime           = [DateTime]::Parse('1/1/3000 08:00')
            IsFormatValid          = $true
            DomainController       = 'CN=MockDC,{0}' -f $mockADDomain
            ServerConfiguration    = $mockKDSServerConfiguration
            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
            VersionNumber          = 1
        }

        $mockKDSRootKeyPast = [pscustomobject] @{
            AttributeOfWrongFormat = $null
            KeyValue               = $null #Byte[], not currently needed
            EffectiveTime          = [DateTime]::Parse('1/1/2000 13:00')
            CreationTime           = [DateTime]::Parse('1/1/2000 08:00')
            IsFormatValid          = $true
            DomainController       = 'CN=MockDC,{0}' -f $mockADDomain
            ServerConfiguration    = $mockKDSServerConfiguration
            KeyId                  = '92051014-f6c5-4a09-8f7a-f747728d1b9a'
            VersionNumber          = 1
        }

        $mockKDSRootKeyFutureGet = @{
            EffectiveTime     = $mockKDSRootKeyFuture.EffectiveTime
            CreationTime      = $mockKDSRootKeyFuture.CreationTime
            KeyId             = $mockKDSRootKeyFuture.KeyId
            Ensure            = 'Present'
            DistinguishedName = 'CN={0},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{1}' -f
                                    $mockKDSRootKeyFuture.KeyId, $mockADDomain
        }

        $mockKDSRootKeyPastGet = @{
            EffectiveTime     = $mockKDSRootKeyPast.EffectiveTime
            CreationTime      = $mockKDSRootKeyPast.CreationTime
            KeyId             = $mockKDSRootKeyPast.KeyId
            Ensure            = 'Present'
            DistinguishedName = 'CN={0},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{1}' -f
                                    $mockKDSRootKeyPast.KeyId, $mockADDomain
        }

        $mockKDSRootKeyFutureCompare = @(
            [pscustomobject] @{
                Parameter = 'EffectiveTime'
                Expected  = $mockKDSRootKeyFutureGet.EffectiveTime
                Actual    = $mockKDSRootKeyFutureGet.EffectiveTime
                Pass      = $true
            }
            [pscustomobject] @{
                Parameter = 'Ensure'
                Expected  = $mockKDSRootKeyFutureGet.Ensure
                Actual    = $mockKDSRootKeyFutureGet.Ensure
                Pass      = $true
            }
            [pscustomobject] @{
                Parameter = 'DistinguishedName'
                Expected  = $mockKDSRootKeyFutureGet.DistinguishedName
                Actual    = $mockKDSRootKeyFutureGet.DistinguishedName
                Pass      = $true
            }
        )

        $mockKDSRootKeyPastCompare = @(
            [pscustomobject] @{
                Parameter = 'EffectiveTime'
                Expected  = $mockKDSRootKeyPastGet.EffectiveTime
                Actual    = $mockKDSRootKeyPastGet.EffectiveTime
                Pass      = $true
            }
            [pscustomobject] @{
                Parameter = 'Ensure'
                Expected  = $mockKDSRootKeyPastGet.Ensure
                Actual    = $mockKDSRootKeyPastGet.Ensure
                Pass      = $true
            }
            [pscustomobject] @{
                Parameter = 'DistinguishedName'
                Expected  = $mockKDSRootKeyPastGet.DistinguishedName
                Actual    = $mockKDSRootKeyPastGet.DistinguishedName
                Pass      = $true
            }
        )

        #region Function Get-TargetResource
        Describe -Name 'MSFT_xADKDSKey\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                Mock -CommandName Assert-Module -ParameterFilter {
                    $ModuleName -eq 'ActiveDirectory'
                }

                Mock -CommandName Get-ADRootDomainDN -MockWith {
                    return $mockADDomain
                }

                Mock -CommandName Assert-HasDomainAdminRights -MockWith { return $true }
            }

            Context -Name 'When the system uses specific parameters' {
                Mock -CommandName Get-KdsRootKey

                It 'Should call "Assert-Module" to check AD module is installed' {
                    $getTargetResourceParameters = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                    }

                    { Get-TargetResource @getTargetResourceParameters } | Should -Not -Throw

                    Assert-MockCalled -CommandName Assert-Module -Scope It -Exactly -Times 1
                }
            }

            Context -Name 'When system cannot connect to domain or other errors' {
                Mock -CommandName Get-KdsRootKey -MockWith {
                    throw 'Microsoft.ActiveDirectory.Management.ADServerDownException'
                }

                It "Should call 'Get-KdsRootKey' and throw an error when catching any errors" {
                    $getTargetResourceParameters = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                    }

                    { $null = Get-TargetResource  @getTargetResourceParameters -ErrorAction 'SilentlyContinue' } | Should -Throw
                }
            }

            Context -Name 'When the system is in desired state' {
                Mock -CommandName Get-KdsRootKey -ParameterFilter {
                    $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                } -MockWith {
                    Write-Verbose "Call Get-KdsRootKey with effective time of: $($mockKDSRootKeyFuture.EffectiveTime)"
                    return ,@($mockKDSRootKeyFuture)
                }

                It 'Should mock call to Get-KdsRootKey and return identical information' {
                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                    }

                    $getTargetResourceResult = Get-TargetResource @getTargetResourceParametersFuture

                    $getTargetResourceResult.EffectiveTime | Should -Be $mockKDSRootKeyFuture.EffectiveTime
                    $getTargetResourceResult.CreationTime | Should -Be $mockKDSRootKeyFuture.CreationTime
                    $getTargetResourceResult.KeyId | Should -Be $mockKDSRootKeyFuture.KeyId
                    $getTargetResourceResult.Ensure | Should -Be 'Present'

                    $dn = 'CN={0},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{1}' -f
                                $mockKDSRootKeyFuture.KeyId, $mockADDomain

                    $getTargetResourceResult.DistinguishedName | Should -Be $dn
                }

                Context -Name 'When system has two or more KDS keys with the same effective date' {
                    Mock -CommandName Write-Warning

                    Mock -CommandName Get-KdsRootKey -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Call Get-KdsRootKey with effective time of: $($mockKDSRootKeyFuture.EffectiveTime)"
                        return @($mockKDSRootKeyFuture,$mockKDSRootKeyFuture)
                    }

                    It 'Should return Warning that more than one key exists and Error that two keys exist with the same dates' {
                        $getTargetResourceParameters = @{
                            EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        }

                        { $null = Get-TargetResource @getTargetResourceParameters -ErrorAction 'SilentlyContinue' } | Should -Throw

                        Assert-MockCalled -CommandName Write-Warning -Scope It -Times 1
                    }
                }
            }

            Context -Name 'When the system is NOT in the desired state' {
                Context -Name 'When no KDS root keys exists' {
                    Mock -CommandName Get-KdsRootKey -MockWith {
                        Write-Verbose "Call Get-KdsRootKey with and no keys exist"
                        return $null
                    }

                    It "Should return 'Ensure' is 'Absent'" {
                        $getTargetResourceParametersFuture = @{
                            EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        }

                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParametersFuture

                        $getTargetResourceResult.Ensure | Should Be 'Absent'
                    }
                }

                Context -Name 'When the KDS root key does not exist' {
                    Mock -CommandName Get-KdsRootKey -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Call Get-KdsRootKey with effective time of: $($mockKDSRootKeyFuture.EffectiveTime)"
                        return ,@($mockKDSRootKeyPast)
                    }

                    It "Should return 'Ensure' is 'Absent'" {
                        $getTargetResourceParametersFuture = @{
                            EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        }

                        $getTargetResourceResult = Get-TargetResource @getTargetResourceParametersFuture

                        $getTargetResourceResult.Ensure | Should Be 'Absent'
                    }

                }
            }

        }
        #endregion Function Get-TargetResource

        #region Function Compare-TargetResourceState
        Describe -Name 'MSFT_xADKDSKey\Compare-TargetResourceState' -Tag 'Compare' {
            BeforeAll {
                Mock -CommandName Get-TargetResource -ParameterFilter {
                    $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                } -MockWith {
                    Write-Verbose "Calling Get-TargetResource with $($mockKDSRootKeyFuture.EffectiveTime)"
                    return $mockKDSRootKeyFutureGet
                }
            }

            Context -Name 'When the system is in the desired state' {
                $getTargetResourceParametersFuture = @{
                    EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                }

                $getTargetResourceResult = Compare-TargetResourceState @getTargetResourceParametersFuture
                $testCases = @()
                $getTargetResourceResult | ForEach-Object {
                    $testCases += @{
                        Parameter = $_.Parameter
                        Expected  = $_.Expected
                        Actual    = $_.Actual
                        Pass      = $_.Pass
                    }
                }

                It "Should return identical information for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Expected,

                        [Parameter()]
                        $Actual,

                        [Parameter()]
                        $Pass
                    )

                    $Expected | Should -BeExactly $Actual
                    $Pass | Should -BeTrue
                }
            }

            Context -Name 'When the system is NOT in the desired state' {
                $getTargetResourceParametersFuture = @{
                    EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                    Ensure        = 'Absent'
                }

                $getTargetResourceResult = Compare-TargetResourceState @getTargetResourceParametersFuture
                $testCases = @()
                # Need to remove parameters that will always be true
                $getTargetResourceResult = $getTargetResourceResult | Where-Object {
                    $_.Parameter -ne 'EffectiveTime' -and
                    $_.Parameter -ne 'DistinguishedName'
                }

                $getTargetResourceResult | ForEach-Object {
                    $testCases += @{
                        Parameter = $_.Parameter
                        Expected  = $_.Expected
                        Actual    = $_.Actual
                        Pass      = $_.Pass
                    }
                }

                It "Should return false for <Parameter>" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Expected,

                        [Parameter()]
                        $Actual,

                        [Parameter()]
                        $Pass
                    )

                    $Expected | Should -Not -Be $Actual
                    $Pass | Should -BeFalse
                }

            }
        }
        #endregion Function Compare-TargetResourceState

        #region Function Test-TargetResource
        Describe -Name 'MSFT_xADKDSKey\Test-TargetResource' -Tag 'Test' {
            Context -Name "When the system is in the desired state and 'Ensure' is 'Present'" {
                It "Should pass when the Parameters are properly set" {
                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompare
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                    }

                    Test-TargetResource @getTargetResourceParametersFuture | Should -Be $true
                }
            }

            Context -Name "When the system is in the desired state and 'Ensure' is 'Absent'" {
                It "Should pass when 'Ensure' is set to 'Absent" {
                    $mockKDSRootKeyFutureCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyFutureCompare
                    $objectEnsure = $mockKDSRootKeyFutureCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                    $objectEnsure.Actual = 'Absent'
                    $objectEnsure.Pass = $true

                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompareEnsureAbsent
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure        = 'Absent'
                    }

                    Test-TargetResource @getTargetResourceParametersFuture | Should -Be $true
                }
            }

            Context -Name "When the system is NOT in the desired state and 'Ensure' is 'Absent'" {
                $mockKDSRootKeyFutureCompareNotCompliant = Copy-ArrayObjects $mockKDSRootKeyFutureCompare

                $testIncorrectParameters = @{
                    Ensure = 'Absent'
                }

                $testCases = @()
                foreach($incorrectParameter in $testIncorrectParameters.GetEnumerator())
                {
                    $objectParameter = $mockKDSRootKeyFutureCompareNotCompliant | Where-Object { $_.Parameter -eq $incorrectParameter.Name }
                    $objectParameter.Expected = $incorrectParameter.Value
                    $objectParameter.Pass = $false

                    $testCases += @{ Parameter = $incorrectParameter.Name; Value = $incorrectParameter.Value }
                }

                Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                    $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                } -MockWith {
                    Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                    return $mockKDSRootKeyFutureCompareNotCompliant
                }

                It "Should return $false when <Parameter> is incorrect" -TestCases $testCases {
                    param (
                        [Parameter()]
                        $Parameter,

                        [Parameter()]
                        $Value
                    )

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure        = 'Present'
                    }

                    $getTargetResourceParametersFuture[$Parameter] = $value
                    Test-TargetResource @getTargetResourceParametersFuture | Should Be $false
                }
            }
        }
        #endregion Function Test-TargetResource

        #region Function Set-TargetResource
        Describe -Name 'MSFT_xADKDSKey\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                Mock -CommandName Add-KDSRootKey
                Mock -CommandName Remove-ADObject
                Mock -CommandName Write-Warning
            }

            Context -Name 'When the system is in the desired state' {
                Context -Name 'When the KDS root key is Present' {
                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompare
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                    }

                    It 'Should NOT take any action when all parameters are correct' {
                        Set-TargetResource @getTargetResourceParametersFuture

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 0
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 0
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 0
                    }
                }

                Context -Name 'When the KDS root key is Absent' {
                    $mockKDSRootKeyFutureCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyFutureCompare
                    $objectEnsure = $mockKDSRootKeyFutureCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                    $objectEnsure.Expected = 'Absent'
                    $objectEnsure.Pass = $false

                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompareEnsureAbsent
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure = 'Present'
                    }

                    It 'Should NOT take any action when all parameters are correct' {
                        Set-TargetResource @getTargetResourceParametersFuture

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 1
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 0
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 0
                    }
                }
            }

            Context -Name 'When the system is NOT in the desired state' {
                Context -Name 'When the KDS root key is Present and more than one KDS root key exists' {
                    Mock -CommandName Get-KdsRootKey -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Call Get-KdsRootKey with effective time of: $($mockKDSRootKeyFuture.EffectiveTime)"
                        return @($mockKDSRootKeyFuture, $mockKDSRootKeyPast)
                    }

                    $mockKDSRootKeyFutureCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyFutureCompare
                    $objectEnsure = $mockKDSRootKeyFutureCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                    $objectEnsure.Actual = 'Present'
                    $objectEnsure.Pass = $false

                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompareEnsureAbsent
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure = 'Absent'
                    }

                    It "Should call 'Remove-ADObject' when 'Ensure' is set to 'Present'" {
                        Set-TargetResource @getTargetResourceParametersFuture

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 0
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 1
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 0
                        Assert-MockCalled -CommandName Get-KdsRootKey -Scope It -Exactly -Times 1
                    }


                }

                Context -Name 'When the KDS root key is Present and only one KDS root key exists' {
                    Mock -CommandName Get-KdsRootKey -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Call Get-KdsRootKey with effective time of: $($mockKDSRootKeyFuture.EffectiveTime)"
                        return ,@($mockKDSRootKeyFuture)
                    }

                    $mockKDSRootKeyFutureCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyFutureCompare
                    $objectEnsure = $mockKDSRootKeyFutureCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                    $objectEnsure.Actual = 'Present'
                    $objectEnsure.Pass = $false

                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompareEnsureAbsent
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure = 'Absent'
                    }

                    It "Should call NOT 'Remove-ADObject' when 'Ensure' is set to 'Present' and 'ForceRemove' is 'False'" {
                        { $null = Set-TargetResource @getTargetResourceParametersFuture -ErrorAction 'SilentlyContinue' } | Should -Throw

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 0
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 0
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 0
                        Assert-MockCalled -CommandName Get-KdsRootKey -Scope It -Exactly -Times 1
                    }

                    $getTargetResourceParametersFutureForce = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure        = 'Absent'
                        ForceRemove   = $true
                    }

                    It "Should call 'Remove-ADObject' when 'Ensure' is set to 'Present' and 'ForceRemove' is 'True'" {
                        $null = Set-TargetResource @getTargetResourceParametersFutureForce

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 0
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 1
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-KdsRootKey -Scope It -Exactly -Times 1
                    }
                }

                Context -Name 'When the KDS root key is Absent' {
                    $mockKDSRootKeyFutureCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyFutureCompare
                    $objectEnsure = $mockKDSRootKeyFutureCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                    $objectEnsure.Actual = 'Absent'
                    $objectEnsure.Pass = $false

                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                        return $mockKDSRootKeyFutureCompareEnsureAbsent
                    }

                    $getTargetResourceParametersFuture = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure = 'Present'
                    }

                    It "Should call 'Add-KDSRootKey' when 'Ensure' is set to 'Present'" {
                        Set-TargetResource @getTargetResourceParametersFuture

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 1
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 0
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 0
                    }
                }

                Context -Name 'When the KDS root key is Absent and the EffectiveTime is before current date' {
                    $mockKDSRootKeyPastCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyPastCompare
                    $objectEnsure = $mockKDSRootKeyPastCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                    $objectEnsure.Actual = 'Absent'
                    $objectEnsure.Pass = $false

                    Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                        $mockKDSRootKeyPast.EffectiveTime -eq $EffectiveTime
                    } -MockWith {
                        Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyPast.EffectiveTime)"
                        return $mockKDSRootKeyPastCompareEnsureAbsent
                    }

                    $getTargetResourceParametersPast = @{
                        EffectiveTime = $mockKDSRootKeyPast.EffectiveTime
                        Ensure        = 'Present'
                    }

                    It "Should NOT call 'Add-KDSRootKey' when 'EffectiveTime' is past date and 'UnsafeEffectiveTime' is 'False'" {
                        { $null = Set-TargetResource @getTargetResourceParametersPast -ErrorAction 'SilentlyContinue' } | Should -Throw

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 0
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 0
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 0
                    }

                    $getTargetResourceParametersPast = @{
                        EffectiveTime       = $mockKDSRootKeyPast.EffectiveTime
                        Ensure              = 'Present'
                        UnsafeEffectiveTime = $true
                    }

                    It "Should NOT call 'Add-KDSRootKey' when 'EffectiveTime' is past date and 'UnsafeEffectiveTime' is 'True'" {
                        Set-TargetResource @getTargetResourceParametersPast

                        Assert-MockCalled -CommandName Add-KDSRootKey -Scope It -Times 1
                        Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 0
                        Assert-MockCalled -CommandName Write-Warning -Scope It -Exactly -Times 1
                    }
                }
            }

            Context -Name 'When system cannot connect to domain or other errors' {
                $mockKDSRootKeyFutureCompareEnsureAbsent = Copy-ArrayObjects $mockKDSRootKeyFutureCompare
                $objectEnsure = $mockKDSRootKeyFutureCompareEnsureAbsent | Where-Object {$_.Parameter -eq 'Ensure'}
                $objectEnsure.Actual = 'Present'
                $objectEnsure.Pass = $false

                Mock -CommandName Compare-TargetResourceState -ParameterFilter {
                    $mockKDSRootKeyFuture.EffectiveTime -eq $EffectiveTime
                } -MockWith {
                    Write-Verbose "Calling Compare-TargetResourceState with $($mockKDSRootKeyFuture.EffectiveTime)"
                    return $mockKDSRootKeyFutureCompareEnsureAbsent
                }

                Mock -CommandName Get-KdsRootKey -MockWith {
                    Write-Verbose 'Get-KdsRootKey throws an error'
                    throw 'Microsoft.ActiveDirectory.Management.ADServerDownException'
                }

                It "Should call 'Get-KdsRootKey' and throw an error when catching any errors" {
                    $getTargetResourceParameters = @{
                        EffectiveTime = $mockKDSRootKeyFuture.EffectiveTime
                        Ensure = 'Absent'
                    }

                    { $null = Set-TargetResource  @getTargetResourceParameters -ErrorAction 'SilentlyContinue' } | Should -Throw
                }
            }
        }
        #endregion Function Set-TargetResource
    }
}
finally
{
    Invoke-TestCleanup
}
