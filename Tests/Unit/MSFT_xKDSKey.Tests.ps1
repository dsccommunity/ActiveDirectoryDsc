[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param()

$Global:DSCModuleName      = 'xActiveDirectory'
$Global:DSCResourceName    = 'MSFT_xKDSKey'

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
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

# Begin Testing
try
{

    #region Pester Tests

    # The InModuleScope command allows you to perform white-box unit testing on the internal
    # (non-exported) code of a Script Module.
    InModuleScope $Global:DSCResourceName {

        #region Pester Test Initialization
        $BaseTime = (Get-Date)

        $testImmediateParams = @{
            StartTime = $BaseTime
        }

        $TestLaterParams = @{
            StartTime = $BaseTime.AddDays(1)
        }

        $TestEalierParams = @{
            StartTime = $BaseTime.AddDays(-5)
        }

        $fakeOlderKeyObject = @{
            AttributeOfWrongFormat = ""
            KeyValue = ""
            EffectiveTime = $BaseTime.AddDays(-1)
            CreationTime = $BaseTime.AddDays(-5)
            IsFormatValid = $true
            DomainController = "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"
            ServerConfiguration = $null
            KeyId = [guid]::NewGuid()
            VersionNumber = 1
        }

        $fakeImmediateKeyObject = @{
            AttributeOfWrongFormat = ""
            KeyValue = ""
            EffectiveTime = $BaseTime
            CreationTime = $BaseTime.AddDays(-5)
            IsFormatValid = $true
            DomainController = "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"
            ServerConfiguration = $null
            KeyId = [guid]::NewGuid()
            VersionNumber = 1
        }

        $fakeFutureKeyObject = @{
            AttributeOfWrongFormat = ""
            KeyValue = ""
            EffectiveTime = $BaseTime.AddDays(1)
            CreationTime = $BaseTime.AddDays(-5)
            IsFormatValid = $true
            DomainController = "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"
            ServerConfiguration = $null
            KeyId = [guid]::NewGuid()
            VersionNumber = 1
        }
        #endregion


        #region Function Get-TargetResource
        Describe "$($Global:DSCResourceName)\Get-TargetResource" {
            It 'Returns a "System.Collections.Hashtable" object type' {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeImmediateKeyObject}
                $targetResource = Get-TargetResource @TestEalierParams
                $targetResource -is [System.Collections.Hashtable] | Should Be $true
            }

            It "Returns EffectiveTime when Key is found" {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeImmediateKeyObject}
                $targetResource = Get-TargetResource @testImmediateParams
                $targetResource.EffectiveTime | Should Be $BaseTime
            }

            It "Returns an empty EffectiveTime when no key is found" {
                Mock -CommandName Get-KDSRootKey -MockWith {}
                $targetResource = Get-TargetResource @testImmediateParams
                $targetResource.EffectiveTime | Should Be $null
            }
        }
        #endregion


        #region Function Test-TargetResource
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
            It 'Returns a "System.Boolean" object type' {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeImmediateKeyObject}
                $targetResource =  Test-TargetResource @testImmediateParams
                $targetResource -is [System.Boolean] | Should Be $true
            }

            It 'Passes when key is active and StartState is in the past' {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeOlderKeyObject}
                Test-TargetResource @testImmediateParams | Should Be $true
            }

            It 'Passes when key EffectiveTime is the same when StartState is in the future' {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeFutureKeyObject}
                Test-TargetResource @TestLaterParams | Should Be $true
            }

            It 'Fails when EffectiveTime is after StartTime' {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeFutureKeyObject}
                Test-TargetResource @TestEalierParams | Should Be $false
            }
        }
        #endregion


        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {

            It "Doesn't throw exception and call Add-KDSRootKey once when key is not found" {
                Mock -CommandName Get-KDSRootKey -MockWith {}
                Mock -CommandName Add-KDSRootKey -MockWith {}
                {Set-TargetResource @testImmediateParams} | Should Not Throw
                Assert-MockCalled -CommandName Add-KDSRootKey -Times 1 -Scope It
            }

            It "Doesn't throw exception and call Add-KDSRootKey once when key exists but requested key is be available sooner" {
                Mock -CommandName Get-KDSRootKey -MockWith {return $fakeFutureKeyObject}
                Mock -CommandName Add-KDSRootKey -MockWith {}
                {Set-TargetResource @TestLaterParams} | Should Not Throw
                Assert-MockCalled -CommandName Add-KDSRootKey -Times 1 -Scope It
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
