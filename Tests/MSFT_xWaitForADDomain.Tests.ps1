$Global:DSCModuleName      = 'xActiveDirectory'
$Global:DSCResourceName    = 'MSFT_xWaitForADDomain'

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}
else
{
    & git @('-C',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'),'pull')
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
        $password = 'Password' | ConvertTo-SecureString -AsPlainText -Force
        $DomainUserCredential = New-Object pscredential('Username', $password)
        $domainName = 'example.com'
        $testParams = @{
            DomainName = $domainName
            DomainUserCredential = $DomainUserCredential
            RetryIntervalSec = 10
            RetryCount = 5
        }
        $fakeDomainObject = @{Name = $domainName}
        #endregion


        #region Function Get-TargetResource
        Describe "$($Global:DSCResourceName)\Get-TargetResource" {
            It 'Returns a "System.Collections.Hashtable" object type' {
                Mock -CommandName Get-Domain -MockWith {return $fakeDomainObject}
                $targetResource = Get-TargetResource @testParams
                $targetResource -is [System.Collections.Hashtable] | Should Be $true
            }

            It "Returns DomainName = $($testParams.DomainName) when domain is found" {
                Mock -CommandName Get-Domain -MockWith {return $fakeDomainObject}
                $targetResource = Get-TargetResource @testParams
                $targetResource.DomainName | Should Be $testParams.DomainName
            }

            It "Returns an empty DomainName when domain is not found" {
                Mock -CommandName Get-Domain -MockWith {}
                $targetResource = Get-TargetResource @testParams
                $targetResource.DomainName | Should Be $null
            }
        }
        #endregion


        #region Function Test-TargetResource
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
            It 'Returns a "System.Boolean" object type' {
                Mock -CommandName Get-Domain -MockWith {return $fakeDomainObject}
                $targetResource =  Test-TargetResource @testParams
                $targetResource -is [System.Boolean] | Should Be $true
            }

            It 'Passes when domain found' {
                Mock -CommandName Get-Domain -MockWith {return $fakeDomainObject}
                Test-TargetResource @testParams | Should Be $true
            }

            It 'Fails when domain not found' {
                Mock -CommandName Get-Domain -MockWith {}
                Test-TargetResource @testParams | Should Be $false
            }
        }
        #endregion


        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            It "Doesn't throw exception and doesn't call Start-Sleep and Clear-DnsClientCache when domain found" {
                Mock -CommandName Get-Domain -MockWith {return $fakeDomainObject}
                Mock -CommandName Start-Sleep -MockWith {}
                Mock -CommandName Clear-DnsClientCache -MockWith {}
                {Set-TargetResource @testParams} | Should Not Throw
                Assert-MockCalled -CommandName Get-Domain -Times 1 -Exactly -Scope It
                Assert-MockCalled -CommandName Start-Sleep -Times 0 -Scope It
                Assert-MockCalled -CommandName Clear-DnsClientCache -Times 0 -Scope It
            }

            It "Doesn't call Start-Sleep and Clear-DnsClientCache when domain found" {
                Mock -CommandName Get-Domain -MockWith {return $fakeDomainObject}
                Mock -CommandName Start-Sleep -MockWith {}
                Mock -CommandName Clear-DnsClientCache -MockWith {}
                {Set-TargetResource @testParams} | Should Not Throw
                Assert-MockCalled -CommandName Start-Sleep -Times 0 -Scope It
                Assert-MockCalled -CommandName Clear-DnsClientCache -Times 0 -Scope It
            }

            It "Throws exception when domain not found after $($testParams.RetryCount) retries" {
                Mock -CommandName Get-Domain -MockWith {}
                Mock -CommandName Start-Sleep -MockWith {}
                Mock -CommandName Clear-DnsClientCache -MockWith {}
                {Set-TargetResource @testParams} | Should Throw
            }

            It "Calls Get-Domain exactly $($testParams.RetryCount) times when domain not found" {
                Mock -CommandName Get-Domain -MockWith {}
                Mock -CommandName Start-Sleep -MockWith {}
                Mock -CommandName Clear-DnsClientCache -MockWith {}
                {Set-TargetResource @testParams} | Should Throw
                Assert-MockCalled -CommandName Get-Domain -Times $testParams.RetryCount -Exactly -Scope It
            }

            It "Calls Start-Sleep exactly $($testParams.RetryCount) times when domain not found" {
                Mock -CommandName Get-Domain -MockWith {}
                Mock -CommandName Start-Sleep -MockWith {}
                Mock -CommandName Clear-DnsClientCache -MockWith {}
                {Set-TargetResource @testParams} | Should Throw
                Assert-MockCalled -CommandName Start-Sleep -Times $testParams.RetryCount -Exactly -Scope It
            }

            It "Calls Clear-DnsClientCache exactly $($testParams.RetryCount) times when domain not found" {
                Mock -CommandName Get-Domain -MockWith {}
                Mock -CommandName Start-Sleep -MockWith {}
                Mock -CommandName Clear-DnsClientCache -MockWith {}
                {Set-TargetResource @testParams} | Should Throw
                Assert-MockCalled -CommandName Clear-DnsClientCache -Times $testParams.RetryCount -Exactly -Scope It
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
