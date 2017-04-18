[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param()

$Global:DSCModuleName      = 'xActiveDirectory' # Example xNetworking
$Global:DSCResourceName    = 'MSFT_xADDomain' # Example MSFT_xFirewall

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
Write-Host $moduleRoot -ForegroundColor Green;
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

#Begin Tests
try 
{
    InModuleScope $Global:DSCResourceName {

        $correctDomainName = "present.com"
        $incorrectDomain = "incorrect.com"
        $workgroup = "WORKGROUP"
        $adminCreds = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        $defaultParams = @{
            ADAdmin = $adminCreds;
        }

        $testCimDomainResult = @{ 
            PartOfDomain = $true;
            Domain = $correctDomainName;
        }
        $testCimWorkGroupResult = @{
            PartOfDomain = $false;
            Domain = $workgroup
        }

        Describe "$($Global:DSCResourceName)\Get-TargetResource" {
            #TODO: Implement the PESTER tests here
        }
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
            #TODO: Implement the PESTER tests here
        }
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            #TODO: Implement the PESTER tests here
        }
    }
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}