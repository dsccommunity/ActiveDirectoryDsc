$Global:DSCModuleName      = 'xActiveDirectory'
$Global:DSCResourceName    = 'MSFT_xADDomainJoinFile'

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

    InModuleScope $Global:DSCResourceName {

        $ComputerName = 'Workstation'
        $DomainNameNetBios = 'CONTOSO'
        $TestRequestODJ = @{
            DomainName   = "$DomainNameNetBios.COM"
            ComputerName = $ComputerName
            RequestFile  = 'c:\testodj.txt'
        }
        $DomainName = "DC=$DomainNameNetBios,DC=COM"
        $ComputersContainerName = 'Computers'
        $FakeDomain = @{
            ComputersContainer = "CN=$ComputersContainerName,$DomainName"
            DistinguishedName  = $DomainName
            Name               = $DomainNameNetBios
        }
        $FakeComputer = @{
            DistinguishedName = "CN=$ComputerName,$($FakeDomain.ComputersContainer)"
            Name              = $ComputerName
            Enabled           = $True
        }

        Describe "$($Global:DSCResourceName)\Get-TargetResource" {

            Mock Get-ADDomain -MockWith { return $FakeDomain }
            Mock Get-ADComputer -MockWith { }

            Context 'Computer object not in Domain' {
                It 'should return the correct values' {
                    $Result = Get-TargetResource `
                        @TestRequestODJ

                    $Result.DomainName   | Should Be $TestRequestODJ.DomainName
                    $Result.ComputerName | Should Be $TestRequestODJ.ComputerName
                    $Result.Path         | Should BeNullOrEmpty
                    $Result.RequestFile  | Should Be $TestRequestODJ.RequestFile
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Get-ADDomain -Times 1
                    Assert-MockCalled Get-ADComputer -Times 1
                }
            }

            Mock Get-ADComputer -MockWith { return $FakeComputer }

            Context 'Computer object exists in Domain' {
                It 'should return the correct values' {
                    $Result = Get-TargetResource `
                        @TestRequestODJ

                    $Result.DomainName   | Should Be $TestRequestODJ.DomainName
                    $Result.ComputerName | Should Be $TestRequestODJ.ComputerName
                    $Result.Path         | Should Be $FakeDomain.ComputersContainer
                    $Result.RequestFile  | Should Be $TestRequestODJ.RequestFile
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Get-ADDomain -Times 1
                    Assert-MockCalled Get-ADComputer -Times 1
                }
            }
        }

        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            Mock Join-Domain
            Mock Test-Path -MockWith { return $False }

            Context 'Domain is not joined, request file does not exist' {
                It 'should not throw exception' {
                    { Set-TargetResource @TestRequestODJ } | Should Not Throw
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Test-Path -Times 1
                    Assert-MockCalled Join-Domain -Times 1
                }
            }

            Mock Test-Path -MockWith { return $True }
            
            Context 'Domain is not joined, request file exists' {
                It 'should throw a RequestFileExistsError exception' {
                    $errorId = 'RequestFileExistsError'
                    $errorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                    $errorMessage = $($LocalizedData.RequestFileExistsError) `
                        -f $TestRequestODJ.RequestFile
                    $exception = New-Object -TypeName System.ArgumentException `
                        -ArgumentList $errorMessage
                    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
                        -ArgumentList $exception, $errorId, $errorCategory, $null

                    { Set-TargetResource @TestRequestODJ } | Should Throw $errorRecord
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Test-Path -Times 1
                    Assert-MockCalled Join-Domain -Times 0
                }
            }
        }
        
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
            Mock Test-ComputerAccount -MockWith { return $True }

            Context 'Computer Account exists in Domain' {
                It 'should return true' {
                    Test-TargetResource @TestRequestODJ | Should be $true
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Test-ComputerAccount -Times 1
                }
            }

            Mock Test-ComputerAccount -MockWith { return $False }

            Context 'Domain is already joined' {
                It 'should return false' {
                    Test-TargetResource @TestRequestODJ | should be $false
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Test-ComputerAccount -Times 1
                }
            }
        }

        Describe "$($Global:DSCResourceName)\Join-Domain" {
            Mock djoin.exe -MockWith { $Global:LASTEXITCODE = 0; return "OK" }

            Context 'Domain Join successful' {
                It 'should not throw' {
                    { Join-Domain @TestRequestODJ } | Should Not Throw
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled djoin.exe -Times 1
                }
            }

            Mock djoin.exe -MockWith { $Global:LASTEXITCODE = 99; return "ERROR" }

            Context 'Domain Join throws error' {
                $errorId = 'DjoinError'
                $errorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                $errorMessage = $($LocalizedData.DjoinError) `
                    -f 99
                $exception = New-Object -TypeName System.ArgumentException `
                    -ArgumentList $errorMessage
                $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
                    -ArgumentList $exception, $errorId, $errorCategory, $null

                It 'should throw DjoinError exception' {
                    { Join-Domain @TestRequestODJ } | Should Throw $errorRecord
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled djoin.exe -Times 1
                }
            }
        }

        Describe "$($Global:DSCResourceName)\Test-ComputerAccount" {
            Mock Get-ADDomain -MockWith { return $FakeDomain }
            Mock Get-ADComputer -MockWith { return $FakeComputer }

            Context 'Computer Account exists in Domain' {
                It 'should return true' {
                    Test-ComputerAccount @TestRequestODJ | Should Be $True
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Get-ADDomain -Times 1
                    Assert-MockCalled Get-ADComputer -Times 1
                }
            }

            Mock Get-ADComputer

            Context 'Computer Account does not exist in Domain' {
                It 'should return false' {
                    Test-ComputerAccount @TestRequestODJ | Should Be $False
                }
                It 'Should do call all the mocks' {
                    Assert-MockCalled Get-ADDomain -Times 1
                    Assert-MockCalled Get-ADComputer -Times 1
                }
            }
        }
    } #end InModuleScope $DSCResourceName
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
