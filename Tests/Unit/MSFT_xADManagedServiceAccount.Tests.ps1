$Global:DSCModuleName = 'xActiveDirectory'
$Global:DSCResourceName = 'MSFT_xADManagedServiceAccount'

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit
#endregion HEADER


# Begin Testing
try
{

    #region Pester Tests

    InModuleScope $Global:DSCResourceName {

        $testPresentParams = @{
            DomainName                                 = 'contoso.com'
            UserName                                   = 'SQLService_Svc'
            DNSHostname                                = 'SQL.contoso.com'
            PrincipalsAllowedToRetrieveManagedPassword = @("SQLServers")
            Ensure                                     = 'Present'
            Path                                       = "CN=Managed Service Accounts,DC=contoso,DC=com"
        }

        $testAbsentParams = $testPresentParams.Clone()
        $testAbsentParams['Ensure'] = 'Absent'

        $fakeADServiceAccount = @{
            DistinguishedName                          = "CN=$($testPresentParams.UserName),CN=Managed Service Accounts,DC=contoso,DC=com"
            Path                                       = "CN=Managed Service Accounts,DC=contoso,DC=com"
            Enabled                                    = $true
            Name                                       = "$($testPresentParams.UserName)$"
            SamAccountName                             = "$($testPresentParams.UserName)$"
            DNSHostname                                = $testPresentParams.DNSHostname
            PrincipalsAllowedToRetrieveManagedPassword = @("CN=SQLServers,CN=Users,DC=contoso,DC=com")
            AccountExpirationDate                      = $null
            AccountNotDelegated                        = $false
            CompoundIdentitySupported                  = @($false)
            Description                                = $null
            DisplayName                                = $null
            ManagedPasswordIntervalInDays              = @(30)
            PrincipalsAllowedToDelegateToAccount       = @()
            ServicePrincipalName                       = @()
            TrustedForDelegation                       = $false
            RestrictToSingleComputer                   = $false
        }

        $fakeSQLADGroup = @{
            DistinguishedName = "CN=SQLServers,CN=Users,DC=contoso,DC=com"
            Name              = "SQLServers"
        }

        $fakeAppADGroup = @{
            DistinguishedName = "CN=ApplicationServers,CN=Users,DC=contoso,DC=com"
            Name              = "SQLServers"
        }

        $testDomainController = 'TESTDC'
        $testCredential = [System.Management.Automation.PSCredential]::Empty

        $testStringProperties = @('Description', 'DisplayName', 'DNSHostName', 'UserName', 'Path')
        $Mandatory = @("UserName")
        $testArrayProperties = @('PrincipalsAllowedToDelegateToAccount', 'PrincipalsAllowedToRetrieveManagedPassword', 'ServicePrincipalName')
        $testBooleanProperties = @('RestrictToSingleComputer', 'TrustedForDelegation', 'Enabled')
        $testIntProperties = @('ManagedPasswordIntervalInDays' )

        #region Function Get-TargetResource
        Describe "$($Global:DSCResourceName)\Get-TargetResource" {

            It "Should return a 'System.Collections.Hashtable' object type" {
                Mock Get-ADServiceAccount { return [PSCustomObject] $fakeADServiceAccount }

                $ADServiceAccount = Get-TargetResource @testPresentParams

                $ADServiceAccount | Should BeOfType [System.Collections.Hashtable]
            }

            It "Should return 'Ensure' is 'Present' when service account exists" {
                Mock Get-ADServiceAccount { return [PSCustomObject] $fakeADServiceAccount }

                $ADServiceAccount = Get-TargetResource @testPresentParams

                $ADServiceAccount.Ensure | Should Be 'Present'
            }

            It "Should return 'Ensure' is 'Absent' when service account does not exist" {
                Mock Get-ADServiceAccount { throw New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException }

                $ADServiceAccount = Get-TargetResource @testPresentParams

                $ADServiceAccount.Ensure | Should Be 'Absent'
            }

            It "Should call 'Get-ADServiceAccount' with 'Server' parameter when 'DomainController' specified" {
                Mock Get-ADServiceAccount -ParameterFilter { $Server -eq $testDomainController } -MockWith { return [PSCustomObject] $fakeADServiceAccount }

                Get-TargetResource @testPresentParams -DomainController $testDomainController

                Assert-MockCalled Get-ADServiceAccount -ParameterFilter { $Server -eq $testDomainController } -Scope It
            }

            It "Should call 'Get-ADServiceAccount' with 'Credential' parameter when 'DomainAdministratorCredential' specified" {
                Mock Get-ADServiceAccount -ParameterFilter { $Credential -eq $testCredential } -MockWith { return [PSCustomObject] $fakeADServiceAccount }

                Get-TargetResource @testPresentParams -DomainAdministratorCredential $testCredential

                Assert-MockCalled Get-ADServiceAccount -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

        }
        #endregion

        #region Function Test-TargetResource
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
            Mock Get-ADObject { return $fakeADServiceAccount }
            Mock Get-ADObject -ParameterFilter { $Filter -imatch "SQLServers" } { return $fakeSQLADGroup }

            $get = $fakeADServiceAccount.Clone()

            It "Should pass when service account does not exist and 'Ensure' is 'Absent'" {
                $get["Ensure"] = "Absent"
                Mock Get-TargetResource { return $get }

                Test-TargetResource @testAbsentParams | Should Be $true
            }

            It "Should pass when service account exists and 'Ensure' is 'Present'" {
                $get["Ensure"] = "Present"
                Mock Get-TargetResource { return $get }

                Test-TargetResource @testPresentParams | Should Be $true
            }

            It "Should fail when service account does not exist and 'Ensure' is 'Present'" {
                $get["Ensure"] = "Absent"
                Mock Get-TargetResource { return $get }

                Test-TargetResource @testPresentParams | Should Be $false
            }

            It "Should fail when service account exists, and 'Ensure' is 'Absent'" {
                $get["Ensure"] = "Present"
                Mock Get-TargetResource { return $get }

                Test-TargetResource @testAbsentParams | Should Be $false
            }

            foreach ($testParameter in $testStringProperties)
            {
                $get = $fakeADServiceAccount.Clone()
                $get["Ensure"] = "Present"

                It "Should pass when service account '$testParameter' matches AD account property" {
                    $testParameterValue = 'Test Parameter String Value'
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    Mock Get-TargetResource {
                        $get[$testParameter] = $testParameterValue
                        return $get
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $true
                }

                It "Should fail when service account '$testParameter' does not match incorrect AD account property value" {
                    $testParameterValue = 'Test Parameter String Value'
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    Mock Get-TargetResource {
                        $get[$testParameter] = $testParameterValue.Substring(0, ([System.Int32] $testParameterValue.Length / 2))
                        return $get
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $false
                }

                It "Should fail when service account '$testParameter' does not match empty AD account property value" {
                    $testParameterValue = 'Test Parameter String Value'
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    Mock Get-TargetResource {
                        $get[$testParameter] = ''
                        return $get
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $false
                }

                if ($Mandatory.Contains($testParameter) -eq $false)
                {
                    It "Should fail when service account '$testParameter' does not match null AD account property value" {
                        $testParameterValue = 'Test Parameter String Value'
                        $testValidPresentParams = $testPresentParams.Clone()
                        $testValidPresentParams[$testParameter] = $testParameterValue
                        Mock Get-TargetResource {
                            $get[$testParameter] = $null
                            return $get
                        }

                        Test-TargetResource @testValidPresentParams | Should Be $false
                    }

                    It "Should pass when empty service account '$testParameter' matches empty AD account property" {
                        $testValidPresentParams = $testPresentParams.Clone()
                        $testValidPresentParams[$testParameter] = $testParameterValue
                        $validADServiceAccount = $fakeADServiceAccount.Clone()
                        Mock Get-TargetResource {
                            $get[$testParameter] = ''
                            return $get
                        }

                        Test-TargetResource @testValidPresentParams | Should Be $true
                    }

                    It "Should pass when empty service account '$testParameter' matches null AD account property" {
                        $testValidPresentParams = $testPresentParams.Clone()
                        $testValidPresentParams[$testParameter] = $testParameterValue
                        $validADServiceAccount = $fakeADServiceAccount.Clone()
                        Mock Get-TargetResource {
                            $get[$testParameter] = $null
                            return $get
                        }

                        Test-TargetResource @testValidPresentParams | Should Be $true
                    }
                }

            } #end foreach test string property

            foreach ($testParameter in $testBooleanProperties)
            {
                $get = $fakeADServiceAccount.Clone()
                $get["Ensure"] = "Present"
                It "Should pass when service account '$testParameter' matches AD account property" {
                    $testParameterValue = $true
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    Mock Get-TargetResource {
                        $get[$testParameter] = $testParameterValue
                        return $get
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $true
                }

                It "Should fail when service account '$testParameter' does not match AD account property value" {
                    $testParameterValue = $true
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    Mock Get-TargetResource {
                        $get[$testParameter] = $false
                        return $get
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $false
                }

            } #end foreach test boolean property

            foreach ($testParameter in $testintProperties)
            {
                $get = $fakeADServiceAccount.Clone()
                $get["Ensure"] = "Present"
                It "Should pass when service account '$testParameter' matches AD account property" {
                    $testParameterValue = "1"
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    $validADServiceAccount = $fakeADServiceAccount.Clone()
                    $invalidADServiceAccount = $fakeADServiceAccount.Clone()
                    Mock Get-TargetResource {
                        $validADServiceAccount[$testParameter] = $testParameterValue
                        return $validADServiceAccount
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $true
                }

                It "Should fail when service account '$testParameter' does not match AD account property value" {
                    $testParameterValue = 1
                    $testValidPresentParams = $testPresentParams.Clone()
                    $testValidPresentParams[$testParameter] = $testParameterValue
                    $validADServiceAccount = $fakeADServiceAccount.Clone()
                    $invalidADServiceAccount = $fakeADServiceAccount.Clone()
                    Mock Get-TargetResource {
                        $invalidADServiceAccount[$testParameter] = -not $testParameterValue
                        return $invalidADServiceAccount
                    }

                    Test-TargetResource @testValidPresentParams | Should Be $false
                }

            } #end foreach test boolean property

        }
        #endregion

        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            Mock Get-ADObject { return $fakeADServiceAccount }
            Mock Get-ADObject -ParameterFilter { $Filter -imatch "SQLServers" } { return $fakeSQLADGroup }

            $get = $fakeADServiceAccount.Clone()

            It "Should call 'New-ADServiceAccount' when 'Ensure' is 'Present' and the account does not exist" {
                $newUserName = 'NewUser'
                $newAbsentParams = $testAbsentParams.Clone()
                $newAbsentParams['UserName'] = $newUserName
                $newPresentParams = $testPresentParams.Clone()
                $newPresentParams['UserName'] = $newUserName
                Mock New-ADServiceAccount -ParameterFilter { $Name -match $newUserName -and $DNSHostName -match $newAbsentParams["DNSHostName"] } { }
                Mock Set-ADServiceAccount { }
                Mock Get-TargetResource -ParameterFilter { $Username -match $newUserName } { return $newAbsentParams }

                Set-TargetResource @newPresentParams

                Assert-MockCalled New-ADServiceAccount -ParameterFilter { $Name -match $newUserName } -Scope It
            }

            It "Should call 'Move-ADObject' when 'Ensure' is 'Present', the account exists but Path is incorrect" {
                $testTargetPath = 'CN=Users,DC=contoso,DC=com'
                $MoveParams = $testPresentParams.Clone()
                $MoveParams["Path"] = $testTargetPath
                Mock Set-ADServiceAccount { }
                Mock Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -MockWith { }

                Mock Get-TargetResource -ParameterFilter { $Username -match $newUserName } { return $get }

                Set-TargetResource @MoveParams -Enabled $true

                Assert-MockCalled Move-ADObject -ParameterFilter { $TargetPath -eq $testTargetPath } -Scope It
            }

            It "Should call 'Set-ADServiceAccount' when Description AD property is wrong" {
                $testADPropertyName = 'Description'
                Mock Set-ADServiceAccount -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -MockWith { }
                Mock Get-TargetResource -ParameterFilter { $Username -match $newUserName } { return $get }

                Set-TargetResource @testPresentParams -Description 'My custom description'

                Assert-MockCalled Set-ADServiceAccount -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -Scope It -Exactly 1
            }

            It "Should call 'Set-ADServiceAccount' when DNSHostName AD property is wrong" {
                $testADPropertyName = 'DNSHostName'
                Mock Set-ADServiceAccount -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -MockWith { }
                Mock Get-TargetResource -ParameterFilter { $Username -match $newUserName } { return $get }

                $testPresentParams["DNSHostName"] = "MSSQL.contoso.com"

                Set-TargetResource @testPresentParams

                Assert-MockCalled Set-ADServiceAccount -ParameterFilter { $Replace.ContainsKey($testADPropertyName) } -Scope It -Exactly 1
            }

            It "Should call 'Set-ADServiceAccount' when PrincipalsAllowedToRetrieveManagedPassword AD property is wrong" {
                $testADPropertyName = 'PrincipalsAllowedToRetrieveManagedPassword'
                Mock Set-ADServiceAccount -ParameterFilter { $testADPropertyName } -MockWith { }
                Mock Get-TargetResource -ParameterFilter { $Username -match $newUserName } { return $get }

                $testPresentParams["PrincipalsAllowedToRetrieveManagedPassword"] = @("ApplicationServers")

                Set-TargetResource @testPresentParams

                Assert-MockCalled Set-ADServiceAccount -ParameterFilter { $testADPropertyName } -Scope It -Exactly 1
            }

            It "Should call 'Remove-ADServiceAccount' when 'Ensure' is 'Absent' and service account exists" {
                Mock Remove-ADServiceAccount -ParameterFilter { $Identity -match $testAbsentParams.UserName } -MockWith { }
                Mock Get-TargetResource -ParameterFilter { $Username -match $newUserName } {
                    $get["Ensure"] = "Present"
                    return $get
                }

                Set-TargetResource @testAbsentParams

                Assert-MockCalled Remove-ADServiceAccount -ParameterFilter { $Identity -match $testAbsentParams.UserName } -Scope It
            }

        }
        #endregion

        #region Function Assert-TargetResource
        Describe "$($Global:DSCResourceName)\Assert-Parameters" {

            It "Should not throw when 'PasswordNeverExpires' and 'CannotChangePassword' are specified" {
                { Assert-Parameters -PasswordNeverExpires $true -CannotChangePassword $true } | Should Not Throw
            }

            It "Should Throw when account is disabled and 'Password' is specified" {
                { Assert-Parameters -Password $testCredential -Enabled $false } | Should Throw
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

