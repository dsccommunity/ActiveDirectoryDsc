$script:dscModuleName = 'ActiveDirectoryDsc'
$script:dscResourceName = 'MSFT_ADFineGrainedPasswordPolicy'

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

        $testDomainName = 'contoso.com'
        $testDefaultParams = @{
            DomainName = $testDomainName
        }
        $testDomainController = 'testserver.contoso.com'

        $testPassword = ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force
        $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            'Safemode',
            $testPassword
        )

        $fakeFineGrainedPasswordPolicy = @{
            Name                        = "Administrators"
            ComplexityEnabled           = $true
            LockoutDuration             = New-TimeSpan -Minutes 30
            LockoutObservationWindow    = New-TimeSpan -Minutes 30
            LockoutThreshold            = 3
            MinPasswordAge              = New-TimeSpan -Days 1
            MaxPasswordAge              = New-TimeSpan -Days 42
            MinPasswordLength           = 7
            PasswordHistoryCount        = 12
            ReversibleEncryptionEnabled = $false
            Exists                      = $false
        }

        #region Function Get-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Get-TargetResource' {
            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy { return $fakeFineGrainedPasswordPolicy; }

                $result = Get-TargetResource @testDefaultParams

                Assert-MockCalled -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Scope It
            }

            It 'Returns "System.Collections.Hashtable" object type' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy { return $fakeFineGrainedPasswordPolicy; }

                $result = Get-TargetResource @testDefaultParams

                $result -is [System.Collections.Hashtable] | Should -BeTrue
            }

            It 'Calls "Get-ADFineGrainedPasswordPolicy" without credentials by default' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $null } -MockWith { return $fakeFineGrainedPasswordPolicy; }

                $result = Get-TargetResource @testDefaultParams

                Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $null } -Scope It
            }

            It 'Calls "Get-ADFineGrainedPasswordPolicy" with credentials when specified' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $testCredential } -MockWith { return $fakeFineGrainedPasswordPolicy; }

                $result = Get-TargetResource @testDefaultParams -Credential $testCredential

                Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

            It 'Calls "Get-ADFineGrainedPasswordPolicy" without server by default' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $null } -MockWith { return $fakeFineGrainedPasswordPolicy; }

                $result = Get-TargetResource @testDefaultParams

                Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $null } -Scope It
            }

            It 'Calls "Get-ADFineGrainedPasswordPolicy" with server when specified' {
                Mock -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $testDomainController } -MockWith { return $fakeFineGrainedPasswordPolicy; }

                $result = Get-TargetResource @testDefaultParams -DomainController $testDomainController

                Assert-MockCalled -CommandName Get-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $testDomainController } -Scope It
            }

        }
        #endregion

        #region Function Test-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Test-TargetResource' {
            $testDomainName = 'contoso.com'
            $testDefaultParams = @{
                DomainName = $testDomainName
            }
            $testDomainController = 'testserver.contoso.com'

            $testPassword = ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force
            $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                'Safemode',
                $testPassword
            )

            $stubFineGrainedPasswordPolicy = @{
                ComplexityEnabled           = $true
                LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                LockoutThreshold            = 3
                MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                MinPasswordLength           = 7
                PasswordHistoryCount        = 12
                ReversibleEncryptionEnabled = $true
                Exists                      = $true
            }

            It 'Returns "System.Boolean" object type' {
                Mock -CommandName Get-TargetResource -MockWith { return $stubFineGrainedPasswordPolicy; }

                $result = Test-TargetResource @testDefaultParams

                $result -is [System.Boolean] | Should -BeTrue
            }

            It 'Calls "Get-TargetResource" with "Credential" parameter when specified' {
                Mock -CommandName Get-TargetResource -ParameterFilter { $Credential -eq $testCredential } { return $stubFineGrainedPasswordPolicy; }

                $result = Test-TargetResource @testDefaultParams -Credential $testCredential

                Assert-MockCalled -CommandName Get-TargetResource -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

            It 'Calls "Get-TargetResource" with "DomainController" parameter when specified' {
                Mock -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq $testDomainController } { return $stubFineGrainedPasswordPolicy; }

                $result = Test-TargetResource @testDefaultParams -DomainController $testDomainController

                Assert-MockCalled -CommandName Get-TargetResource -ParameterFilter { $DomainController -eq $testDomainController } -Scope It
            }

            foreach ($propertyName in $stubFineGrainedPasswordPolicy.Keys)
            {
                It "Passes when '$propertyName' parameter matches resource property value" {
                    Mock -CommandName Get-TargetResource -MockWith { return $stubFineGrainedPasswordPolicy; }
                    $propertyDefaultParams = $testDefaultParams.Clone()
                    $propertyDefaultParams[$propertyName] = $stubFineGrainedPasswordPolicy[$propertyName]

                    $result = Test-TargetResource @propertyDefaultParams

                    $result | Should -BeTrue
                }

                It "Fails when '$propertyName' parameter does not match resource property value" {
                    Mock -CommandName Get-TargetResource -MockWith { return $stubFineGrainedPasswordPolicy; }
                    $propertyDefaultParams = $testDefaultParams.Clone()

                    switch ($stubFineGrainedPasswordPolicy[$propertyName].GetType())
                    {
                        'bool'
                        {
                            $propertyDefaultParams[$propertyName] = -not $stubFineGrainedPasswordPolicy[$propertyName]
                        }
                        'string'
                        {
                            $propertyDefaultParams[$propertyName] = 'not{0}' -f $stubFineGrainedPasswordPolicy[$propertyName]
                        }
                        default
                        {
                            $propertyDefaultParams[$propertyName] = $stubFineGrainedPasswordPolicy[$propertyName] + 1
                        }
                    }

                    $result = Test-TargetResource @propertyDefaultParams

                    $result | Should -BeFalse
                }
            } #end foreach property

        }
        #endregion

        #region Function Set-TargetResource
        Describe 'ADFineGrainedPasswordPolicy\Set-TargetResource' {
            $testDomainName = 'contoso.com'
            $testDefaultParams = @{
                DomainName = $testDomainName
            }
            $testDomainController = 'testserver.contoso.com'

            $testPassword = ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force
            $testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                'Safemode',
                $testPassword
            )

            $stubFineGrainedPasswordPolicy = @{
                ComplexityEnabled           = $true
                LockoutDuration             = (New-TimeSpan -Minutes 30).TotalMinutes
                LockoutObservationWindow    = (New-TimeSpan -Minutes 30).TotalMinutes
                LockoutThreshold            = 3
                MinPasswordAge              = (New-TimeSpan -Days 1).TotalMinutes
                MaxPasswordAge              = (New-TimeSpan -Days 42).TotalMinutes
                MinPasswordLength           = 7
                PasswordHistoryCount        = 12
                ReversibleEncryptionEnabled = $true
                Exists                      = $false
            }

            Mock -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' }

            It 'Calls "Assert-Module" to check "ActiveDirectory" module is installed' {
                Mock -CommandName Set-ADFineGrainedPasswordPolicy

                $result = Set-TargetResource @testDefaultParams

                Assert-MockCalled -CommandName Assert-Module -ParameterFilter { $ModuleName -eq 'ActiveDirectory' } -Scope It
            }

            It 'Calls "Set-ADFineGrainedPasswordPolicy" without "Credential" parameter by default' {
                Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $null }

                $result = Set-TargetResource @testDefaultParams

                Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $null } -Scope It
            }

            It 'Calls "Set-ADFineGrainedPasswordPolicy" with "Credential" parameter when specified' {
                Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $testCredential }

                $result = Set-TargetResource @testDefaultParams -Credential $testCredential

                Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

            It 'Calls "Set-ADFineGrainedPasswordPolicy" without "Server" parameter by default' {
                Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $null }

                $result = Set-TargetResource @testDefaultParams

                Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $null } -Scope It
            }

            It 'Calls "Set-ADFineGrainedPasswordPolicy" with "Server" parameter when specified' {
                Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $testDomainController }

                $result = Set-TargetResource @testDefaultParams -DomainController $testDomainController

                Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $Server -eq $testDomainController } -Scope It
            }

            foreach ($propertyName in $stubFineGrainedPasswordPolicy.Keys)
            {
                It "Calls 'Set-ADFineGrainedPasswordPolicy' with '$propertyName' parameter when specified" {
                    $propertyDefaultParams = $testDefaultParams.Clone()
                    $propertyDefaultParams[$propertyName] = $stubFineGrainedPasswordPolicy[$propertyName]
                    Mock -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $PSBoundParameters.ContainsKey($propertyName) }

                    $result = Set-TargetResource @propertyDefaultParams

                    Assert-MockCalled -CommandName Set-ADFineGrainedPasswordPolicy -ParameterFilter { $PSBoundParameters.ContainsKey($propertyName) } -Scope It
                }

            } #end foreach property name

        }
        #endregion

    }
    #endregion
}
finally
{
    Invoke-TestCleanup
}
