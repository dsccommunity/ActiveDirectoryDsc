# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
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
    $script:dscResourceName = 'MSFT_ADOptionalFeature'

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'

    # Load stub cmdlets and classes.
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1')

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

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
}

Describe 'MSFT_ADOptionalFeature\Get-TargetResource' -Tag 'Get' {
    Context 'When feature is enabled' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                @{
                    EnabledScopes      = @(
                        'CN=Partitions,CN=Configuration,DC=contoso,DC=com',
                        'CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com'
                    )
                    Name               = 'Recycle Bin Feature'
                    RequiredDomainMode = $null
                    RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]4 # Windows2008R2
                }
            }
        }

        It 'Should return expected properties' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $result = Get-TargetResource @featureParameters

                $result.FeatureName | Should -Be $featureParameters.FeatureName
                $result.ForestFqdn | Should -Be $featureParameters.ForestFqdn
                $result.Enabled | Should -BeTrue
                $result.EnterpriseAdministratorCredential.Username | Should -Be $featureParameters.EnterpriseAdministratorCredential.Username
                $result.EnterpriseAdministratorCredential.Password | Should -BeNullOrEmpty
            }

            Should -Invoke -CommandName Get-ADOptionalFeature -Times 1 -Exactly -Scope It -ParameterFilter {
                $Identity.ToString() -eq 'Recycle Bin Feature' -and
                $Server -eq 'DC01' -and
                $Credential.Username -eq 'DummyUser'
            }

            Should -Invoke -CommandName Get-ADForest -Times 1 -Exactly -Scope It -ParameterFilter {
                $Server -eq 'contoso.com' -and
                $Credential.Username -eq 'DummyUser'
            }
        }
    }

    Context 'When feature is not enabled' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                @{
                    EnabledScopes      = @()
                    Name               = 'Recycle Bin Feature'
                    RequiredDomainMode = $null
                    RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]4 # Windows2008R2
                }
            }
        }

        It 'Should return expected properties' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $targetResource = Get-TargetResource @featureParameters

                $targetResource.FeatureName | Should -Be $featureParameters.FeatureName
                $targetResource.ForestFqdn | Should -Be $featureParameters.ForestFqdn
                $targetResource.Enabled | Should -BeFalse
                $targetResource.EnterpriseAdministratorCredential.Username | Should -Be $featureParameters.EnterpriseAdministratorCredential.Username
                $targetResource.EnterpriseAdministratorCredential.Password | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When domain is not available' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADOptionalFeature -ParameterFilter { $Credential.Username -eq 'Invalid' } -MockWith {
                throw New-Object System.Security.Authentication.AuthenticationException
            }
        }

        Context 'When domain is available but authentication fails' {
            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $featureParameters = @{
                        FeatureName                       = 'Recycle Bin Feature'
                        ForestFqdn                        = 'contoso.com'
                        EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'Invalid',
                            (ConvertTo-SecureString -String 'Invalid' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-InvalidArgumentRecord -Message $script:localizedData.CredentialError -ArgumentName 'EnterpriseAdministratorCredential'

                    { Get-TargetResource @featureParameters } | Should -Throw -ExpectedMessage $errorRecord
                }
            }
        }

        Context 'When forest cannot be located' {
            BeforeAll {
                Mock -CommandName Get-ADOptionalFeature -MockWith {
                    throw New-Object Microsoft.ActiveDirectory.Management.ADServerDownException
                }
            }

            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $featureParameters = @{
                        FeatureName                       = 'Recycle Bin Feature'
                        ForestFqdn                        = 'contoso.com'
                        EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-ObjectNotFoundRecord -Message ($script:localizedData.ForestNotFound -f $featureParameters.ForestFQDN)

                    { Get-TargetResource @featureParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }
    }

    Context 'When unknown error occurs' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                throw 'Unknown error'
            }
        }

        It 'Should throw the correct error' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.GetUnhandledException -f $featureParameters.ForestFQDN)

                { Get-TargetResource @featureParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }
        }
    }
}

Describe 'MSFT_ADOptionalFeature\Test-TargetResource' -Tag 'Test' {
    Context 'When target resource in desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    ForestFQDN                        = 'contoso.com'
                    FeatureName                       = 'Recycle Bin Feature'
                    Enabled                           = $true
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }
            }
        }

        It 'Should return $true' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                Test-TargetResource @featureParameters | Should -BeTrue
            }
        }
    }

    Context 'When target not in desired state' {
        BeforeAll {
            Mock -CommandName Get-TargetResource -MockWith {
                @{
                    ForestFQDN                        = 'contoso.com'
                    FeatureName                       = 'Recycle Bin Feature'
                    Enabled                           = $false
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }
            }
        }

        It 'Should return $false' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                Test-TargetResource @featureParameters | Should -BeFalse
            }
        }
    }
}

Describe 'MSFT_ADOptionalFeature\Set-TargetResource' -Tag 'Set' {
    Context 'When domain and forest requirements are met' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADDomain -MockWith {
                @{
                    Name       = 'contoso.com'
                    DomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]7  # Windows2016Domain
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                @{
                    EnabledScopes      = @()
                    Name               = 'Recycle Bin Feature'
                    RequiredDomainMode = $null
                    RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]4 # Windows2008R2
                }
            }

            Mock -CommandName Enable-ADOptionalFeature
        }

        It 'Should call Enable-ADOptionalFeature with correct properties' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                { Set-TargetResource @featureParameters } | Should -Not -Throw
            }

            Should -Invoke Enable-ADOptionalFeature -Scope It -Times 1 -Exactly -ParameterFilter {
                $Identity.ToString() -eq 'Recycle Bin Feature' -and
                $Scope.ToString() -eq 'ForestOrConfigurationSet' -and
                $Server -eq 'DC01'
            }

            Should -Invoke -CommandName Get-ADOptionalFeature -Times 1 -Exactly -Scope It -ParameterFilter {
                $Identity.ToString() -eq 'Recycle Bin Feature' -and
                $Server -eq 'DC01' -and
                $Credential.Username -eq 'DummyUser'
            }

            Should -Invoke -CommandName Get-ADForest -Times 1 -Exactly -Scope It -ParameterFilter {
                $Server -eq 'contoso.com' -and
                $Credential.Username -eq 'DummyUser'
            }

            Should -Invoke -CommandName Get-ADDomain -Times 1 -Exactly -Scope It -ParameterFilter {
                $Server -eq 'contoso.com' -and
                $Credential.Username -eq 'DummyUser'
            }
        }
    }

    Context 'When forest requirements are not met' {
        BeforeAll {
            Mock -CommandName Get-ADDomain -MockWith {
                @{
                    Name       = 'contoso.com'
                    DomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]7  # Windows2016Domain
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                @{
                    EnabledScopes      = @()
                    Name               = 'Recycle Bin Feature'
                    RequiredDomainMode = $null
                    RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]4 # Windows2008R2
                }
            }

            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]0 # Windows2000Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Enable-ADOptionalFeature
        }

        It 'Should throw exception that forest functional level is too low' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.SetUnhandledException -f $featureParameters.ForestFQDN)

                { Set-TargetResource @featureParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }

            Should -Invoke -CommandName Get-ADForest -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOptionalFeature -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Enable-ADOptionalFeature -Exactly -Times 0 -Scope It
        }
    }

    Context 'When domain requirements are not met' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                @{
                    EnabledScopes      = @()
                    Name               = 'Test Feature'
                    RequiredDomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]7 # Windows2016Domain
                    RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                }
            }

            Mock -CommandName Get-ADDomain -MockWith {
                @{
                    Name       = 'contoso.com'
                    DomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]0  # Windows2000Domain
                }
            }

            Mock -CommandName Enable-ADOptionalFeature
        }

        It 'Should throw exception that domain functional level is too low' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $testFeatureProperties = @{
                    FeatureName                       = 'Test Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $errorMessage = Get-InvalidOperationRecord -Message ($script:localizedData.SetUnhandledException -f $testFeatureProperties.ForestFQDN)

                { Set-TargetResource @testFeatureProperties } | Should -Throw -ExpectedMessage $errorMessage.Message
            }

            Should -Invoke -CommandName Get-ADForest -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADDomain -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Get-ADOptionalFeature -Exactly -Times 1 -Scope It
            Should -Invoke -CommandName Enable-ADOptionalFeature -Exactly -Times 0 -Scope It
        }
    }

    Context 'When domain is not available' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADDomain -MockWith {
                @{
                    Name       = 'contoso.com'
                    DomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]7  # Windows2016Domain
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                @{
                    EnabledScopes      = @()
                    Name               = 'Recycle Bin Feature'
                    RequiredDomainMode = $null
                    RequiredForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]4 # Windows2008R2
                }
            }
        }

        Context 'When forest is available but authentication fails' {
            BeforeAll {
                Mock -CommandName Get-ADForest -ParameterFilter {
                    $Credential.Username -eq 'Invalid'
                } -MockWith {
                    throw New-Object System.Security.Authentication.AuthenticationException
                }
            }

            It 'Should throw "Credential Error"' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $badCredentialsProperties = @{
                        FeatureName                       = 'Recycle Bin Feature'
                        ForestFqdn                        = 'contoso.com'
                        EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'Invalid',
                            (ConvertTo-SecureString -String 'Invalid' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-InvalidArgumentRecord -Message $script:localizedData.CredentialError -ArgumentName 'EnterpriseAdministratorCredential'

                    { Set-TargetResource @badCredentialsProperties } | Should -Throw -ExpectedMessage $errorRecord
                }
            }
        }

        Context 'When forest cannot be located' {
            BeforeAll {
                Mock -CommandName Get-ADForest -MockWith {
                    throw New-Object Microsoft.ActiveDirectory.Management.ADServerDownException
                }
            }

            It 'Should throw "Cannot contact forest"' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $featureParameters = @{
                        FeatureName                       = 'Recycle Bin Feature'
                        ForestFqdn                        = 'contoso.com'
                        EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-ObjectNotFoundRecord -Message ($script:localizedData.ForestNotFound -f $featureParameters.ForestFQDN)

                    { Set-TargetResource @featureParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }

        Context 'When domain is available but authentication fails' {
            BeforeAll {
                Mock -CommandName Get-ADDomain -ParameterFilter {
                    $Credential.Username -eq 'Invalid'
                } -MockWith {
                    throw New-Object System.Security.Authentication.AuthenticationException
                }
            }

            It 'Should throw "Credential Error"' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $badCredentialsProperties = @{
                        FeatureName                       = 'Recycle Bin Feature'
                        ForestFqdn                        = 'contoso.com'
                        EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'Invalid',
                            (ConvertTo-SecureString -String 'Invalid' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-InvalidArgumentRecord -Message $script:localizedData.CredentialError -ArgumentName 'EnterpriseAdministratorCredential'

                    { Set-TargetResource @badCredentialsProperties } | Should -Throw -ExpectedMessage $errorRecord
                }
            }
        }

        Context 'When domain cannot be located' {
            BeforeAll {
                Mock -CommandName Get-ADDomain -MockWith {
                    throw New-Object Microsoft.ActiveDirectory.Management.ADServerDownException
                }
            }

            It 'Should throw "Cannot contact forest"' {
                InModuleScope -ScriptBlock {
                    Set-StrictMode -Version 1.0

                    $featureParameters = @{
                        FeatureName                       = 'Recycle Bin Feature'
                        ForestFqdn                        = 'contoso.com'
                        EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                            'DummyUser',
                            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                        )
                    }

                    $errorRecord = Get-ObjectNotFoundRecord -Message ($script:localizedData.ForestNotFound -f $featureParameters.ForestFQDN)

                    { Set-TargetResource @featureParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
                }
            }
        }
    }

    Context 'When unknown error occurs' {
        BeforeAll {
            Mock -CommandName Get-ADForest -MockWith {
                @{
                    Name               = 'contoso.com'
                    ForestMode         = [Microsoft.ActiveDirectory.Management.ADForestMode]7 # Windows2016Forest
                    RootDomain         = 'contoso.com'
                    DomainNamingMaster = 'DC01'
                }
            }

            Mock -CommandName Get-ADDomain -MockWith {
                @{
                    Name       = 'contoso.com'
                    DomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]7  # Windows2016Domain
                }
            }

            Mock -CommandName Get-ADOptionalFeature -MockWith {
                throw 'Unknown error'
            }
        }

        It 'Should throw "unknown" when unknown error occurs' {
            InModuleScope -ScriptBlock {
                Set-StrictMode -Version 1.0

                $featureParameters = @{
                    FeatureName                       = 'Recycle Bin Feature'
                    ForestFqdn                        = 'contoso.com'
                    EnterpriseAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
                        'DummyUser',
                        (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
                    )
                }

                $errorRecord = Get-InvalidOperationRecord -Message ($script:localizedData.SetUnhandledException -f $featureParameters.ForestFQDN)

                { Set-TargetResource @featureParameters } | Should -Throw -ExpectedMessage ($errorRecord.Exception.Message + '*')
            }
        }
    }
}
