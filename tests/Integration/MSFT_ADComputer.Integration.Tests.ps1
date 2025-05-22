$script:dscResourceFriendlyName = 'ADComputer'
$script:dscResourceName = "MSFT_$($script:dscResourceFriendlyName)"

$configFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:dscResourceName).config.ps1"
. $configFile

Describe "$($script:dscResourceName)_Integration" {
    BeforeAll {
        $resourceId = "[$($script:dscResourceFriendlyName)]Integration_Test"
    }

    $configurationName = "$($script:dscResourceName)_CreateComputerAccount1_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should -Not -Throw
        }

        It 'Should have set the resource and all the parameters should match' {
            $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                $_.ConfigurationName -eq $configurationName `
                    -and $_.ResourceId -eq $resourceId
            }

            $resourceCurrentState.Ensure | Should -Be 'Present'
            $resourceCurrentState.ComputerName | Should -Be $ConfigurationData.AllNodes.ComputerName1
            $resourceCurrentState.Location | Should -Be 'Old location'
            $resourceCurrentState.DnsHostName | Should -BeNullOrEmpty
            $resourceCurrentState.ServicePrincipalNames | Should -BeNullOrEmpty
            $resourceCurrentState.UserPrincipalName | Should -BeNullOrEmpty
            $resourceCurrentState.DisplayName | Should -BeNullOrEmpty
            $resourceCurrentState.Path | Should -Match '^CN=Computers'
            $resourceCurrentState.Description | Should -BeNullOrEmpty
            $resourceCurrentState.Enabled | Should -BeTrue
            $resourceCurrentState.EnabledOnCreation | Should -BeFalse
            $resourceCurrentState.DomainController | Should -BeNullOrEmpty
            $resourceCurrentState.Credential | Should -BeNullOrEmpty
            $resourceCurrentState.RequestFile | Should -BeNullOrEmpty
            $resourceCurrentState.RestoreFromRecycleBin | Should -BeFalse
            $resourceCurrentState.DistinguishedName | Should -Match ('^CN={0}' -f $ConfigurationData.AllNodes.ComputerName1)
            $resourceCurrentState.SID | Should -Match '^S-'
            $resourceCurrentState.SamAccountName | Should -Be ('{0}$' -f $ConfigurationData.AllNodes.ComputerName1)
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }

    $configurationName = "$($script:dscResourceName)_RemoveComputerAccount1_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Verbose      = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should -Not -Throw
        }

        It 'Should have set the resource and all the parameters should match' {
            $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                $_.ConfigurationName -eq $configurationName `
                    -and $_.ResourceId -eq $resourceId
            }

            $resourceCurrentState.Ensure | Should -Be 'Absent'
            $resourceCurrentState.Enabled | Should -BeFalse
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }

    $configurationName = "$($script:dscResourceName)_RestoreComputerAccount1_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Verbose      = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should -Not -Throw
        }

        It 'Should have set the resource and all the parameters should match' {
            $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                $_.ConfigurationName -eq $configurationName `
                    -and $_.ResourceId -eq $resourceId
            }

            $resourceCurrentState.Ensure | Should -Be 'Present'
            $resourceCurrentState.Enabled | Should -BeTrue
            $resourceCurrentState.Location | Should -Be 'Old location'
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }

    $configurationName = "$($script:dscResourceName)_CreateComputerAccount2Disabled_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Verbose      = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should -Not -Throw
        }

        It 'Should have set the resource and all the parameters should match' {
            $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                $_.ConfigurationName -eq $configurationName `
                    -and $_.ResourceId -eq $resourceId
            }

            $resourceCurrentState.Ensure | Should -Be 'Present'
            $resourceCurrentState.Enabled | Should -BeFalse
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }

    $configurationName = "$($script:dscResourceName)_CreateComputerAccount3WithOfflineDomainJoin_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Verbose      = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should have created a Offline Domain Join request file' {
            $ConfigurationData.AllNodes.RequestFileName | Should -Exist
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should -Not -Throw
        }

        It 'Should have set the resource and all the parameters should match' {
            $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                $_.ConfigurationName -eq $configurationName `
                    -and $_.ResourceId -eq $resourceId
            }

            $resourceCurrentState.Ensure | Should -Be 'Present'
            $resourceCurrentState.Enabled | Should -BeTrue
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }

    $configurationName = "$($script:dscResourceName)_UpdateComputerAccount1_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Verbose      = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
            } | Should -Not -Throw
        }

        It 'Should have set the resource and all the parameters should match' {
            $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                $_.ConfigurationName -eq $configurationName `
                    -and $_.ResourceId -eq $resourceId
            }

            $resourceCurrentState.Ensure | Should -Be 'Present'
            $resourceCurrentState.ComputerName | Should -Be $ConfigurationData.AllNodes.ComputerName1
            $resourceCurrentState.Location | Should -Be $ConfigurationData.AllNodes.Location
            $resourceCurrentState.DnsHostName | Should -Be $ConfigurationData.AllNodes.DnsHostName
            $resourceCurrentState.ServicePrincipalNames | Should -Contain 'spn/a'
            $resourceCurrentState.ServicePrincipalNames | Should -Contain 'spn/b'
            $resourceCurrentState.UserPrincipalName | Should -Be $ConfigurationData.AllNodes.UserPrincipalName
            $resourceCurrentState.DisplayName | Should -Be $ConfigurationData.AllNodes.DisplayName
            $resourceCurrentState.Path | Should -Be ('OU={0},{1}' -f $ConfigurationData.AllNodes.OrganizationalUnitName, $ConfigurationData.AllNodes.DomainDistinguishedName)
            $resourceCurrentState.Description | Should -Be $ConfigurationData.AllNodes.Description
            $resourceCurrentState.Enabled | Should -BeTrue
            $resourceCurrentState.EnabledOnCreation | Should -BeFalse
            $resourceCurrentState.DomainController | Should -BeNullOrEmpty
            $resourceCurrentState.Credential | Should -BeNullOrEmpty
            $resourceCurrentState.RequestFile | Should -BeNullOrEmpty
            $resourceCurrentState.RestoreFromRecycleBin | Should -BeFalse
            $resourceCurrentState.DistinguishedName | Should -Match ('^CN={0}' -f $ConfigurationData.AllNodes.ComputerName1)
            $resourceCurrentState.SID | Should -Match '^S-'
            $resourceCurrentState.SamAccountName | Should -Be ('{0}$' -f $ConfigurationData.AllNodes.ComputerName1)
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }

    $configurationName = "$($script:dscResourceName)_CleanUp_Config"

    Context ('When using configuration {0}' -f $configurationName) {
        It 'Should compile and apply the MOF without throwing' {
            {
                $configurationParameters = @{
                    OutputPath        = $TestDrive
                    # The variable $ConfigurationData was dot-sourced above.
                    ConfigurationData = $ConfigurationData
                }

                & $configurationName @configurationParameters

                $startDscConfigurationParameters = @{
                    Path         = $TestDrive
                    ComputerName = 'localhost'
                    Wait         = $true
                    Verbose      = $true
                    Force        = $true
                    ErrorAction  = 'Stop'
                }

                Start-DscConfiguration @startDscConfigurationParameters
            } | Should -Not -Throw
        }

        It 'Should return $true when Test-DscConfiguration is run' {
            Test-DscConfiguration -Verbose | Should -Be 'True'
        }
    }
}
