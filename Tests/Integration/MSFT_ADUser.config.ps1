#region HEADER
# Integration Test Config Template Version: 1.2.0
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    <#
        Allows reading the configuration data from a JSON file, for real testing
        scenarios outside of the CI.
    #>
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $currentDomain = Get-ADDomain
    $netBiosDomainName = $currentDomain.NetBIOSName
    if ($currentDomain.ComputersContainer -match 'DC=.+')
    {
        $domainDistinguishedName = $matches[0]
    }

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName                = 'localhost'
                CertificateFile         = $env:DscPublicCertificatePath

                DomainDistinguishedName = $domainDistinguishedName
                NetBIOSName             = $netBiosDomainName

                UserName1               = 'DscTestUser1'
                DisplayName1            = 'Dsc Test User 1'

                Password                = New-Object `
                    -TypeName System.Management.Automation.PSCredential `
                    -ArgumentList @(
                    'AnyName',
                    (ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force)
                )

                AdministratorUserName   = ('{0}\Administrator' -f $netBiosDomainName)
                AdministratorPassword   = 'P@ssw0rd1'
            }
        )
    }
}

<#
    .SYNOPSIS
        Removes a user account.
#>
Configuration MSFT_ADUser_CreateUser1_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADUser 'Integration_Test'
        {
            # Using distinguished name for DomainName - Regression test for issue #451.
            DomainName           = $Node.DomainDistinguishedName
            UserName             = $Node.UserName1
            UserPrincipalName    = $Node.UserName1
            DisplayName          = $Node.DisplayName1
            PasswordNeverExpires = $true
            Password             = $Node.Password

            Credential           = New-Object `
                -TypeName System.Management.Automation.PSCredential `
                -ArgumentList @(
                $Node.AdministratorUserName,
                (ConvertTo-SecureString -String $Node.AdministratorPassword -AsPlainText -Force)
            )
        }
    }
}

<#
    .SYNOPSIS
        Creates a user account with a password that never expires.
#>
Configuration MSFT_ADUser_RemoveUser1_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADUser 'Integration_Test'
        {
            Ensure     = 'Absent'
            DomainName = $Node.DomainDistinguishedName
            UserName   = $Node.UserName1

            Credential           = New-Object `
                -TypeName System.Management.Automation.PSCredential `
                -ArgumentList @(
                $Node.AdministratorUserName,
                (ConvertTo-SecureString -String $Node.AdministratorPassword -AsPlainText -Force)
            )
        }
    }
}
