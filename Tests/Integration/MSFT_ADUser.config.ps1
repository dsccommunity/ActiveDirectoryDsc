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
    $computersContainerDistinguishedName = (Get-ADDomain).ComputersContainer
    if ($computersContainerDistinguishedName -match 'DC=.+')
    {
        $domainDistinguishedName = $matches[0]
    }

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName                = 'localhost'
                CertificateFile         = $env:DscPublicCertificatePath

                DomainDistinguishedName = $domainDistinguishedName
                UserNamePrefix          = 'DscUser'
                DisplayNamePrefix       = 'Dsc User'

                Password                = New-Object `
                    -TypeName System.Management.Automation.PSCredential `
                    -ArgumentList @(
                        'AnyName',
                        (ConvertTo-SecureString -String 'P@ssW0rd1' -AsPlainText -Force)
                    )

                AdministratorUserName  = ('{0}\Administrator' -f $domainDistinguishedName)
                AdministratorPassword  = 'P@ssw0rd1'
            }
        )
    }
}

<#
    .SYNOPSIS
        Creates a user account with a password that never expires.
#>
Configuration MSFT_ADUser_CreateUser1_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADUser 'Integration_Test'
        {
            DomainName = $Node.DomainDistinguishedName
            UserName = '{0}1' -f $Node.UserNamePrefix
            UserPrincipalName = '{0}1' -f $Node.UserNamePrefix
            DisplayName = '{0} 1' -f $Node.DisplayNamePrefix
            PasswordNeverExpires = $true
            Password = $Node.Password

            PasswordNeverResets = $true

            DomainAdministratorCredential = New-Object `
                -TypeName System.Management.Automation.PSCredential `
                -ArgumentList @(
                    $Node.AdministratorUserName,
                    (ConvertTo-SecureString -String $Node.AdministratorPassword -AsPlainText -Force)
                )
        }
    }
}
