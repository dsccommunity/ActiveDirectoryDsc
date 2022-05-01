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
    $domainDistinguishedName = $currentDomain.DistinguishedName

    $ConfigurationData = @{
        AllNodes               = @(
            @{
                NodeName                = 'localhost'
                CertificateFile         = $env:DscPublicCertificatePath
                DomainDistinguishedName = $domainDistinguishedName
            }
        )

        ManagedServiceAccount1 = @{
            Name        = 'Dsc-sMSA1'
            AccountType = 'Standalone'
        }

        ManagedServiceAccount2 = @{
            Name                   = 'Dsc-gMSA1'
            AccountType            = 'Group'
            Path                   = "CN=Users,$($domainDistinguishedName)"
            DisplayName            = 'DSC Group Managed Service Account 2'
            Description            = 'A DSC description'
            KerberosEncryptionType = 'AES128', 'AES256'
        }

        ManagedServiceAccount3 = @{
            Name                      = 'Dsc-gMSA2'
            AccountType               = 'Group'
            ManagedPasswordPrincipals = @(
                'Administrator',
                'Guest'
            )
        }

        ManagedServiceAccount4 = @{
            Name        = 'Dsc-gMSA4'
            AccountType = 'Group'
            CommonName  = 'Dsc-gMSACommonName4'
        }
    }
}

<#
    .SYNOPSIS
        Initialise Config
#>
Configuration MSFT_ADManagedServiceAccount_Initialise_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'RemoveGroup1'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount1.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount1.AccountType
            Ensure             = 'Absent'
        }

        ADManagedServiceAccount 'RemoveGroup2'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount2.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount2.AccountType
            Ensure             = 'Absent'
        }

        ADManagedServiceAccount 'RemoveGroup3'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount3.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount3.AccountType
            Ensure             = 'Absent'
        }

        ADManagedServiceAccount 'RemoveGroup4'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount4.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount4.AccountType
            Ensure             = 'Absent'
        }
    }
}

<#
    .SYNOPSIS
        Add a Stand-Alone ManagedServiceAccount using default values.
#>
Configuration MSFT_ADManagedServiceAccount_CreateServiceAccount1_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount1.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount1.AccountType
        }
    }
}

<#
    .SYNOPSIS
        Add a Group ManagedServiceAccount using default values.
#>
Configuration MSFT_ADManagedServiceAccount_CreateServiceAccount2_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount2.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount2.AccountType
        }
    }
}

<#
    .SYNOPSIS
        Add a Second Group ManagedServiceAccount using default values.
#>
Configuration MSFT_ADManagedServiceAccount_CreateServiceAccount3_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount3.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount3.AccountType
        }
    }
}

<#
    .SYNOPSIS
        Add a Third Group ManagedServiceAccount using default values.
#>
Configuration MSFT_ADManagedServiceAccount_CreateServiceAccount4_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount4.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount4.AccountType
            CommonName         = $ConfigurationData.ManagedServiceAccount4.CommonName
        }
    }
}

<#
    .SYNOPSIS
        Remove a ManagedServiceAccount.
#>
Configuration MSFT_ADManagedServiceAccount_RemoveServiceAccount1_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount1.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount1.AccountType
            Ensure             = 'Absent'
        }
    }
}

<#
    .SYNOPSIS
        Update an existing ManagedServiceAccount.
#>
Configuration MSFT_ADManagedServiceAccount_UpdateServiceAccount2_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName     = $ConfigurationData.ManagedServiceAccount2.Name
            AccountType            = $ConfigurationData.ManagedServiceAccount2.AccountType
            Path                   = $ConfigurationData.ManagedServiceAccount2.Path
            DisplayName            = $ConfigurationData.ManagedServiceAccount2.DisplayName
            Description            = $ConfigurationData.ManagedServiceAccount2.Description
            KerberosEncryptionType = $ConfigurationData.ManagedServiceAccount2.KerberosEncryptionType
        }
    }
}

<#
    .SYNOPSIS
        Enforce members in a ManagedServiceAccount.
#>
Configuration MSFT_ADManagedServiceAccount_EnforcePasswordPrincipalsServiceAccount3_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName        = $ConfigurationData.ManagedServiceAccount3.Name
            AccountType               = $ConfigurationData.ManagedServiceAccount3.AccountType
            ManagedPasswordPrincipals = $ConfigurationData.ManagedServiceAccount3.ManagedPasswordPrincipals
        }
    }
}

<#
    .SYNOPSIS
        Enforce no members in a ManagedServiceAccount.
#>
Configuration MSFT_ADManagedServiceAccount_ClearPasswordPrincipalsServiceAccount3_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName        = $ConfigurationData.ManagedServiceAccount3.Name
            AccountType               = $ConfigurationData.ManagedServiceAccount3.AccountType
            ManagedPasswordPrincipals = @()
        }
    }
}

<#
    .SYNOPSIS
        Rename the common name of a ManagedServiceAccount.
#>
Configuration MSFT_ADManagedServiceAccount_RenameServiceAccount4_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    node $AllNodes.NodeName
    {
        ADManagedServiceAccount 'Integration_Test'
        {
            ServiceAccountName = $ConfigurationData.ManagedServiceAccount4.Name
            AccountType        = $ConfigurationData.ManagedServiceAccount4.AccountType
            CommonName         = $ConfigurationData.ManagedServiceAccount4.Name
        }
    }
}
