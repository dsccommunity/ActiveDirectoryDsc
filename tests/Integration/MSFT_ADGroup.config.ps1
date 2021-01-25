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
    $domainDistinguishedName = $currentDomain.DistinguishedName
    $AdminUserName = "$netBiosDomainName\Administrator"
    $AdminPassword = 'Coffee33!'
    $AdminCredential = [System.Management.Automation.PSCredential]::new($AdminUserName,
        (ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force))

    $groupName = 'DscIntegrationTestGroup'

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName                = 'localhost'
                CertificateFile         = $env:DscPublicCertificatePath
                PsDscAllowDomainUser    = $true

                DomainDistinguishedName = $domainDistinguishedName

                Tests                   = [Ordered]@{
                    CreateGroup               = @{
                        GroupName   = $groupName
                        GroupScope  = 'Global'
                        Category    = 'Security'
                        Path        = "CN=Users,$domainDistinguishedName"
                        Description = 'Original Description'
                        DisplayName = 'Display Name'
                        Members     = 'Administrator', 'Guest'
                        ManagedBy   = "CN=Administrator,CN=Users,$domainDistinguishedName"
                        Notes       = 'Notes'
                        Ensure      = 'Present'
                    }
                    ModifyGroup               = @{
                        GroupName   = $groupName
                        GroupScope  = 'DomainLocal'
                        Category    = 'Distribution'
                        Path        = "CN=Computers,$domainDistinguishedName"
                        Description = 'Modified Description'
                        DisplayName = 'Modified Display Name'
                        Members     = 'Administrator'
                        ManagedBy   = "CN=Guest,CN=Users,$domainDistinguishedName"
                        Notes       = 'Modified Notes'
                    }
                    MembersToInclude          = @{
                        GroupName        = $groupName
                        MembersToInclude = 'Guest'
                    }
                    MembersToExclude          = @{
                        GroupName        = $groupName
                        MembersToExclude = 'Guest'
                    }
                    RemoveAllMembersFromGroup = @{
                        GroupName = $groupName
                        Members   = @()
                    }
                    RemoveGroup               = @{
                        GroupName = $groupName
                        Ensure    = 'Absent'
                    }
                }
            }
        )
    }
}

<#
    .SYNOPSIS
        Create an AD Group.
#>
Configuration MSFT_ADGroup_CreateGroup_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'CreateGroup'

    node $AllNodes.NodeName
    {
        ADGroup 'Integration_Test'
        {
            GroupName            = $Node.Tests.$testName.GroupName
            GroupScope           = $Node.Tests.$testName.GroupScope
            Category             = $Node.Tests.$testName.Category
            Path                 = $Node.Tests.$testName.Path
            Description          = $Node.Tests.$testName.Description
            DisplayName          = $Node.Tests.$testName.DisplayName
            Members              = $Node.Tests.$testName.Members
            ManagedBy            = $Node.Tests.$testName.ManagedBy
            Notes                = $Node.Tests.$testName.Notes
            Ensure               = $Node.Tests.$testName.Ensure
            PsDscRunAsCredential = $adminCredential
        }
    }
}

<#
    .SYNOPSIS
        Modify an AD Group.
#>
Configuration MSFT_ADGroup_ModifyGroup_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'ModifyGroup'

    node $AllNodes.NodeName
    {
        ADGroup 'Integration_Test'
        {
            GroupName            = $Node.Tests.$testName.GroupName
            GroupScope           = $Node.Tests.$testName.GroupScope
            Category             = $Node.Tests.$testName.Category
            Path                 = $Node.Tests.$testName.Path
            Description          = $Node.Tests.$testName.Description
            DisplayName          = $Node.Tests.$testName.DisplayName
            Members              = $Node.Tests.$testName.Members
            ManagedBy            = $Node.Tests.$testName.ManagedBy
            Notes                = $Node.Tests.$testName.Notes
            PsDscRunAsCredential = $adminCredential
        }
    }
}

<#
    .SYNOPSIS
        Include members in an AD Group.
#>
Configuration MSFT_ADGroup_MembersToInclude_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'MembersToInclude'

    node $AllNodes.NodeName
    {
        ADGroup 'Integration_Test'
        {
            GroupName            = $Node.Tests.$testName.GroupName
            MembersToInclude     = $Node.Tests.$testName.MembersToInclude
            PsDscRunAsCredential = $adminCredential
        }
    }
}

<#
    .SYNOPSIS
        Exclude members in an AD Group.
#>
Configuration MSFT_ADGroup_MembersToExclude_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'MembersToExclude'

    node $AllNodes.NodeName
    {
        ADGroup 'Integration_Test'
        {
            GroupName            = $Node.Tests.$testName.GroupName
            MembersToExclude     = $Node.Tests.$testName.MembersToExclude
            PsDscRunAsCredential = $adminCredential
        }
    }
}

<#
    .SYNOPSIS
        Remove all members from an AD Group.
#>
Configuration MSFT_ADGroup_RemoveAllMembersFromGroup_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'RemoveAllMembersFromGroup'

    node $AllNodes.NodeName
    {
        ADGroup 'Integration_Test'
        {
            GroupName            = $Node.Tests.$testName.GroupName
            Members              = $Node.Tests.$testName.Members
            PsDscRunAsCredential = $adminCredential
        }
    }
}

<#
    .SYNOPSIS
        Remove an AD Group.
#>
Configuration MSFT_ADGroup_RemoveGroup_Config
{
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    $testName = 'RemoveGroup'

    node $AllNodes.NodeName
    {
        ADGroup 'Integration_Test'
        {
            GroupName            = $Node.Tests.$testName.GroupName
            Ensure               = $Node.Tests.$testName.Ensure
            PsDscRunAsCredential = $adminCredential
        }
    }
}
