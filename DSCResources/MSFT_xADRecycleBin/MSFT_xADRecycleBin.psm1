$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath 'xActiveDirectory.Common'
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath 'xActiveDirectory.Common.psm1')

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xADRecycleBin'

<#
    .SYNOPSIS
        Gets the state of the Active Directory recycle bin.

    .PARAMETER ForestFQDN
        The fully qualified domain name (FQDN) of the forest in which to change the Recycle Bin feature.

    .PARAMETER EnterpriseAdministratorCredential
        The user account credentials to use to perform this task.

#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    $previousErrorActionPreference = $ErrorActionPreference

    try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $rootDSE = Get-ADRootDSE -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential
        $recycleBinPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)"
        $msDSEnabledFeature = Get-ADObject -Identity "CN=Partitions,$($rootDSE.configurationNamingContext)" -Property 'msDS-EnabledFeature' -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential |
            Select-Object -ExpandProperty 'msDS-EnabledFeature'

        if ($msDSEnabledFeature -contains $recycleBinPath)
        {
            Write-Verbose -Message $script:localizedData.RecycleBinEnabled
            $recycleBinEnabled = $true
        }
        else
        {
            Write-Verbose -Message $script:localizedData.RecycleBinNotEnabled
            $recycleBinEnabled = $false
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException], [Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        $errorMessage = $script:localizedData.ForestNotFound -f $ForestFQDN
        New-ObjectNotFoundException -Message $errorMessage -ErrorRecord $_
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        $errorMessage = $script:localizedData.CredentialError
        New-InvalidArgumentException -Message $errorMessage -ArgumentName 'EnterpriseAdministratorCredential'
    }
    catch
    {
        $errorMessage = $script:localizedData.GetUnhandledException -f $ForestFQDN
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }
    finally
    {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    return @{
        ForestFQDN        = $ForestFQDN
        RecycleBinEnabled = $recycleBinEnabled
        ForestMode        = $rootDSE.forestFunctionality.ToString()
    }
}

<#
    .SYNOPSIS
        Sets the state of the Active Directory recycle bin.

    .PARAMETER ForestFQDN
        The fully qualified domain name (FQDN) of the forest in which to change the Recycle Bin feature.

    .PARAMETER EnterpriseAdministratorCredential
        The user account credentials to use to perform this task.

#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    $previousErrorActionPreference = $ErrorActionPreference

    try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $forest = Get-ADForest -Identity $ForestFQDN -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential

        # Check minimum forest level and throw if not
        if (($forest.ForestMode -as [int]) -lt 4)
        {
            throw ($script:localizedData.ForestFunctionalLevelError -f $forest.ForestMode)
        }

        Write-Verbose -Message ($script:localizedData.EnablingRecycleBin -f $forest.RootDomain)

        Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet `
            -Target $forest.RootDomain -Server $forest.DomainNamingMaster `
            -Credential $EnterpriseAdministratorCredential `
            -Verbose
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException], [Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        $errorMessage = $script:localizedData.ForestNotFound -f $ForestFQDN
        New-ObjectNotFoundException -Message $errorMessage -ErrorRecord $_
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        $errorMessage = $script:localizedData.CredentialError
        New-InvalidArgumentException -Message $errorMessage -ArgumentName 'EnterpriseAdministratorCredential'
    }
    catch
    {
        $errorMessage = $script:localizedData.SetUnhandledException -f $ForestFQDN
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }
    finally
    {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

<#
    .SYNOPSIS
        Tests the state the Active Directory recycle bin.

    .PARAMETER ForestFQDN
        The fully qualified domain name (FQDN) of the forest in which to change the Recycle Bin feature.

    .PARAMETER EnterpriseAdministratorCredential
        The user account credentials to use to perform this task.

#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    $previousErrorActionPreference = $ErrorActionPreference

    try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $rootDSE = Get-ADRootDSE -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential
        $recycleBinPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)"
        $msDSEnabledFeature = Get-ADObject -Identity "CN=Partitions,$($rootDSE.configurationNamingContext)" -Property 'msDS-EnabledFeature' -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential |
            Select-Object -ExpandProperty 'msDS-EnabledFeature'

        if ($msDSEnabledFeature -contains $recycleBinPath)
        {
            Write-Verbose $script:localizedData.RecycleBinEnabled
            return $true
        }
        else
        {
            Write-Verbose $script:localizedData.RecycleBinNotEnabled
            return $false
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException], [Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        $errorMessage = $script:localizedData.ForestNotFound -f $ForestFQDN
        New-ObjectNotFoundException -Message $errorMessage -ErrorRecord $_
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        $errorMessage = $script:localizedData.CredentialError
        New-InvalidArgumentException -Message $errorMessage -ArgumentName 'EnterpriseAdministratorCredential'
    }
    catch
    {
        $errorMessage = $script:localizedData.TestUnhandledException -f $ForestFQDN
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }
    finally
    {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

Export-ModuleMember -Function *-TargetResource
