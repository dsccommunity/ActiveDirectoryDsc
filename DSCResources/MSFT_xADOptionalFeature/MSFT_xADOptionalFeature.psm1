function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FeatureName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        Write-Verbose -Message "Retrieving the Optional Feature $FeatureName"
        $Feature = Get-ADOptionalFeature -Filter {name -eq $FeatureName} -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential

        if ($Feature.EnabledScopes.Count -gt 0)
        {
            $FeatureEnabled = $True
        }
        else
        {
            $FeatureEnabled = $False
        }
    }

    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],[Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        Write-Error -Message "Cannot contact forest $ForestFQDN. Check the spelling of the Forest FQDN and make sure that a domain contoller is available on the network."
        Throw $_
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        Write-Error -Message "Credential error. Check the username and password used."
        Throw $_
    }
    catch
    {
        Write-Error -Message "Unhandled exception getting $FeatureName status for forest $ForestFQDN."
        Throw $_
    }

    finally
    {
        $ErrorActionPreference = 'Continue'
    }

    $returnValue = @{
        ForestFQDN = $ForestFQDN
        FeatureName = $FeatureName
        Enabled = $FeatureEnabled
    }

    $returnValue
}


function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FeatureName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )


    try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $Feature = Get-ADOptionalFeature -Filter {name -eq $FeatureName} -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential

        $Forest = Get-ADForest -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential
        $Domain = Get-ADDomain -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential


        # Check minimum forest level and throw if not
        if (($Forest.ForestMode -as [int]) -lt ($Feature.RequiredForestMode -as [int]))
        {
            Write-Verbose -Message "Forest functionality level $($Forest.ForestMode) does not meet minimum requirement of $($Feature.RequiredForestMode) or greater."
            Throw "Forest functionality level $($Forest.ForestMode) does not meet minimum requirement of $($Feature.RequiredForestMode) or greater."
        }

        # Check minimum domain level and throw if not
        if (($Domain.DomainMode -as [int]) -lt ($Feature.RequiredDomainMode -as [int]))
        {
            Write-Verbose -Message "Domain functionality level $($Domain.DomainMode) does not meet minimum requirement of $($Feature.RequiredDomainMode) or greater."
            Throw "Domain functionality level $($Domain.DomainMode) does not meet minimum requirement of $($Feature.RequiredDomainMode) or greater."
        }

        if ($PSCmdlet.ShouldProcess($Forest.RootDomain, "Enable $FeatureName"))
        {
            Enable-ADOptionalFeature -Identity $FeatureName -Scope ForestOrConfigurationSet `
                -Target $Forest.RootDomain -Server $Forest.DomainNamingMaster `
                -Credential $EnterpriseAdministratorCredential `
                -Verbose
        }
    }

    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],[Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        Write-Error -Message "Cannot contact forest $ForestFQDN. Check the spelling of the Forest FQDN and make sure that a domain contoller is available on the network."
        Throw $_
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        Write-Error -Message "Credential error. Check the username and password used."
        Throw $_
    }
    catch
    {
        Write-Error -Message "Unhandled exception setting $FeatureName status for forest $ForestFQDN."
        Throw $_
    }

    finally
    {
        $ErrorActionPreference = 'Continue'
    }

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FeatureName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $State = Get-TargetResource @PSBoundParameters

        If ($true -eq $State.Enabled) {
            Write-Verbose "$FeatureName is enabled."
            Return $True
        } Else {
            Write-Verbose "$FeatureName is not enabled."
            Return $False
        }
    }

    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],[Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        Write-Error -Message "Cannot contact forest $ForestFQDN. Check the spelling of the Forest FQDN and make sure that a domain contoller is available on the network."
        Throw $_
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        Write-Error -Message "Credential error. Check the username and password used."
        Throw $_
    }
    catch
    {
        Write-Error -Message "Unhandled exception testing $FeatureName status for forest $ForestFQDN."
        Throw $_
    }

    finally
    {
        $ErrorActionPreference = 'Continue'
    }


}


Export-ModuleMember -Function *-TargetResource

<#
Test syntax:

$cred = Get-Credential contoso\administrator

# Valid Domain
Get-TargetResource -FeatureName 'Privileged Access Management Feature' -ForestFQDN contoso.com -EnterpriseAdministratorCredential $cred
Test-TargetResource -FeatureName 'Privileged Access Management Feature' -ForestFQDN contoso.com -EnterpriseAdministratorCredential $cred
Set-TargetResource -FeatureName 'Privileged Access Management Feature' -ForestFQDN contoso.com -EnterpriseAdministratorCredential $cred -WhatIf

# Invalid Domain
Get-TargetResource -FeatureName 'Privileged Access Management Feature' -ForestFQDN contoso.cm -EnterpriseAdministratorCredential $cred
Test-TargetResource -FeatureName 'Privileged Access Management Feature' -ForestFQDN contoso.cm -EnterpriseAdministratorCredential $cred
Set-TargetResource -FeatureName 'Privileged Access Management Feature' -ForestFQDN contoso.cm -EnterpriseAdministratorCredential $cred -WhatIf
#>
