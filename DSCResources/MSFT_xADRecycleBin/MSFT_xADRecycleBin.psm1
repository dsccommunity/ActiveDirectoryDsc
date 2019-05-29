$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath 'xActiveDirectory.Common'
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath 'xActiveDirectory.Common.psm1')

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xADReplicationSiteLink'

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

    Try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $RootDSE = Get-ADRootDSE -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential
        $RecycleBinPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($RootDSE.configurationNamingContext)"
        $msDSEnabledFeature = Get-ADObject -Identity "CN=Partitions,$($RootDSE.configurationNamingContext)" -Property msDS-EnabledFeature -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential |
            Select-Object -ExpandProperty msDS-EnabledFeature

        If ($msDSEnabledFeature -contains $RecycleBinPath)
        {
            Write-Verbose -Message $script:localizedData.RecycleBinEnabled
            $RecycleBinEnabled = $True
        } Else {
            Write-Verbose -Message $script:localizedData.RecycleBinNotEnabled
            $RecycleBinEnabled = $False
        }
    }

    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],[Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        Write-Error -Message ($script:localizedData.ForestNotFound -f $ForestFQDN)
        Throw $_
    }
    Catch [System.Security.Authentication.AuthenticationException]
    {
        Write-Error -Message $script:localizedData.CredentialError
        Throw $_
    }
    Catch
    {
        Write-Error -Message ($script:localizedData.GetUnhandledException -f $ForestFQDN)
        Throw $_
    }

    Finally {
        $ErrorActionPreference = 'Continue'
    }

    $returnValue = @{
        ForestFQDN = $ForestFQDN
        RecycleBinEnabled = $RecycleBinEnabled
        ForestMode = $RootDSE.forestFunctionality.ToString()
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
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )


    Try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $Forest = Get-ADForest -Identity $ForestFQDN -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential

        # Check minimum forest level and throw if not
        If (($Forest.ForestMode -as [int]) -lt 4)
        {
            Write-Verbose -Message ($script:localizedData.ForestFunctionalLevelError -f $Forest.ForestMode)
            Throw ($script:localizedData.ForestFunctionalLevelError -f $Forest.ForestMode)
        }

        If ($PSCmdlet.ShouldProcess($Forest.RootDomain, "Enable Active Directory Recycle Bin"))
        {
            Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet `
                -Target $Forest.RootDomain -Server $Forest.DomainNamingMaster `
                -Credential $EnterpriseAdministratorCredential `
                -Verbose
        }
    }

    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],[Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        Write-Error -Message ($script:localizedData.ForestNotFound -f $ForestFQDN)
        Throw $_
    }
    Catch [System.Security.Authentication.AuthenticationException]
    {
        Write-Error -Message $script:localizedData.CredentialError
        Throw $_
    }
    Catch
    {
        Write-Error -Message ($script:localizedData.SetUnhandledException -f $ForestFQDN)
        Throw $_
    }

    Finally
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
        $ForestFQDN,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $EnterpriseAdministratorCredential
    )

    Try
    {
        # AD cmdlets generate non-terminating errors.
        $ErrorActionPreference = 'Stop'

        $RootDSE = Get-ADRootDSE -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential
        $RecycleBinPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($RootDSE.configurationNamingContext)"
        $msDSEnabledFeature = Get-ADObject -Identity "CN=Partitions,$($RootDSE.configurationNamingContext)" -Property msDS-EnabledFeature -Server $ForestFQDN -Credential $EnterpriseAdministratorCredential |
            Select-Object -ExpandProperty msDS-EnabledFeature

        If ($msDSEnabledFeature -contains $RecycleBinPath)
        {
            Write-Verbose $script:localizedData.RecycleBinEnabled
            Return $True
        } Else {
            Write-Verbose $script:localizedData.RecycleBinNotEnabled
            Return $False
        }
    }

    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException],[Microsoft.ActiveDirectory.Management.ADServerDownException]
    {
        Write-Error -Message ($script:localizedData.ForestNotFound -f $ForestFQDN)
        Throw $_
    }
    Catch [System.Security.Authentication.AuthenticationException]
    {
        Write-Error -Message $script:localizedData.CredentialError
        Throw $_
    }
    Catch
    {
        Write-Error -Message ($script:localizedData.TestUnhandledException -f $ForestFQDN)
        Throw $_
    }

    Finally
    {
        $ErrorActionPreference = 'Continue'
    }


}


Export-ModuleMember -Function *-TargetResource

<#
Test syntax:

$cred = Get-Credential contoso\administrator

# Valid Domain
Get-TargetResource -ForestFQDN contoso.com -EnterpriseAdministratorCredential $cred
Test-TargetResource -ForestFQDN contoso.com -EnterpriseAdministratorCredential $cred
Set-TargetResource -ForestFQDN contoso.com -EnterpriseAdministratorCredential $cred -WhatIf

# Invalid Domain
Get-TargetResource -ForestFQDN contoso.cm -EnterpriseAdministratorCredential $cred
Test-TargetResource -ForestFQDN contoso.cm -EnterpriseAdministratorCredential $cred
Set-TargetResource -ForestFQDN contoso.cm -EnterpriseAdministratorCredential $cred -WhatIf
#>
