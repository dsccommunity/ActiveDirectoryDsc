$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath 'xActiveDirectory.Common'
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath 'xActiveDirectory.Common.psm1')

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xADReplicationSite'

<#
    .SYNOPSIS
        Returns the current state of the AD replication site.

    .PARAMETER Name
        Specifies the name of the AD replication site.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    # Get the replication site filtered by it's name. If the site is not
    # present, the command will return $null.
    Write-Verbose -Message ($script:localizedData.GetReplicationSite -f $Name)
    $replicationSite = Get-ADReplicationSite -Filter { Name -eq $Name }

    if ($null -eq $replicationSite)
    {
        Write-Verbose -Message ($script:localizedData.ReplicationSiteAbsent -f $Name)
        $returnValue = @{
            Ensure                     = 'Absent'
            Name                       = $Name
            RenameDefaultFirstSiteName = ''
        }
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ReplicationSitePresent -f $Name)
        $returnValue = @{
            Ensure                     = 'Present'
            Name                       = $Name
            RenameDefaultFirstSiteName = ''
        }
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Add, remove or rename the AD replication site.

    .PARAMETER Ensure
        Specifies if the AD replication site should be added or remove. Default
        value is 'Present'.

    .PARAMETER Name
        Specifies the name of the AD replication site.

    .PARAMETER RenameDefaultFirstSiteName
        Specify if the Default-First-Site-Name should be renamed, if it exists.
        Dafult value is 'false'.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Boolean]
        $RenameDefaultFirstSiteName = $false
    )

    if ($Ensure -eq 'Present')
    {
        $defaultFirstSiteName = Get-ADReplicationSite -Filter { Name -eq 'Default-First-Site-Name' }

        <#
            Check if the user specified to rename the Default-First-Site-Name
            and if it still exists. If both is true, rename the replication site
            instead of creating a new site.
        #>
        if ($RenameDefaultFirstSiteName -and ($null -ne $defaultFirstSiteName))
        {
            Write-Verbose -Message ($script:localizedData.AddReplicationSiteDefaultFirstSiteName -f $Name)

            Rename-ADObject -Identity $defaultFirstSiteName.DistinguishedName -NewName $Name -ErrorAction Stop
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.AddReplicationSite -f $Name)

            New-ADReplicationSite -Name $Name -ErrorAction Stop
        }
    }

    if ($Ensure -eq 'Absent')
    {
        Write-Verbose -Message ($script:localizedData.RemoveReplicationSite -f $Name)

        Remove-ADReplicationSite -Identity $Name -Confirm:$false -ErrorAction Stop
    }
}

<#
    .SYNOPSIS
        Test the AD replication site.

    .PARAMETER Ensure
        Specifies if the AD replication site should be added or remove. Default
        value is 'Present'.

    .PARAMETER Name
        Specifies the name of the AD replication site.

    .PARAMETER RenameDefaultFirstSiteName
        Specify if the Default-First-Site-Name should be renamed, if it exists.
        Dafult value is 'false'.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Boolean]
        $RenameDefaultFirstSiteName = $false
    )

    $currentConfiguration = Get-TargetResource -Name $Name

    if ($currentConfiguration.Ensure -eq $Ensure)
    {
        Write-Verbose -Message ($script:localizedData.ReplicationSiteInDesiredState -f $Name)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ReplicationSiteNotInDesiredState -f $Name)
    }
    return $currentConfiguration.Ensure -eq $Ensure
}
