$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath 'ActiveDirectoryDsc.Common.psm1')

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_ADReplicationSite'

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
    $replicationSite = Get-ADReplicationSite -Filter { Name -eq $Name } -ErrorAction SilentlyContinue

    if ($null -eq $replicationSite)
    {
        Write-Verbose -Message ($script:localizedData.ReplicationSiteAbsent -f $Name)
        $returnValue = @{
            Ensure                     = 'Absent'
            Name                       = $Name
            Description                = ''
            RenameDefaultFirstSiteName = ''
        }
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ReplicationSitePresent -f $Name)
        $returnValue = @{
            Ensure                     = 'Present'
            Name                       = $Name
            Description                = $replicationSite.Description
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
        $RenameDefaultFirstSiteName = $false,

        [Parameter()]
        [System.String]
        $Description
    )

    $Params = @{}
    $createOrUpdate = Get-ADReplicationSite -Filter { Name -eq $Name } -ErrorAction SilentlyContinue


    if ($Ensure -eq 'Present')
    {
        $defaultFirstSiteName = Get-ADReplicationSite -Filter { Name -eq 'Default-First-Site-Name' } -ErrorAction SilentlyContinue

        <#
            Check if the user specified to rename the Default-First-Site-Name
            and if it still exists. If both is true, rename the replication site
            instead of creating a new site.
        #>
        if ($RenameDefaultFirstSiteName -and ($null -ne $defaultFirstSiteName))
        {
            Write-Verbose -Message ($script:localizedData.AddReplicationSiteDefaultFirstSiteName -f $Name)

            Rename-ADObject -Identity $defaultFirstSiteName.DistinguishedName -NewName $Name -ErrorAction Stop

            if($Description)
            {
                Set-ADReplicationSite -Identity $Name -Description $Description
            }
        }
        else
        {
            if ($createOrUpdate)
            {
                # Update site
                Write-Verbose -Message ($script:localizedData.UpdateReplicationSite -f $Name)
                Set-ADReplicationSite -Identity $Name -Description $Description
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.AddReplicationSite -f $Name)

                $Params.Add('Name', $Name)
                $Params.Add('ErrorAction', 'Stop')
                if($Description)
                {
                    $Params.Add('Description', $Description)
                }

                New-ADReplicationSite @Params
            }
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

    .PARAMETER Description
        Specifies a description of the object. This parameter sets the value of
        the Description property for the object. The LDAP Display Name
        (ldapDisplayName) for this property is 'description'.
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
        $RenameDefaultFirstSiteName = $false,

        [Parameter()]
        [System.String]
        $Description
    )

    $currentConfiguration = Get-TargetResource -Name $Name
    $configurationCompliant = $true

    if ($currentConfiguration.Ensure -eq 'Absent')
    {
        # Site doesn't exist
        if ($currentConfiguration.Ensure -eq $Ensure)
        {
            # Site should not exist
            Write-Verbose -Message ($script:localizedData.ReplicationSiteInDesiredState -f $Name)
        }
        else
        {
            #Site should exist
            Write-Verbose -Message ($script:localizedData.ReplicationSiteNotInDesiredState -f $Name)
            $configurationCompliant = $false
        }
    }
    else {
        # Site Exists
        if ($currentConfiguration.Ensure -eq $Ensure)
        {
            # Site should exist
            if ($currentConfiguration.Description -ne $Description)
            {
                Write-Verbose -Message ($script:localizedData.ReplicationSiteNotInDesiredState -f $Name)
                $configurationCompliant = $false
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.ReplicationSiteInDesiredState -f $Name)
            }
        }
        else
        {
            # Site should not exist
            Write-Verbose -Message ($script:localizedData.ReplicationSiteNotInDesiredState -f $Name)
            $configurationCompliant = $false
        }
    }

    return $configurationCompliant
}
