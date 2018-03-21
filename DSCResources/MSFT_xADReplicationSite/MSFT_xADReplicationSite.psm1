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
    $replicationSite = Get-ADReplicationSite -Filter { Name -eq $Name }

    if ($null -eq $replicationSite)
    {
        $returnValue = @{
            Ensure                     = 'Absent'
            Name                       = $Name
            RenameDefaultFirstSiteName = ''
        }
    }
    else
    {
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
            Write-Verbose "Add the replication site 'Default-First-Site-Name' to '$Name'"

            Rename-ADObject -Identity $defaultFirstSiteName.DistinguishedName -NewName $Name -ErrorAction Stop
        }
        else
        {
            Write-Verbose "Add the replication site '$Name'"

            New-ADReplicationSite -Name $Name -ErrorAction Stop
        }
    }

    if ($Ensure -eq 'Absent')
    {
        Write-Verbose "Remove the replication site '$Name'"

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

    return $currentConfiguration.Ensure -eq $Ensure
}
