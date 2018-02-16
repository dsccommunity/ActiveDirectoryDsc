<#
    .SYNOPSIS
        Returns the current state of the replication subnet.

    .PARAMETER Name
        The name of the AD replication subnet, e.g. 10.0.0.0/24.

    .PARAMETER Site
        The name of the assigned AD replication site, e.g. Default-First-Site-Name.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Site
    )

    # Get the replication subnet filtered by it's name. If the subnet is not
    # present, the command will return $null.
    $replicationSubnet = Get-ADReplicationSubnet -Filter { Name -eq $Name }

    if ($null -eq $replicationSubnet)
    {
        # Replication subnet not found, return absent.
        $returnValue = @{
            Ensure   = 'Absent'
            Name     = $Name
            Site     = ''
            Location = ''
        }
    }
    else
    {
        # Get the name of the replication site, if it's not empty.
        $replicationSiteName = ''
        if ($null -ne $replicationSubnet.Site)
        {
            $replicationSiteName = Get-ADObject -Identity $replicationSubnet.Site | Select-Object -ExpandProperty 'Name'
        }

        # Replication subnet not found, return present.
        $returnValue = @{
            Ensure   = 'Present'
            Name     = $Name
            Site     = $replicationSiteName
            Location = [String] $replicationSubnet.Location
        }
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Add, remove or update the replication subnet.

    .PARAMETER Ensure
        Specifies if the AD replication subnet should be added or remove. Default value is 'Present'.

    .PARAMETER Name
        The name of the AD replication subnet, e.g. 10.0.0.0/24.

    .PARAMETER Site
        The name of the assigned AD replication site, e.g. Default-First-Site-Name.

    .PARAMETER Location
        The location for the AD replication site. Default value is empty.
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
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Site,

        [Parameter()]
        [System.String]
        $Location = ''
    )

    # Get the replication subnet filtered by it's name. If the subnet is not
    # present, the command will return $null.
    $replicationSubnet = Get-ADReplicationSubnet -Filter { Name -eq $Name }

    if ($Ensure -eq 'Present')
    {
        # Add the replication subnet, if it does not exist.
        if ($null -eq $replicationSubnet)
        {
            Write-Verbose "Create the replication subnet $Name"

            $replicationSubnet = New-ADReplicationSubnet -Name $Name -Site $Site -PassThru
        }

        # Get the name of the replication site, if it's not empty and update the
        # site if it's not vaild.
        if ($null -ne $replicationSubnet.Site)
        {
            $replicationSiteName = Get-ADObject -Identity $replicationSubnet.Site | Select-Object -ExpandProperty 'Name'
        }
        if ($replicationSiteName -ne $Site)
        {
            Write-Verbose "Set on replication subnet $Name the site to $Site"

            Set-ADReplicationSubnet -Identity $replicationSubnet.DistinguishedName -Site $Site -PassThru
        }

        # Update the location, if it's not valid. Ensure an empty location
        # string is converted to $null, because the Set-ADReplicationSubnet does
        # not accept an empty string for the location, but $null.
        $nullableLocation = $Location
        if ([String]::IsNullOrEmpty($Location))
        {
            $nullableLocation = $null
        }
        if ($replicationSubnet.Location -ne $nullableLocation)
        {
            Write-Verbose "Set on replication subnet $Name the location to $nullableLocation"

            Set-ADReplicationSubnet -Identity $replicationSubnet.DistinguishedName -Location $nullableLocation -PassThru
        }
    }

    if ($Ensure -eq 'Absent')
    {
        # Remove the replication subnet, if it exists.
        if ($null -ne $replicationSubnet)
        {
            Write-Verbose "Remove the replication subnet $Name"

            Remove-ADReplicationSubnet -Identity $replicationSubnet.DistinguishedName -Confirm:$false
        }
    }
}

<#
    .SYNOPSIS
        Test the replication subnet.

    .PARAMETER Ensure
        Specifies if the AD replication subnet should be added or remove. Default value is 'Present'.

    .PARAMETER Name
        The name of the AD replication subnet, e.g. 10.0.0.0/24.

    .PARAMETER Site
        The name of the assigned AD replication site, e.g. Default-First-Site-Name.

    .PARAMETER Location
        The location for the AD replication site. Default value is empty.
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
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Site,

        [Parameter()]
        [System.String]
        $Location = ''
    )

    $currentConfiguration = Get-TargetResource -Name $Name -Site $Site

    $desiredConfigurationMatch = $currentConfiguration.Ensure -eq $Ensure

    if ($Ensure -eq 'Present')
    {
        $desiredConfigurationMatch = $desiredConfigurationMatch -and
                                     $currentConfiguration.Site -eq $Site -and
                                     $currentConfiguration.Location -eq $Location
    }

    return $desiredConfigurationMatch
}
