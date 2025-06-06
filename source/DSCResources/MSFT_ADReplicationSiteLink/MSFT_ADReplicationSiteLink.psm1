$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Gets the current configuration on an AD Replication Site Link.

    .PARAMETER Name
        Specifies the name of the AD Replication Site Link.

    .PARAMETER SitesExcluded
        Specifies the list of sites to remove from a site link.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String[]]
        $SitesExcluded
    )

    try
    {
        $siteLink = Get-ADReplicationSiteLink -Identity $Name -Properties 'Description', 'Options'
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message ($script:localizedData.SiteLinkNotFound -f $Name)

        $siteLink = $null
    }
    catch
    {
        $errorMessage = $script:localizedData.GetSiteLinkUnexpectedError -f $Name
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }

    if ($null -ne $siteLink)
    {
        $siteCommonNames = @()

        if ($siteLink.SitesIncluded)
        {
            foreach ($siteDN in $siteLink.SitesIncluded)
            {
                $siteCommonNames += Resolve-SiteLinkName -SiteName $siteDn
            }
        }

        if ($null -eq $siteLink.Options)
        {
            $siteLinkOptions = Get-EnabledOptions -OptionValue 0
        }
        else
        {
            $siteLinkOptions = Get-EnabledOptions -OptionValue $siteLink.Options
        }

        $sitesExcludedEvaluated = $SitesExcluded |
            Where-Object -FilterScript { $_ -notin $siteCommonNames }

        $returnValue = @{
            Name                          = $Name
            Cost                          = $siteLink.Cost
            Description                   = $siteLink.Description
            ReplicationFrequencyInMinutes = $siteLink.ReplicationFrequencyInMinutes
            SitesIncluded                 = $siteCommonNames
            SitesExcluded                 = $sitesExcludedEvaluated
            OptionChangeNotification      = $siteLinkOptions.USE_NOTIFY
            OptionTwoWaySync              = $siteLinkOptions.TWOWAY_SYNC
            OptionDisableCompression      = $siteLinkOptions.DISABLE_COMPRESSION
            Ensure                        = 'Present'
        }
    }
    else
    {
        $returnValue = @{
            Name                          = $Name
            Cost                          = $null
            Description                   = $null
            ReplicationFrequencyInMinutes = $null
            SitesIncluded                 = $null
            SitesExcluded                 = $SitesExcluded
            OptionChangeNotification      = $false
            OptionTwoWaySync              = $false
            OptionDisableCompression      = $false
            Ensure                        = 'Absent'
        }
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Sets the desired configuration on an AD Replication Site Link.

    .PARAMETER Name
        Specifies the name of the AD Replication Site Link.

    .PARAMETER Cost
        Specifies the cost to be placed on the site link.

    .PARAMETER Description
        Specifies a description of the object.

    .PARAMETER ReplicationFrequencyInMinutes
        Specifies the frequency (in minutes) for which replication will occur where this site link is in use between sites.

    .PARAMETER SitesIncluded
        Specifies the list of sites included in the site link.

    .PARAMETER SitesExcluded
        Specifies the list of sites to remove from a site link.

    .PARAMETER OptionChangeNotification
        Enables or disables Change Notification Replication on a site link. Default value is $false.

    .PARAMETER OptionTwoWaySync
        Two Way Sync on a site link. Default value is $false.

    .PARAMETER OptionDisableCompression
        Enables or disables Compression on a site link. Default value is $false.

    .PARAMETER Ensure
        Specifies if the site link is created or deleted.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Int32]
        $Cost,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.Int32]
        $ReplicationFrequencyInMinutes,

        [Parameter()]
        [System.String[]]
        $SitesIncluded,

        [Parameter()]
        [System.String[]]
        $SitesExcluded,

        [Parameter()]
        [System.Boolean]
        $OptionChangeNotification,

        [Parameter()]
        [System.Boolean]
        $OptionTwoWaySync,

        [Parameter()]
        [System.Boolean]
        $OptionDisableCompression,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    if ($Ensure -eq 'Present')
    {
        # Resource should be Present
        $currentADSiteLink = Get-TargetResource -Name $Name

        <#
            Since Set and New have different parameters we have to test if the site link exists to determine what
            cmdlet we need to use.
        #>
        if ( $currentADSiteLink.Ensure -eq 'Absent' )
        {
            # Resource is Absent

            # Modify parameters for splatting to New-ADReplicationSiteLink.
            $newADReplicationSiteLinkParameters = @{} + $PSBoundParameters
            $newADReplicationSiteLinkParameters.Remove('Ensure')
            $newADReplicationSiteLinkParameters.Remove('SitesExcluded')
            $newADReplicationSiteLinkParameters.Remove('OptionChangeNotification')
            $newADReplicationSiteLinkParameters.Remove('OptionTwoWaySync')
            $newADReplicationSiteLinkParameters.Remove('OptionDisableCompression')
            $newADReplicationSiteLinkParameters.Remove('Verbose')

            $optionsValue = ConvertTo-EnabledOptions -OptionChangeNotification $optionChangeNotification `
                -OptionTwoWaySync $optionTwoWaySync -OptionDisableCompression $optionDisableCompression

            if ($optionsValue -gt 0)
            {
                $newADReplicationSiteLinkParameters['OtherAttributes'] = @{
                    options = $optionsValue
                }
            }

            Write-Verbose -Message ($script:localizedData.NewSiteLink -f $Name)
            New-ADReplicationSiteLink @newADReplicationSiteLinkParameters
        }
        else
        {
            # Resource is Present

            $setADReplicationSiteLinkParameters = @{}
            $setADReplicationSiteLinkParameters['Identity'] = $Name

            $replaceParameters = @{}

            # now we have to determine if we need to add or remove sites from SitesIncluded.
            if (-not (Test-Members -ExistingMembers $currentADSiteLink.SitesIncluded `
                        -MembersToInclude $SitesIncluded -MembersToExclude $SitesExcluded))
            {
                # build the SitesIncluded hashtable.
                $sitesIncludedParameters = @{}
                if ($SitesExcluded)
                {
                    Write-Verbose -Message ($script:localizedData.RemovingSites -f $($SitesExcluded -join ', '), $Name)

                    <#
                    Wrapped in $() as we were getting some weird results without it,
                    results were not being added into Hashtable as strings.
                #>
                    $sitesIncludedParameters.Add('Remove', $($SitesExcluded))
                }

                if ($SitesIncluded)
                {
                    Write-Verbose -Message ($script:localizedData.AddingSites -f $($SitesIncluded -join ', '), $Name)

                    <#
                    Wrapped in $() as we were getting some weird results without it,
                    results were not being added into Hashtable as strings.
                #>
                    $sitesIncludedParameters.Add('Add', $($SitesIncluded))
                }

                if ($null -ne $($sitesIncludedParameters.Keys))
                {
                    $setADReplicationSiteLinkParameters['SitesIncluded'] = $sitesIncludedParameters
                }
            }

            if ($PSBoundParameters.ContainsKey('Cost') -and $Cost -ne $currentADSiteLink.Cost)
            {
                Write-Verbose -Message ($script:localizedData.SettingProperty -f
                    'Cost', $Cost, $Name)
                $setADReplicationSiteLinkParameters['Cost'] = $Cost
            }

            if ($PSBoundParameters.ContainsKey('Description') -and $Description -ne $currentADSiteLink.Description)
            {
                Write-Verbose -Message ($script:localizedData.SettingProperty -f
                    'Description', $Description, $Name)
                $setADReplicationSiteLinkParameters['Description'] = $Description
            }

            if ($PSBoundParameters.ContainsKey('ReplicationFrequencyInMinutes') -and
                $ReplicationFrequencyInMinutes -ne $currentADSiteLink.ReplicationFrequencyInMinutes)
            {
                Write-Verbose -Message ($script:localizedData.SettingProperty -f
                    'ReplicationFrequencyInMinutes', $ReplicationFrequencyInMinutes, $Name)
                $setADReplicationSiteLinkParameters['ReplicationFrequencyInMinutes'] = $ReplicationFrequencyInMinutes
            }

            if ($PSBoundParameters.ContainsKey('OptionChangeNotification') -and
                $OptionChangeNotification -ne $currentADSiteLink.OptionChangeNotification)
            {
                Write-Verbose -Message ($script:localizedData.SettingProperty -f
                    'OptionChangeNotification', $OptionChangeNotification, $Name)
                $desiredChangeNotification = $OptionChangeNotification
            }
            else
            {
                $desiredChangeNotification = $currentADSiteLink.OptionChangeNotification
            }

            if ($PSBoundParameters.ContainsKey('OptionTwoWaySync') -and
                $OptionTwoWaySync -ne $currentADSiteLink.OptionTwoWaySync)
            {
                Write-Verbose -Message ($script:localizedData.SettingProperty -f
                    'TwoWaySync', $OptionTwoWaySync, $Name)
                $desiredTwoWaySync = $OptionTwoWaySync
            }
            else
            {
                $desiredTwoWaySync = $currentADSiteLink.OptionTwoWaySync
            }

            if ($PSBoundParameters.ContainsKey('OptionDisableCompression') -and
                $OptionDisableCompression -ne $currentADSiteLink.OptionDisableCompression)
            {
                Write-Verbose -Message ($script:localizedData.SettingProperty -f
                    'OptionDisableCompression', $OptionDisableCompression, $Name)
                $desiredDisableCompression = $OptionDisableCompression
            }
            else
            {
                $desiredDisableCompression = $currentADSiteLink.OptionDisableCompression
            }

            $currentOptionsValue = ConvertTo-EnabledOptions `
                -OptionChangeNotification $currentADSiteLink.OptionChangeNotification `
                -OptionTwoWaySync $currentADSiteLink.OptionTwoWaySync `
                -OptionDisableCompression $currentADSiteLink.OptionDisableCompression
            $desiredOptionsValue = ConvertTo-EnabledOptions `
                -OptionChangeNotification $desiredChangeNotification `
                -OptionTwoWaySync $desiredTwoWaySync `
                -OptionDisableCompression $desiredDisableCompression

            if ($currentOptionsValue -ne $desiredOptionsValue)
            {
                if ($desiredoptionsValue -eq 0)
                {
                    $setADReplicationSiteLinkParameters.Add('Clear', 'Options')
                }
                else
                {
                    $replaceParameters.Add('Options', $desiredOptionsValue)
                }
            }

            if ($replaceParameters.Count -gt 0)
            {
                $setADReplicationSiteLinkParameters.Add('Replace', $replaceParameters)
            }

            Set-ADReplicationSiteLink @setADReplicationSiteLinkParameters
        }
    }
    else
    {
        # Resource should be absent

        Write-Verbose -Message ($script:localizedData.RemoveSiteLink -f $Name)

        Remove-ADReplicationSiteLink -Identity $Name
    }
}

<#
    .SYNOPSIS
        Tests if the AD Replication Site Link is in a desired state.

    .PARAMETER Name
        Specifies the name of the AD Replication Site Link.

    .PARAMETER Cost
        Specifies the cost to be placed on the site link.

    .PARAMETER Description
        Specifies a description of the object.

    .PARAMETER ReplicationFrequencyInMinutes
        Specifies the frequency (in minutes) for which replication will occur where this site link is in use between sites.

    .PARAMETER SitesIncluded
        Specifies the list of sites included in the site link.

    .PARAMETER SitesExcluded
        Specifies the list of sites to remove from a site link.

    .PARAMETER OptionChangeNotification
        Enables or disables Change Notification Replication on a site link. Default value is $false.

    .PARAMETER OptionTwoWaySync
        Two Way Sync on a site link. Default value is $false.

    .PARAMETER OptionDisableCompression
        Enables or disables Compression on a site link. Default value is $false.

    .PARAMETER Ensure
        Specifies if the site link is created or deleted.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Int32]
        $Cost,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.Int32]
        $ReplicationFrequencyInMinutes,

        [Parameter()]
        [System.String[]]
        $SitesIncluded,

        [Parameter()]
        [System.String[]]
        $SitesExcluded,

        [Parameter()]
        [System.Boolean]
        $OptionChangeNotification,

        [Parameter()]
        [System.Boolean]
        $OptionTwoWaySync,

        [Parameter()]
        [System.Boolean]
        $OptionDisableCompression,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    $parameters = @{} + $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')
    $parameters.Remove('Debug')

    # Add parameters with default values as they may not be explicitly passed
    $parameters['OptionChangeNotification'] = $OptionChangeNotification
    $parameters['OptionTwoWaySync'] = $OptionTwoWaySync
    $parameters['OptionDisableCompression'] = $OptionDisableCompression

    $targetResource = Get-TargetResource -Name $Name

    $inDesiredState = $true

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        if ($Ensure -eq 'Present')
        {
            # Resource Should be Present
            foreach ($parameter in $parameters.Keys)
            {
                if ($parameter -eq 'SitesIncluded')
                {
                    foreach ($desiredIncludedSite in $SitesIncluded)
                    {
                        if ($desiredIncludedSite -notin $targetResource.SitesIncluded)
                        {
                            Write-Verbose -Message ($script:localizedData.SiteNotFound -f
                                $desiredIncludedSite, $($targetResource.SitesIncluded -join ', '))
                            $inDesiredState = $false
                        }
                    }
                }
                elseif ($parameter -eq 'SitesExcluded')
                {
                    foreach ($desiredExcludedSite in $SitesExcluded)
                    {
                        if ($desiredExcludedSite -in $targetResource.SitesIncluded)
                        {
                            Write-Verbose -Message ($script:localizedData.SiteFoundInExcluded -f
                                $desiredExcludedSite, $($targetResource.SitesIncluded -join ', '))
                            $inDesiredState = $false
                        }
                    }
                }
                elseif ($parameters[$parameter] -ne $targetResource[$parameter])
                {
                    Write-Verbose -Message ($script:localizedData.PropertyNotInDesiredState -f
                        $parameter, $targetResource[$parameter], $parameters[$parameter])
                    $inDesiredState = $false
                }
            }

            if ($inDesiredState)
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.ADSiteInDesiredState -f $Name)
            }
            else
            {
                # Resource is not in the desired state
                Write-Verbose -Message ($script:localizedData.ADSiteNotInDesiredState -f $Name)
            }
        }
        else
        {
            # Resource Should be Absent
            Write-Verbose -Message ($script:localizedData.ADSiteIsPresentButShouldBeAbsent -f $Name)

            $inDesiredState = $false
        }
    }
    else
    {
        # Resource is Absent
        if ($Ensure -eq 'Present')
        {
            # Resource Should be Present
            Write-Verbose -Message ($script:localizedData.ADSiteIsAbsentButShouldBePresent -f $Name)

            $inDesiredState = $false
        }
        else
        {
            # Resource should be Absent
            Write-Verbose ($script:localizedData.ADSiteInDesiredState -f $Name)

            $inDesiredState = $true
        }
    }

    return $inDesiredState
}

<#
    .SYNOPSIS
        Resolves the AD replication site link distinguished names to short names

    .PARAMETER SiteName
        Specifies the distinguished name of a AD replication site link

    .EXAMPLE
        PS C:\> Resolve-SiteLinkName -SiteName 'CN=Site1,CN=Sites,CN=Configuration,DC=contoso,DC=com'
        Site1
#>
function Resolve-SiteLinkName
{
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $SiteName
    )

    $adSite = Get-ADReplicationSite -Identity $SiteName

    return $adSite.Name
}

<#
    .SYNOPSIS
        Calculates the options enabled on a Site Link

    .PARAMETER OptionValue
        The value of currently enabled options
#>
function Get-EnabledOptions
{
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $OptionValue
    )

    $returnValue = @{
        USE_NOTIFY          = $false
        TWOWAY_SYNC         = $false
        DISABLE_COMPRESSION = $false
    }

    if (1 -band $optionValue)
    {
        $returnValue.USE_NOTIFY = $true
    }

    if (2 -band $optionValue)
    {
        $returnValue.TWOWAY_SYNC = $true
    }

    if (4 -band $optionValue)
    {
        $returnValue.DISABLE_COMPRESSION = $true
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Calculates the options value for the given choices

    .PARAMETER OptionChangeNotification
        Enable/Disable Change notification replication

    .PARAMETER OptionTwoWaySync
        Enable/Disable Two Way sync

    .PARAMETER OptionDisableCompression
        Enable/Disable Compression
#>
function ConvertTo-EnabledOptions
{
    [OutputType([System.Int32])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.Boolean]
        $OptionChangeNotification,

        [Parameter()]
        [System.Boolean]
        $OptionTwoWaySync,

        [Parameter()]
        [System.Boolean]
        $OptionDisableCompression
    )

    $returnValue = 0

    if ($OptionChangeNotification)
    {
        $returnValue = $returnValue + 1
    }

    if ($OptionTwoWaySync)
    {
        $returnValue = $returnValue + 2
    }

    if ($OptionDisableCompression)
    {
        $returnValue = $returnValue + 4
    }

    return $returnValue
}

Export-ModuleMember -Function *-TargetResource
