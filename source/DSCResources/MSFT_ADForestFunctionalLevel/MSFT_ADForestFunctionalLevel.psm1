$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Returns the current functional level of the forest.

    .PARAMETER ForestIdentity
        Specifies the Active Directory forest to modify. You can identify a
        forest by its fully qualified domain name (FQDN), GUID, DNS host name,
        or NetBIOS name.

    .PARAMETER ForestMode
        Specifies the functional level for the Active Directory forest.

        Not used in Get-TargetResource.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestIdentity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows2008R2Forest', 'Windows2012Forest', 'Windows2012R2Forest', 'Windows2016Forest', 'Windows2025Forest')]
        [System.String]
        $ForestMode
    )

    Write-Verbose -Message (
        $script:localizedData.RetrievingForestMode -f $ForestIdentity
    )

    $getTargetResourceReturnValue = @{
        ForestIdentity = $ForestIdentity
        ForestMode     = $null
    }

    $forestObject = Get-ADForest -Identity $ForestIdentity -ErrorAction 'Stop'
    $getTargetResourceReturnValue['ForestMode'] = $forestObject.ForestMode

    return $getTargetResourceReturnValue
}

<#
    .SYNOPSIS
        Determines if the functional level is in the desired state.

    .PARAMETER ForestIdentity
        Specifies the Active Directory forest to modify. You can identify a
        forest by its fully qualified domain name (FQDN), GUID, DNS host name,
        or NetBIOS name.

    .PARAMETER ForestMode
        Specifies the functional level for the Active Directory forest.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestIdentity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows2008R2Forest', 'Windows2012Forest', 'Windows2012R2Forest', 'Windows2016Forest', 'Windows2025Forest')]
        [System.String]
        $ForestMode
    )

    Write-Verbose -Message (
        $script:localizedData.TestConfiguration -f $ForestIdentity
    )

    $compareTargetResourceStateResult = Compare-TargetResourceState @PSBoundParameters

    if ($false -in $compareTargetResourceStateResult.InDesiredState)
    {
        Write-Verbose -Message $script:localizedData.LevelNotInDesiredState

        $testTargetResourceReturnValue = $false
    }
    else
    {
        Write-Verbose -Message $script:localizedData.LevelInDesiredState

        $testTargetResourceReturnValue = $true
    }

    return $testTargetResourceReturnValue
}

<#
    .SYNOPSIS
        Sets the functional level on the Active Directory forest.

    .PARAMETER ForestIdentity
        Specifies the Active Directory forest to modify. You can identify a
        forest by its fully qualified domain name (FQDN), GUID, DNS host name,
        or NetBIOS name.

    .PARAMETER ForestMode
        Specifies the functional level for the Active Directory forest.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestIdentity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows2008R2Forest', 'Windows2012Forest', 'Windows2012R2Forest', 'Windows2016Forest', 'Windows2025Forest')]
        [System.String]
        $ForestMode
    )

    $compareTargetResourceStateResult = Compare-TargetResourceState @PSBoundParameters

    # Get all properties that are not in desired state.
    $propertiesNotInDesiredState = $compareTargetResourceStateResult | Where-Object -FilterScript {
        -not $_.InDesiredState
    }

    $forestModeProperty = $propertiesNotInDesiredState.Where( { $_.ParameterName -eq 'ForestMode' })

    if ($forestModeProperty)
    {
        Write-Verbose -Message (
            $script:localizedData.ForestModeUpdating -f $forestModeProperty.Actual, $ForestMode
        )

        $setADForestModeParameters = @{
            Identity   = $ForestIdentity
            ForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::$ForestMode
            Confirm    = $false
        }

        Set-ADForestMode @setADForestModeParameters
    }
}

<#
    .SYNOPSIS
        Compares the properties in the current state with the properties of the
        desired state and returns a hashtable with the comparison result.

    .PARAMETER ForestIdentity
        Specifies the Active Directory forest to modify. You can identify a
        forest by its fully qualified domain name (FQDN), GUID, DNS host name,
        or NetBIOS name.

    .PARAMETER ForestMode
       Specifies the functional level for the Active Directory forest.
#>
function Compare-TargetResourceState
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestIdentity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows2008R2Forest', 'Windows2012Forest', 'Windows2012R2Forest', 'Windows2016Forest', 'Windows2025Forest')]
        [System.String]
        $ForestMode
    )

    $getTargetResourceResult = Get-TargetResource @PSBoundParameters

    $compareTargetResourceStateParameters = @{
        CurrentValues = $getTargetResourceResult
        DesiredValues = $PSBoundParameters
        Properties    = @('ForestMode')
    }

    return Compare-ResourcePropertyState @compareTargetResourceStateParameters
}
