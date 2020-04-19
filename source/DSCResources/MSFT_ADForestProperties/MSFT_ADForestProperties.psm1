$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

$script:psModuleName = 'ActiveDirectory'

<#
    .SYNOPSIS
        Gets the current state of user principal name and service principal name suffixes in the forest.

    .PARAMETER Credential
        The user account credentials to use to perform this task.

    .PARAMETER ForestName
        The target Active Directory forest for the change.

    .PARAMETER ServicePrincipalNameSuffixToAdd
        The Service Principal Name Suffix(es) to add in the forest. Cannot be used with ServicePrincipalNameSuffix.

    .PARAMETER ServicePrincipalNameSuffixToRemove
        The Service Principal Name Suffix(es) to remove in the forest. Cannot be used with ServicePrincipalNameSuffix.

    .PARAMETER UserPrincipalNameSuffixToAdd
        The User Principal Name Suffix(es) to add in the forest. Cannot be used with UserPrincipalNameSuffix.

    .PARAMETER UserPrincipalNameSuffixToRemove
        The User Principal Name Suffix(es) to remove in the forest. Cannot be used with UserPrincipalNameSuffix.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Assert-Module                 | DscResource.Common
            New-CimCredentialInstance     | ActiveDirectoryDsc.Common
            Get-ADForest                  | ActiveDirectory
            Get-ADObject                  | ActiveDirectory
            Get-ADRootDSE                 | ActiveDirectory
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestName,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffix,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffixToAdd,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffixToRemove,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffix,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffixToAdd,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffixToRemove
    )

    Assert-Module -ModuleName $script:psModuleName

    Write-Verbose -Message ($script:localizedData.GetForest -f $ForestName)
    $forest = Get-ADForest -Identity $ForestName

    $configurationNamingContext = (Get-ADRootDSE).configurationNamingContext
    $identity = "CN=Directory Service,CN=Windows NT,CN=Services,$configurationNamingContext"
    $tombstoneLifetime = (Get-ADObject -Identity $identity -Partition $configurationNamingContext `
            -Properties 'tombstonelifetime').tombstonelifetime

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        $cimCredential = New-CimCredentialInstance -Credential $Credential
    }
    else
    {
        $cimCredential = $null
    }

    return @{
        Credential                         = $cimCredential
        ForestName                         = $forest.Name
        ServicePrincipalNameSuffix         = [System.Array] $forest.SpnSuffixes
        ServicePrincipalNameSuffixToAdd    = [System.Array] $ServicePrincipalNameSuffixToAdd
        ServicePrincipalNameSuffixToRemove = [System.Array] $ServicePrincipalNameSuffixToRemove
        TombstoneLifetime                  = $tombstoneLifetime
        UserPrincipalNameSuffix            = [System.Array] $forest.UpnSuffixes
        UserPrincipalNameSuffixToAdd       = [System.Array] $UserPrincipalNameSuffixToAdd
        UserPrincipalNameSuffixToRemove    = [System.Array] $UserPrincipalNameSuffixToRemove
    }
}

<#
    .SYNOPSIS
        Tests the current state of user principal name and service principal name suffixes in the forest.

    .PARAMETER Credential
        The user account credentials to use to perform this task.

    .PARAMETER ForestName
        The target Active Directory forest for the change.

    .PARAMETER ServicePrincipalNameSuffix
        The Service Principal Name Suffix(es) to be explicitly defined in the forest and replace existing
        members. Cannot be used with ServicePrincipalNameSuffixToAdd or ServicePrincipalNameSuffixToRemove.

    .PARAMETER ServicePrincipalNameSuffixToAdd
        The Service Principal Name Suffix(es) to add in the forest. Cannot be used with ServicePrincipalNameSuffix.

    .PARAMETER ServicePrincipalNameSuffixToRemove
        The Service Principal Name Suffix(es) to remove in the forest. Cannot be used with ServicePrincipalNameSuffix.

    .PARAMETER TombstoneLifetime
        Specifies the AD Tombstone lifetime which determines how long deleted items exist in Active Directory before
        they are purged.

    .PARAMETER UserPrincipalNameSuffix
        The User Principal Name Suffix(es) to be explicitly defined in the forest and replace existing
        members. Cannot be used with UserPrincipalNameSuffixToAdd or UserPrincipalNameSuffixToRemove.

    .PARAMETER UserPrincipalNameSuffixToAdd
        The User Principal Name Suffix(es) to add in the forest. Cannot be used with UserPrincipalNameSuffix.

    .PARAMETER UserPrincipalNameSuffixToRemove
        The User Principal Name Suffix(es) to remove in the forest. Cannot be used with UserPrincipalNameSuffix.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Assert-MemberParameters       | ActiveDirectoryDsc.Common
            Assert-Module                 | DscResource.Common
            Test-Members                  | ActiveDirectoryDsc.Common
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestName,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffix,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffixToAdd,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffixToRemove,

        [Parameter()]
        [System.Int32]
        $TombstoneLifetime,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffix,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffixToAdd,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffixToRemove
    )

    Assert-Module -ModuleName $script:psModuleName

    $inDesiredState = $true

    $targetResource = Get-TargetResource -ForestName $ForestName

    # Validate parameters before we even attempt to retrieve anything
    $assertMemberParameters = @{}

    if ($PSBoundParameters.ContainsKey('ServicePrincipalNameSuffix') -and
        -not [system.string]::IsNullOrEmpty($ServicePrincipalNameSuffix))
    {
        $assertMemberParameters['Members'] = $ServicePrincipalNameSuffix
    }

    if ($PSBoundParameters.ContainsKey('ServicePrincipalNameSuffixToAdd') -and
        -not [system.string]::IsNullOrEmpty($ServicePrincipalNameSuffixToAdd))
    {
        $assertMemberParameters['MembersToInclude'] = $ServicePrincipalNameSuffixToAdd
    }

    if ($PSBoundParameters.ContainsKey('ServicePrincipalNameSuffixToRemove') -and
        -not [system.string]::IsNullOrEmpty($ServicePrincipalNameSuffixToRemove))
    {
        $assertMemberParameters['MembersToExclude'] = $ServicePrincipalNameSuffixToRemove
    }

    Assert-MemberParameters @assertMemberParameters -ErrorAction Stop

    if (-not ( Test-Members @assertMemberParameters -ExistingMembers ($targetResource.ServicePrincipalNameSuffix -split ',') ))
    {
        Write-Verbose -Message ($script:localizedData.ForestSpnSuffixNotInDesiredState -f $ForestName)
        $inDesiredState = $false
    }

    $assertMemberParameters = @{}

    if ($PSBoundParameters.ContainsKey('UserPrincipalNameSuffix') -and
        -not [system.string]::IsNullOrEmpty($UserPrincipalNameSuffix))
    {
        $assertMemberParameters['Members'] = $UserPrincipalNameSuffix
    }

    if ($PSBoundParameters.ContainsKey('UserPrincipalNameSuffixToAdd') -and
        -not [system.string]::IsNullOrEmpty($UserPrincipalNameSuffixToAdd))
    {
        $assertMemberParameters['MembersToInclude'] = $UserPrincipalNameSuffixToAdd
    }

    if ($PSBoundParameters.ContainsKey('UserPrincipalNameSuffixToRemove') -and
        -not [system.string]::IsNullOrEmpty($UserPrincipalNameSuffixToRemove))
    {
        $assertMemberParameters['MembersToExclude'] = $UserPrincipalNameSuffixToRemove
    }

    Assert-MemberParameters @assertMemberParameters -ErrorAction Stop

    if (-not ( Test-Members @assertMemberParameters -ExistingMembers ($targetResource.UserPrincipalNameSuffix -split ',') ))
    {
        Write-Verbose -Message ($script:localizedData.ForestUpnSuffixNotInDesiredState -f $ForestName)

        $inDesiredState = $false
    }

    if ($PSBoundParameters.ContainsKey('TombstoneLifetime'))
    {
        if ($TombstoneLifetime -ne $targetResource.TombstoneLifetime)
        {
            Write-Verbose -Message ($script:localizedData.TombstoneLifetimeNotInDesiredState -f
                $ForestName, $targetResource.TombstoneLifetime, $TombstoneLifetime)

            $inDesiredState = $false
        }
    }

    return $inDesiredState
}

<#
    .SYNOPSIS
        Sets the user principal name and service principal name suffixes in the forest.

    .PARAMETER Credential
        The user account credentials to use to perform this task.

    .PARAMETER ForestName
        The target Active Directory forest for the change.

    .PARAMETER ServicePrincipalNameSuffix
        The Service Principal Name Suffix(es) to be explicitly defined in the forest and replace existing
        members. Cannot be used with ServicePrincipalNameSuffixToAdd or ServicePrincipalNameSuffixToRemove.

    .PARAMETER ServicePrincipalNameSuffixToAdd
        The Service Principal Name Suffix(es) to add in the forest. Cannot be used with ServicePrincipalNameSuffix.

    .PARAMETER ServicePrincipalNameSuffixToRemove
        The Service Principal Name Suffix(es) to remove in the forest. Cannot be used with ServicePrincipalNameSuffix.

    .PARAMETER TombstoneLifetime
        Specifies the AD Tombstone lifetime which determines how long deleted items exist in Active Directory before
        they are purged.

    .PARAMETER UserPrincipalNameSuffix
        The User Principal Name Suffix(es) to be explicitly defined in the forest and replace existing
        members. Cannot be used with UserPrincipalNameSuffixToAdd or UserPrincipalNameSuffixToRemove.

    .PARAMETER UserPrincipalNameSuffixToAdd
        The User Principal Name Suffix(es) to add in the forest. Cannot be used with UserPrincipalNameSuffix.

    .PARAMETER UserPrincipalNameSuffixToRemove
        The User Principal Name Suffix(es) to remove in the forest. Cannot be used with UserPrincipalNameSuffix.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Assert-Module                 | DscResource.Common
            New-InvalidOperationException | DscResource.Common
            Get-ADRootDSE                 | ActiveDirectory
            Set-ADForest                  | ActiveDirectory
            Set-ODObject                  | ActiveDirectory
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ForestName,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffix,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffixToAdd,

        [Parameter()]
        [System.String[]]
        $ServicePrincipalNameSuffixToRemove,

        [Parameter()]
        [System.Int32]
        $TombstoneLifetime,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffix,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffixToAdd,

        [Parameter()]
        [System.String[]]
        $UserPrincipalNameSuffixToRemove
    )

    Assert-Module -ModuleName $script:psModuleName

    $targetResource = Get-TargetResource -ForestName $ForestName

    $setADForestParameters = @{}

    # add ServicePrincipalName parameter
    if ($PSBoundParameters.ContainsKey('ServicePrincipalNameSuffix'))
    {
        if (-not [system.string]::IsNullOrEmpty($ServicePrincipalNameSuffix))
        {
            $setADForestParameters['SpnSuffixes'] = @{
                Replace = $($ServicePrincipalNameSuffix)
            }

            Write-Verbose -Message ($script:localizedData.ReplaceSpnSuffix -f
                ($ServicePrincipalNameSuffix -join ', '), $ForestName)
        }
        else
        {
            $setADForestParameters['SpnSuffixes'] = $null
            Write-Verbose -Message ($script:localizedData.ClearSpnSuffix -f $ForestName)
        }
    }

    if ($PSBoundParameters.ContainsKey('ServicePrincipalNameSuffixToAdd') -and
        -not [system.string]::IsNullOrEmpty($ServicePrincipalNameSuffixToAdd))
    {
        $setADForestParameters['SpnSuffixes'] = @{
            Add = $($ServicePrincipalNameSuffixToAdd)
        }

        Write-Verbose -Message ($script:localizedData.AddSpnSuffix -f
            ($ServicePrincipalNameSuffixToAdd -join ', '), $ForestName)
    }

    if ($PSBoundParameters.ContainsKey('ServicePrincipalNameSuffixToRemove') -and
        -not [system.string]::IsNullOrEmpty($ServicePrincipalNameSuffixToRemove))
    {
        if ($setADForestParameters['SpnSuffixes'])
        {
            $setADForestParameters['SpnSuffixes']['Remove'] = $($ServicePrincipalNameSuffixToRemove)
        }
        else
        {
            $setADForestParameters['SpnSuffixes'] = @{
                Remove = $($ServicePrincipalNameSuffixToRemove)
            }
        }

        Write-Verbose -Message ($script:localizedData.RemoveSpnSuffix -f
            ($ServicePrincipalNameSuffixToRemove -join ', '), $ForestName)
    }

    # add UserPrincipalName parameter
    if ($PSBoundParameters.ContainsKey('UserPrincipalNameSuffix'))
    {
        if (-not [system.string]::IsNullOrEmpty($UserPrincipalNameSuffix))
        {
            $setADForestParameters['UpnSuffixes'] = @{
                Replace = $($UserPrincipalNameSuffix)
            }

            Write-Verbose -Message ($script:localizedData.ReplaceUpnSuffix -f
                ($UserPrincipalNameSuffix -join ', '), $ForestName)
        }
        else
        {
            $setADForestParameters['UpnSuffixes'] = $null
            Write-Verbose -Message ($script:localizedData.ClearUpnSuffix -f $ForestName)
        }
    }

    if ($PSBoundParameters.ContainsKey('UserPrincipalNameSuffixToAdd') -and
        -not [system.string]::IsNullOrEmpty($UserPrincipalNameSuffixToAdd))
    {
        $setADForestParameters['UpnSuffixes'] = @{
            Add = $($UserPrincipalNameSuffixToAdd)
        }

        Write-Verbose -Message ($script:localizedData.AddUpnSuffix -f
            ($UserPrincipalNameSuffixToAdd -join ', '), $ForestName)
    }

    if ($PSBoundParameters.ContainsKey('UserPrincipalNameSuffixToRemove') -and
        -not [system.string]::IsNullOrEmpty($UserPrincipalNameSuffixToRemove))
    {
        if ($setADForestParameters['UpnSuffixes'])
        {
            $setADForestParameters['UpnSuffixes']['Remove'] = $($UserPrincipalNameSuffixToRemove)
        }
        else
        {
            $setADForestParameters['UpnSuffixes'] = @{
                Remove = $($UserPrincipalNameSuffixToRemove)
            }
        }

        Write-Verbose -Message ($script:localizedData.RemoveUpnSuffix -f
            ($UserPrincipalNameSuffixToRemove -join ', '), $ForestName)
    }

    # Only run Set-ADForest if a value needs updating
    if ($setADForestParameters.count -gt 0)
    {
        if ($PSBoundParameters.ContainsKey('Credential'))
        {
            $setADForestParameters['Credential'] = $Credential
        }

        $setADForestParameters['Identity'] = $ForestName

        Set-ADForest @setADForestParameters
    }

    if ($PSBoundParameters.ContainsKey('TombstoneLifetime') -and
        $TombstoneLifetime -ne $targetResource.TombstoneLifetime)
    {
        Write-Verbose -Message ($script:localizedData.SetTombstoneLifetime -f
            $TombstoneLifetime, $ForestName)

        $configurationNamingContext = (Get-ADRootDSE).configurationNamingContext
        $identity = "CN=Directory Service,CN=Windows NT,CN=Services,$configurationNamingContext"

        $setADObjectParameters = @{
            Identity  = $identity
            Partition = $configurationNamingContext
            Replace   = @{
                tombstonelifetime = $TombstoneLifetime
            }
        }

        if ($PSBoundParameters.ContainsKey('Credential'))
        {
            $setADObjectParameters['Credential'] = $Credential
        }

        try
        {
            Set-ADObject @setADObjectParameters
        }
        catch
        {
            $errorMessage = ($script:localizedData.SetTombstoneLifetimeError -f
                $TombstoneLifetime, $ForestName)
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }
    }
}
