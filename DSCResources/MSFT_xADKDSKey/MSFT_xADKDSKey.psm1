## Import the common AD functions
$adCommonFunctions = Join-Path `
    -Path (Split-Path -Path $PSScriptRoot -Parent) `
    -ChildPath '\MSFT_xADCommon\MSFT_xADCommon.psm1'
Import-Module -Name $adCommonFunctions

# Localized messages
data LocalizedData
{
    # culture='en-US'
    ConvertFrom-StringData @'
        RetrievingKDSRootKey               = Retrieving KDS Root Key with effective date of '{0}'.
        RetrievingKDSRootKeyError          = There was an error retrieving the KDS Root Key with effective date of '{0}'.
        AddingKDSRootKey                   = Creating KDS Root Key with the effective date of '{0}'.
        AddingKDSRootKeyDateInPast         = Effective date is in the past and the 'UnsafeEffectiveTime' is set to Enabled. Adding KDS Root Key with the effective date of '{0}', overriding 10 hour safety measure for domain controller replication.
        AddingKDSRootKeyError              = Effective date of '{0}' is in the past and 'UnsafeEffectiveTime' was not specified so the KDS Root Key will NOT be created!
        KDSRootKeyAddError                 = There was an error when trying to Add the KDS Root Key with the effective date of '{0}'.
        KDSRootKeyRemoveError              = There was an error when trying to Remove the KDS Root Key with the effective date of '{0}'.
        FoundKDSRootKeySameEffectiveTime   = Found more than one KDS Root Keys with the same effective time, please ensure that only one KDS key exists with the effective time of '{0}'.
        FoundKDSRootKeyMultiple            = Found more than one KDS Root Keys. This shouldn't be an issue, but having only one key per domain is recommended.
        FoundKDSRootKey                    = Found KDS Root Key with the effective date of '{0}'.
        NotEnoughKDSRootKeysPresent        = The KDS Root Key with effective date of '{0}' is the only key that exists. Please ensure a key exists if there are existing 'Group Managed Service Accounts (gMSAs)' present.
        NotEnoughKDSRootKeysPresentNoForce = There is only one KDS Root Key left and the 'ForceRemove' parameter no set; therefore, the KDS Root Key with effective date of '{0}' will not be removed.
        RemovingKDSRootKey                 = Removing the KDS Root Key with effective date '{0}'.
        KDSRootKeyNotInDesiredState        = KDS Root Key with the effective date of '{0}' is NOT in the desired state.
        KDSRootKeyInDesiredState           = KDS Root Key with the effective date of '{0}' is in the desired state.
        NotDesiredPropertyState            = The parameter of '{0}' for the KDS Root Key with the effective date of '{1}' is incorrect. Expected '{2}', actual '{3}'.
        IncorrectPermissions               = The DSC resource is running under the context of '{0}' and doesn't have 'Domain Admin' permissions. This resource needs to run as a Domain Admin or on a Domain Controller.
        EffectiveTimeInvalid               = The EffectiveTime of '{0}' is invalid. Please ensure that the date and time is parsable using DateTime.
        CheckingDomainAdminUserRights      = Checking if the user '{0}' has valid Domain Admin permissions.
        CheckingDomainAdminComputerRights  = Checking if the node '{0}' is a Domain Controller. The node has a product type of '{1}'. If the product type is 2, then it is a domain controller.
        RetrievingRootDomainDN             = Retrieved the root domain distinguished name of '{0}'
'@
}

<#
    .SYNOPSIS
        Gets the specified KDS root key

    .PARAMETER EffectiveTime
        Time at which key will become active, this is also the key identifier
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
        $EffectiveTime
    )

    Assert-Module -ModuleName 'ActiveDirectory'

    $targetResource = @{
        EffectiveTime     = $EffectiveTime
        CreationTime      = $null
        KeyId             = $null
        Ensure            = $null
        DistinguishedName = $null
    }

    Write-Verbose -Message ($LocalizedData.RetrievingKDSRootKey -f $EffectiveTime)
    try
    {
        $EffectiveTimeObject = [DateTime]::Parse($EffectiveTime)
    }
    catch
    {
        Write-Error -Message ($LocalizedData.EffectiveTimeInvalid -f $EffectiveTime)
        throw $_
    }

    $currentUser = Get-CurrentUser
    if (-not (Assert-HasDomainAdminRights -User $currentUser))
    {
        throw $LocalizedData.IncorrectPermissions -f $currentUser.Name
    }

    try
    {
        $kdsRootKeys = Get-KdsRootKey
    }
    catch
    {
        Write-Error -Message ($LocalizedData.RetrievingKDSRootKeyError)
        throw $_
    }

    $kdsRootKey = $null
    if ($kdsRootKeys)
    {
        $kdsRootKey = $kdsRootKeys.GetEnumerator() | Where-Object -FilterScript {
            [DateTime]::Parse($_.EffectiveTime) -eq $EffectiveTimeObject
        }
    }

    if (-not $kdsRootKey)
    {
        $targetResource['Ensure'] = 'Absent'
    }
    else
    {
        Write-Verbose -Message ($LocalizedData.FoundKDSRootKey -f $EffectiveTime)
        if ($kdsRootKeys.Count -gt 1)
        {
            Write-Warning -Message ($LocalizedData.FoundKDSRootKeyMultiple)
        }

        if ($kdsRootKey.Count -gt 1)
        {
            throw $LocalizedData.FoundKDSRootKeySameEffectiveTime -f $EffectiveTime
        }
        elseif ($kdsRootKey)
        {
            $targetResource['Ensure']            = 'Present'
            $targetResource['EffectiveTime']     = [DateTime]::Parse($kdsRootKey.EffectiveTime)
            $targetResource['CreationTime']      = $kdsRootKey.CreationTime
            $targetResource['KeyId']             = $kdsRootKey.KeyId
            $targetResource['DistinguishedName'] = 'CN={0},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{1}' -f
                                                        $kdsRootKey.KeyId, (Get-ADRootDomainDN)
        }
    }

    return $targetResource
}

<#
    .SYNOPSIS
        Creates or deletes the KDS root Key

    .PARAMETER EffectiveTime
        Time at which key will become active, this is also the key identifier

    .PARAMETER UnsafeEffectiveTime
        Allows effective date to be set in the past

    .PARAMETER Ensure
        Specifies whether the KDS Root Key should exist or not

    .PARAMETER ForceRemove
        Removes the KDS root key with there is only one key left
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $EffectiveTime,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $UnsafeEffectiveTime,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $ForceRemove
    )

    $getTargetResourceParameters = @{
        EffectiveTime = $EffectiveTime
        Ensure        = $Ensure
    }

    $compareTargetResourceNonCompliant = Compare-TargetResourceState @getTargetResourceParameters | Where-Object {$_.Pass -eq $false}

    $ensureState = $compareTargetResourceNonCompliant | Where-Object -FilterScript {$_.Parameter -eq 'Ensure'}

    if ($ensureState)
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f
                        'Ensure', $EffectiveTime, $ensureState.Expected, $ensureState.Actual)
        Write-Verbose -Message ($LocalizedData.KDSRootKeyNotInDesiredState -f $EffectiveTime)
        return $false
    }
    else
    {
        Write-Verbose -Message ($LocalizedData.KDSRootKeyInDesiredState -f $EffectiveTime)
        return $true
    }
}

<#
    .SYNOPSIS
        Creates or deletes the KDS root Key

    .PARAMETER EffectiveTime
        Time at which key will become active, this is also the key identifier

    .PARAMETER UnsafeEffectiveTime
        Allows effective date to be set in the past

    .PARAMETER Ensure
        Specifies whether the KDS Root Key should exist or not

    .PARAMETER ForceRemove
        Removes the KDS root key with there is only one key left
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $EffectiveTime,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $UnsafeEffectiveTime = $false,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $ForceRemove = $false
    )

    $getTargetResourceParameters = @{
        EffectiveTime = $EffectiveTime
        Ensure        = $Ensure
    }

    $compareTargetResource = Compare-TargetResourceState @getTargetResourceParameters
    $ensureState = $compareTargetResource | Where-Object -FilterScript {$_.Parameter -eq 'Ensure'}

    # Ensure is not in proper state
    if ($ensureState.Pass -eq $false)
    {
        if ($Ensure -eq 'Present')
        {
            try
            {
                $EffectiveTimeObject = [DateTime]::Parse($EffectiveTime)
            }
            catch
            {
                Write-Error -Message ($LocalizedData.EffectiveTimeInvalid -f $EffectiveTime)
                throw $_
            }

            # We want the key to be present, but it currently does not exist
            $currentDateTimeObject = [DateTime]::Parse($(Get-Date))

            if ($EffectiveTimeObject -le $currentDateTimeObject -and $UnsafeEffectiveTime)
            {
                Write-Warning -Message ($LocalizedData.AddingKDSRootKeyDateInPast -f $EffectiveTime)
            }
            elseif ($EffectiveTimeObject -le $currentDateTimeObject)
            {
                <#
                 Effective time is in the past and we don't have UnsafeEffectiveTime set
                 to enabled, so we exit with an error
                #>
                throw $LocalizedData.AddingKDSRootKeyError -f $EffectiveTime
            }
            else
            {
                Write-Verbose -Message ($LocalizedData.AddingKDSRootKey -f $EffectiveTime)
            }

            <#
             EffectiveTime appears to expect a UTC datetime, so we are converting
             it to UTC before adding. Get-KDSRootKey will return the wrong time if we
             don't convert first
            #>
            try
            {
                Add-KDSRootKey -EffectiveTime $EffectiveTimeObject.ToUniversalTime()
            }
            catch
            {
                Write-Error -Message ($LocalizedData.KDSRootKeyAddError -f $EffectiveTime)
                throw $_
            }
        }
        elseif ($Ensure -eq 'Absent')
        {
            # We want the account to be Absent, but it is Present
            if((Get-KdsRootKey).Count -gt 1)
            {
                Write-Verbose -Message ($LocalizedData.RemovingKDSRootKey -f $EffectiveTime)
            }
            else
            {
                if ($ForceRemove)
                {
                    Write-Verbose -Message ($LocalizedData.RemovingKDSRootKey -f $EffectiveTime)
                    Write-Warning -Message ($LocalizedData.NotEnoughKDSRootKeysPresent -f $EffectiveTime)
                }
                else
                {
                    throw $LocalizedData.NotEnoughKDSRootKeysPresentNoForce -f $EffectiveTime
                }
            }

            $dn = $compareTargetResource | Where-Object -FilterScript {$_.Parameter -eq 'DistinguishedName'}
            try
            {
                Remove-ADObject -Identity $dn.Actual -Confirm:$false
            }
            catch
            {
                Write-Error -Message ($LocalizedData.KDSRootKeyRemoveError -f $EffectiveTime)
                throw $_
            }
        }
    }
}

<#
    .SYNOPSIS
        Compares the state of the KDS root key

    .PARAMETER EffectiveTime
        Time at which key will become active, this is also the key identifier

    .PARAMETER Ensure
        Specifies whether the KDS Root Key should exist or not
#>
function Compare-TargetResourceState
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $EffectiveTime,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure
    )

    $getTargetResourceParameters = @{
        EffectiveTime  = [DateTime]::Parse($EffectiveTime)
    }

    $getTargetResource = Get-TargetResource @getTargetResourceParameters
    $compareTargetResource = @()

    # Add DistinguishedName as it won't be passed as an argument, but we want to get the DN in Set
    $PSBoundParameters['DistinguishedName'] = $getTargetResource['DistinguishedName']

    # Convert EffectiveTime to DateTime object for comparison
    $PSBoundParameters['EffectiveTime']  = [DateTime]::Parse($EffectiveTime)

    foreach ($parameter in $PSBoundParameters.Keys)
    {
        if ($PSBoundParameters.$parameter -eq $getTargetResource.$parameter)
        {
            # Check if parameter is in compliance
            $compareTargetResource += [pscustomobject] @{
                Parameter = $parameter
                Expected  = $PSBoundParameters.$parameter
                Actual    = $getTargetResource.$parameter
                Pass      = $true
            }
        }
        # Need to check if parameter is part of schema, otherwise ignore all other parameters like verbose
        elseif ($getTargetResource.ContainsKey($parameter))
        {
            # We are out of compliance if we get here
            # $PSBoundParameters.$parameter -ne $getTargetResource.$parameter
            $compareTargetResource += [pscustomobject] @{
                Parameter = $parameter
                Expected  = $PSBoundParameters.$parameter
                Actual    = $getTargetResource.$parameter
                Pass      = $false
            }
        }
    } #end foreach PSBoundParameter

    return $compareTargetResource
}

<#
    .SYNOPSIS
        Checks permissions to see if the user or computer has domain admin permissions

    .PARAMETER User
        The user to check permissions against
#>
function Assert-HasDomainAdminRights
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Principal.WindowsIdentity]
        $User
    )

    # Get-KdsRootKey will return $null instead of a permission error if it can't retrieve the keys
    # so we need manually check

    $windowsPrincipal = New-Object -TypeName System.Security.Principal.WindowsPrincipal($User)
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem

    Write-Verbose -Message ($LocalizedData.CheckingDomainAdminUserRights -f $User.Name)
    Write-Verbose -Message ($LocalizedData.CheckingDomainAdminComputerRights -f $osInfo.CSName, $osInfo.ProductType)

    return $windowsPrincipal.IsInRole("Domain Admins") -or
            $windowsPrincipal.IsInRole("Enterprise Admins") -or
            $osInfo.ProductType -eq 2
}

<#
    .SYNOPSIS
        Returns a string with the Distinguished Name of the root domain.

    .DESCRIPTION
        If you have a domain with sub-domains, this will return the root domain name. For example,
        if you had a domain contoso.com and a sub domain of fake.contoso.com, it would return
        contoso.com
#>
function Get-ADRootDomainDN
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param()

    $rootDomainDN = (New-Object -TypeName System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')).Get('rootDomainNamingContext')
    Write-Verbose -Message ($LocalizedData.RetrievingRootDomainDN -f $rootDomainDN)
    return $rootDomainDN
}

<#
    .SYNOPSIS
        This is used to get the current user context when the resource script runs.
        We are putting this in a function so we can mock it with pester
#>
function Get-CurrentUser
{
    return [System.Security.Principal.WindowsIdentity]::GetCurrent()
}

Export-ModuleMember *-TargetResource
