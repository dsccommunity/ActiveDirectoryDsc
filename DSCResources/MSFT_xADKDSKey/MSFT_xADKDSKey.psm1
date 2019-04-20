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
        AddingKDSRootKey                   = Creating KDS Root key with the Effective date of '{0}'
        AddingKDSRootKeyDateInPast         = Effective date is in the past and the 'UnsafeEffectiveTime' was set to True. Adding KDS Root key with the Effective date of '{0}', overriding 10 hour safety measure for domain controller replication
        AddingKDSRootKeyError              = Effective date of '{0}' is in the past and 'UnsafeEffectiveTime' was not specified so the KDS root key will NOT be created!
        KDSRootKeyErrorOther               = There was an error when trying to add or remove the KDS root key with the effective date of '{0}'
        FoundKDSRootKeySameEffectiveTime   = Found more than one KDS root keys with the same effective time, please ensure that only one KDS key exists with the effective time of '{0}'
        FoundKDSRootKeyMultiple            = Found more than one KDS root keys. This shouldn't be an issue, but having only one key per domain is recommended.
        RetrievingKDSRootKey               = Retrieving KDS Root key with Effective date of '{0}' ...
        NotEnoughKDSrootKeysPresent        = The KDS root key with effective date of '{0}' is the only key that exists. Please ensure a key exists if there are existing gMSAs present
        NotEnoughKDSrootKeysPresentNoForce = There is only one KDS root key left and the 'ForceRemove' parameter no set; therefore, the KDS root key with Effective date of '{0}' will not be removed
        RemovingKDSRootKey                 = Removing the KDS root key with effective date '{0}'
        KDSRootKeyNotInDesiredState        = KDS Root key with the Effective date of '{0}' is NOT in the desired state.
        KDSRootKeyInDesiredState           = KDS Root key with the Effective date of '{0}' is in the desired state.
        NotDesiredPropertyState            = The parameter of '{0}' for the KDS Root Key with the Effective date of '{1}' is incorrect. Expected '{2}', actual '{3}'.
        FoundKDSRootKey                    = Found KDS Root key with the Effective date of '{0}'
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
    $EffectiveTime = Get-Date $EffectiveTime

    $targetResource = @{
        EffectiveTime     = $EffectiveTime
        CreationTime      = $null
        KeyId             = $null
        Ensure            = $null
        DistinguishedName = $null
    }

    try
    {
        $kdsRootKeys = Get-KdsRootKey

        $kdsRootKey = $null
        if ($kdsRootKeys)
        {
            $kdsRootKey = ($kdsRootKeys).GetEnumerator() | Where-Object { $_.EffectiveTime -eq $EffectiveTime }
        }

        if (-not $kdsRootKey)
        {
            $targetResource['Ensure'] = 'Absent'
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.FoundKDSRootKey -f $EffectiveTime)
            if(($kdsRootKeys).Count -gt 1)
            {
                Write-Warning -Message ($LocalizedData.FoundKDSRootKeyMultiple -f $EffectiveTime)
            }

            if ($kdsRootKey.Count -gt 1)
            {
                Write-Error -Message ($LocalizedData.FoundKDSRootKeySameEffectiveTime -f $EffectiveTime) -ErrorAction Stop
            }
            elseif ($kdsRootKey)
            {
                $targetResource['Ensure']            = 'Present'
                $targetResource['EffectiveTime']     = $kdsRootKey.EffectiveTime
                $targetResource['CreationTime']      = $kdsRootKey.CreationTime
                $targetResource['KeyId']             = $kdsRootKey.KeyId
                $targetResource['DistinguishedName'] = 'CN={0},CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,{1}' -f
                                                            $kdsRootKey.KeyId, $((Get-ADDomain).DistinguishedName)
            }
        }

        return $targetResource
    }
    catch
    {
        Write-Error -Message ($LocalizedData.RetrievingKDSRootKey -f $EffectiveTime)
        throw $_
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

    # Need to set these to compare if not specified since user is using defaults
    $PSBoundParameters['Ensure'] = $Ensure

    $compareTargetResourceNonCompliant = Compare-TargetResourceState @PSBoundParameters | Where-Object {$_.Pass -eq $false}

    # Check if Absent, if so then we don't need to propagate any other parameters
    if ($Ensure -eq 'Absent')
    {
        $ensureState = $compareTargetResourceNonCompliant | Where-Object {$_.Parameter -eq 'Ensure'}
        if ($ensureState)
        {
            Write-Verbose ($LocalizedData.NotDesiredPropertyState -f `
                            'Ensure', $EffectiveTime, $ensureState.Expected, $ensureState.Actual)
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.KDSRootKeyInDesiredState -f $EffectiveTime)
            return $true
        }
    }
    else
    {
        # Currently there are no other parameters that can be out of compliance
        # this can change in the future and this code will take care of any other parameters
        <#
        $compareTargetResourceNonCompliant | ForEach-Object {
            Write-Verbose -Message ($LocalizedData.NotDesiredPropertyState -f
                $_.Parameter, $EffectiveTime, $_.Expected, $_.Actual)
        }
        #>
    }

    if ($compareTargetResourceNonCompliant)
    {
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

    @($getTargetResourceParameters.Keys) | ForEach-Object {
        if (-not $PSBoundParameters.ContainsKey($_))
        {
            $getTargetResourceParameters.Remove($_)
        }
    }

    $compareTargetResource = Compare-TargetResourceState @getTargetResourceParameters
    $compareTargetResourceNonCompliant = @($compareTargetResource | Where-Object {$_.Pass -eq $false})

    try
    {
        if ($Ensure -eq 'Present')
        {
            $isEnsureNonCompliant = $false
            if ($compareTargetResourceNonCompliant | Where-Object {$_.Parameter -eq 'Ensure'})
            {
                $isEnsureNonCompliant = $true
            }

            # We want the account to be present, but it currently does not exist
            if ($isEnsureNonCompliant)
            {
                $PSBoundParameters.Remove('Ensure')

                if ((Get-Date $EffectiveTime) -le (Get-Date) -and $UnsafeEffectiveTime)
                {
                    Write-Warning -Message ($LocalizedData.AddingKDSRootKeyDateInPast -f $EffectiveTime)
                }
                elseif ((Get-Date $EffectiveTime) -le (Get-Date))
                {
                    # Effective time is in the past we don't have unsafe effective time set
                    # so we exit with an error
                    Write-Error -Message ($LocalizedData.AddingKDSRootKeyError -f $EffectiveTime) -ErrorAction Stop
                    return # Not sure how to mock this with pester
                }
                else
                {
                    Write-Verbose -Message ($LocalizedData.AddingKDSRootKey -f $EffectiveTime)
                }

                # EffectiveTime appears to expect a UTC datetime, so we are converting
                # it to UTC before adding. Get-KDSRootKey will return the wrong time if we
                # don't convert first
                Add-KDSRootKey -EffectiveTime (Get-Date $EffectiveTime).ToUniversalTime()
            }
        }
        elseif ($Ensure -eq 'Absent')
        {
            $isEnsureNonCompliant = $false
            if ($compareTargetResourceNonCompliant | Where-Object {$_.Parameter -eq 'Ensure'})
            {
                $isEnsureNonCompliant = $true
            }

            # We want the account to be Absent, but it is Present
            if ($isEnsureNonCompliant)
            {
                if((Get-KdsRootKey).Count -gt 1)
                {
                    Write-Verbose -Message ($LocalizedData.RemovingKDSRootKey -f $EffectiveTime)
                }
                else
                {
                    if ($ForceRemove)
                    {
                        Write-Verbose -Message ($LocalizedData.RemovingKDSRootKey -f $EffectiveTime)
                        Write-Warning -Message ($LocalizedData.NotEnoughKDSrootKeysPresent -f $EffectiveTime)
                    }
                    else
                    {
                        Write-Error -Message ($LocalizedData.NotEnoughKDSrootKeysPresentNoForce -f $EffectiveTime) -ErrorAction Stop
                        return # Not sure how to mock this with pester
                    }
                }

                $dn = $compareTargetResource | Where-Object {$_.Parameter -eq 'DistinguishedName'}
                Remove-ADObject -Identity $dn.Actual -Confirm:$false
            }
        }
    }
    catch
    {
        Write-Error -Message ($LocalizedData.KDSRootKeyErrorOther -f $EffectiveTime)
        throw $_
    }
}

<#
    .SYNOPSIS
        Compares the state of the KDS root key

    .PARAMETER EffectiveTime
        Time at which key will become active, this is also the key identifier

    .PARAMETER UnsafeEffectiveTime
        Allows effective date to be set in the past

    .PARAMETER Ensure
        Specifies whether the KDS Root Key should exist or not

    .PARAMETER ForceRemove
        Removes the KDS root key with there is only one key left
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
        EffectiveTime  = $EffectiveTime
    }

    # Currently there are no other parameters to remove
    # This code here will remove any parameters that are optional
    # but don't need to be passed to Get-TargetResource
    <#
    @($getTargetResourceParameters.Keys) | ForEach-Object {
        if (-not $PSBoundParameters.ContainsKey($_))
        {
            $getTargetResourceParameters.Remove($_)
        }
    }
    #>

    $getTargetResource = Get-TargetResource @getTargetResourceParameters
    $compareTargetResource = @()

    # Add DistinguishedName as it won't be passed as an argument, but we want to get the DN in Set
    $PSBoundParameters['DistinguishedName'] = $getTargetResource['DistinguishedName']

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

Export-ModuleMember *-TargetResource
