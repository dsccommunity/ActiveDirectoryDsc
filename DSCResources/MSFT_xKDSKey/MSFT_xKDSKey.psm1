function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $EffectiveTime
    )

    try {
        $KDSKeys = @(Get-KDSRootKey)
        return @{
            EffectiveTime          = $KDSKeys[0].EffectiveTime
            AttributeOfWrongFormat = $KDSKeys[0].AttributeOfWrongFormat
            KeyValue               = $KDSKeys[0].KeyValue
            CreationTime           = $KDSKeys[0].CreationTime
            IsFormatValid          = $KDSKeys[0].IsFormatValid
            DomainController       = $KDSKeys[0].DomainController
            ServerConfiguration    = $KDSKeys[0].ServerConfiguration
            KeyId                  = $KDSKeys[0].KeyId
            VersionNumber          = $KDSKeys[0].VersionNumber
        }
    }
    catch {
        throw $_
    }

} #end function Get-TargetResource

function Test-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $EffectiveTime
    )

    $Keys = Get-TargetResource @PSBoundParameters

    if ($EffectiveTime -le (get-date)) {
        [bool]($Keys.EffectiveTime | ? {$_ -le (get-date)})
    }
    else {
        [bool]($Keys.EffectiveTime | ? {$_ -eq $EffectiveTime})
    }

} #end function Test-TargetResource

function Set-TargetResource {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $EffectiveTime
    )

    $Params = @{}

    if ($EffectiveTime -le (get-date)) {
        $params.add("EffectiveImmediately", $true)
    }
    else {
        $params.add("EffectiveTime", $EffectiveTime)
    }

    Add-KDSRootKey @params | out-null

} #end function Set-TargetResource

Export-ModuleMember *-TargetResource
