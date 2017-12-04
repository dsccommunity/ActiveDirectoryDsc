function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $EffectiveTime
    )

    try {
        $KDSKeys = Get-KDSRootKey | Select-Object -First 1
        return @{
            EffectiveTime          = $KDSKeys.EffectiveTime
            AttributeOfWrongFormat = $KDSKeys.AttributeOfWrongFormat
            KeyValue               = $KDSKeys.KeyValue
            CreationTime           = $KDSKeys.CreationTime
            IsFormatValid          = $KDSKeys.IsFormatValid
            DomainController       = $KDSKeys.DomainController
            ServerConfiguration    = $KDSKeys.ServerConfiguration
            KeyId                  = $KDSKeys.KeyId
            VersionNumber          = $KDSKeys.VersionNumber
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
        [bool]($Keys.EffectiveTime | Where-Object {$_ -le (get-date)})
    }
    else {
        [bool]($Keys.EffectiveTime | Where-Object {$_ -eq $EffectiveTime})
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
