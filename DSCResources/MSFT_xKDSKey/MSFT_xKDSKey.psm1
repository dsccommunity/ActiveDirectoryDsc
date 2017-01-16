function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $StartTime
    )

    try
    {
        $KDSKeys = @(Get-KDSRootKey)
        return @{
            AttributeOfWrongFormat = $KDSKeys[0].AttributeOfWrongFormat
            KeyValue = $KDSKeys[0].KeyValue
            EffectiveTime = $KDSKeys[0].EffectiveTime
            CreationTime = $KDSKeys[0].CreationTime
            IsFormatValid = $KDSKeys[0].IsFormatValid
            DomainController = $KDSKeys[0].DomainController
            ServerConfiguration = $KDSKeys[0].ServerConfiguration
            KeyId = $KDSKeys[0].KeyId
            VersionNumber = $KDSKeys[0].VersionNumber
        }
     }
    catch
    {
        throw $_
    }

} #end function Get-TargetResource

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $StartTime
    )

    $Keys = Get-TargetResource @PSBoundParameters

    if($StartTime -le (get-date))
    {
       [bool]($Keys.EffectiveTime | ? {$_ -le (get-date)})
    }
    else
    {
        [bool]($Keys.EffectiveTime | ? {$_ -eq $StartTime})
    }

} #end function Test-TargetResource

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [DateTime] $StartTime
    )

    $Params = @{}

    if($StartTime -le (get-date))
    {
        $params.add("EffectiveImmediately",$true)
    }
    else
    {
        $params.add("EffectiveTime",$StartTime)
    }

    Add-KDSRootKey @params | out-null

} #end function Set-TargetResource

Export-ModuleMember *-TargetResource
