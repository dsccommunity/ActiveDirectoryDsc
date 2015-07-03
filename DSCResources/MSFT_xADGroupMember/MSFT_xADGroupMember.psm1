function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Identity,

        [parameter(Mandatory = $true)]
        [System.String]
        $Members,

        [parameter(Mandatory = $true)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Management.Automation.PSCredential]
        $Credential
    )

    If($PSBoundParameters.ContainsKey('Credential'))
    {
        $GroupMembers = Get-ADGroupMember -Identity $Identity -Credential $Credential
    }
    Else
    {
        $GroupMembers = Get-ADGroupMember -Identity $Identity
    }



    Foreach($Member in $Members)
    {
        $MemberShipResult += $GroupMembers.Name -contains $Member
    }

    If($MemberShipResult -notcontains $false)
    {
        $EnsureResult = 'Present'
    }
    Else
    {
        $EnsureResult = 'Absent'
    }

        $returnValue = @{
            Identity = $Identity
            Members = $Members
            Ensure = $EnsureResult        
        }

        $returnValue
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Identity,

        [parameter(Mandatory = $true)]
        [System.String]
        $Members,

        [parameter(Mandatory = $true)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Management.Automation.PSCredential]
        $Credential
    )
    
    $PSBoundParameters.Remove('Ensure') | Out-Null
    $PSBoundParameters.Add('Confirm',$false)
    If($Ensure -eq 'Present')
    {
        Write-Verbose "Adding $Members in $Identity"
        Add-ADGroupMember @PSBoundParameters
    }
    Else
    {
        
        Write-Verbose "Removing $Members from $Identity"
        Remove-ADGroupMember @PSBoundParameters
    }


}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Identity,

        [parameter(Mandatory = $true)]
        [System.String]
        $Members,

        [parameter(Mandatory = $true)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Management.Automation.PSCredential]
        $Credential
    )

    $Actual = Get-TargetResource @PSBoundParameters

    Write-Verbose "Expected results $Members $Ensure in $Identity. Actual $($Actual.Ensure)"

    If(($Actual.Ensure -ne 'Present') -and ($Ensure -eq 'Present'))
    {
        return $false
    }
    If(($Actual.Ensure -ne 'Absent') -and ($Ensure -eq 'Absent'))
    {
        return $false
    }
    #If code made it this far all conditions must be true
    return $true
}


Export-ModuleMember -Function *-TargetResource

