# NOTE: This resource requires WMF5 and PsDscRunAsCredential

# DSC resource to manage AD service account on a member computer.

$currentPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Debug -Message "CurrentPath: $currentPath"

# Load Common Code
Import-Module $currentPath\..\..\xActiveDirectoryHelper.psm1 -Verbose:$false -ErrorAction Stop

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Identity
    )

    try
    {
        Write-Verbose "Getting AD service account with identity $Identity"
        $ADServiceAccount = Get-ADServiceAccount -Filter {Name -eq $Identity}
    }
    catch
    {
        Write-Verbose "Failed getting AD service account with identity $Identity"
        $Ensure = "Absent"
    }
    
    if($ADServiceAccount)
    {
        if(Test-ADServiceAccount -Identity $Identity)
        {
            $Ensure = "Present"
        }
        else
        {
            $Ensure = "Absent"
        }
    }

    $returnValue = @{
        Ensure = $Ensure
        Identity = $Identity
    }

    $returnValue
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [parameter(Mandatory = $true)]
        [System.String]
        $Identity
    )

    switch($Ensure)
    {
        "Present"
        {
            try
            {
                Write-Verbose "Installing AD service account with identity $Identity"
                Install-ADServiceAccount -Identity $Identity
            }
            catch
            {
                Write-Verbose "Failed installing AD service account with identity $Identity"
            }
        }
        "Absent"
        {
            try
            {
                Write-Verbose "Uninstalling AD service account with identity $Identity"
                Uninstall-ADServiceAccount -Identity $Identity
            }
            catch
            {
                Write-Verbose "Failed uninstalling AD service account with identity $Identity"
            }
        }
    }

    if(!(Test-TargetResource @PSBoundParameters))
    {
        throw New-TerminatingError -ErrorType TestFailedAfterSet -ErrorCategory InvalidResult
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [parameter(Mandatory = $true)]
        [System.String]
        $Identity
    )

    $result = ((Get-TargetResource -Identity $Identity).Ensure -eq $Ensure)

    $result
}


Export-ModuleMember -Function *-TargetResource