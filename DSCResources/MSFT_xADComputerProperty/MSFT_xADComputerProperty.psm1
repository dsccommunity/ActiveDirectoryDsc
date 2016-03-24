# NOTE: This resource requires WMF5 and PsDscRunAsCredential

# DSC resource to AD computer object properties.
# Runs on the domain joined computer.
# Requires PowerShell module ActiveDirectory.

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
        $Name,

        [parameter(Mandatory = $true)]
        [ValidateSet("OperatingSystem","OperatingSystemVersion")]
        [System.String]
        $Property,

        [parameter(Mandatory = $true)]
        [System.String]
        $Value
    )

    Assert-Module -ModuleName ActiveDirectory
    
    $ADComputer = Get-ADComputer -Identity $Name -Properties $Property

    $returnValue = @{
        Name = $Name
        Property = $Property
        Value = $ADComputer."$Property"
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
        $Name,

        [parameter(Mandatory = $true)]
        [ValidateSet("OperatingSystem","OperatingSystemVersion")]
        [System.String]
        $Property,

        [parameter(Mandatory = $true)]
        [System.String]
        $Value
    )

    Assert-Module -ModuleName ActiveDirectory

    $SetParameters = @{
        Identity = $Name
        $Property = $Value
    }

    Write-Verbose "Setting AD computer $Name property '$Property' to '$Value'"
    try
    {
        Set-ADComputer @SetParameters -ErrorAction Stop
        Write-Verbose "Pausing 15 seconds to allow for intra-site replication before test"
        Start-Sleep 15
    }
    catch
    {
        Write-Verbose "Failed setting property with exception $($_.Exception)"
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
        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [ValidateSet("OperatingSystem","OperatingSystemVersion")]
        [System.String]
        $Property,

        [parameter(Mandatory = $true)]
        [System.String]
        $Value
    )

    $result = ((Get-TargetResource @PSBoundParameters).Value -eq $Value)
    
    $result
}


Export-ModuleMember -Function *-TargetResource