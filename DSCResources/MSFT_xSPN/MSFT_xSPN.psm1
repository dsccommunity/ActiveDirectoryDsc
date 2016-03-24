$currentPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Debug -Message "CurrentPath: $currentPath"

# Load Common Code
Import-Module $currentPath\..\..\xActiveDirectoryHelper.psm1 -Verbose:$false -ErrorAction Stop

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String] 
        $Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [String] 
        $SPN,

        [Parameter(Mandatory=$true)]
        [String] 
        $ObjectName,

        [ValidateSet("Server","User")]
        [String] 
        $ObjectType = "Server"
    )
    
    Set-SPN @PSBoundParameters

    # For now call Test at the end of Set
    if(!(Test-TargetResource @PSBoundParameters))
    {
        throw New-TerminatingError -ErrorType TestFailedAfterSet -ErrorCategory InvalidResult
    }
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String] 
        $Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [String] 
        $SPN,

        [Parameter(Mandatory=$true)]
        [String] 
        $ObjectName,

        [ValidateSet("Server","User")]
        [String] 
        $ObjectType = "Server"
    )

    $retVal = Test-SPN $SPN

    if($retVal.Found)
    {
        $returnValue = @{
            Ensure = "Present"
            Domain = $retVal.Domain
            SPN = $SPN }
    }
    else
    {
        $returnValue = @{
            Ensure = "Absent"
            Domain = $retVal.Domain
            SPN = $SPN }
    }

    $returnValue
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String] 
        $Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [String] 
        $SPN,

        [Parameter(Mandatory=$true)]
        [String] 
        $ObjectName,

        [ValidateSet("Server","User")]
        [String] 
        $ObjectType = "Server"
    )

    $result = ((Get-TargetResource @PSBoundParameters).Ensure -eq $Ensure)

    $result
}

function Set-SPN
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String] 
        $Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [String] 
        $SPN,

        [Parameter(Mandatory=$true)]
        [String] 
        $ObjectName,

        [ValidateSet("Server","User")]
        [String] 
        $ObjectType = "Server"
    )

    $spnCommandArgs = @($SPN,$ObjectName)

    if($Ensure -eq "Absent")
    {
        # -D = Delete
        $spnCommandArgs = @("-D") + $spnCommandArgs
    }
    elseif($ObjectType -eq "Server")
    {    
        # -C = Computer
        $spnCommandArgs =  @("-C","-S") + $spnCommandArgs
    }
    elseif($ObjectType -eq "User")
    {
        # -U = User
        $spnCommandArgs = @("-U","-S") + $spnCommandArgs
    }
    else
    {
        throw New-TerminatingError -ErrorType InvalidSPNType -FormatArgs @($ObjectType) -ErrorCategory InvalidType -TargetObject $ObjectType
    }

    Execute-SPN -SPNArgs $spnCommandArgs
}

function Test-SPN
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [String] 
        $SPN
    )
    
    $found = $false

    $spnOutput = Execute-SPN -SPNArgs "-Q $SPN".Split(' ')

    # Contains the active directory location searched
    $activeDirectoryInformation = $spnOutput | select-Object -First 1
    
    # Contains the results of search success/failure
    $resultText = $spnOutput | select -Last 1

    if($resultText -eq 'Existing SPN found!')
    {
        $found = $true
    }

    $returnValue = @{
        Domain = $activeDirectoryInformation
        Found = $found }

    $returnValue
}

function Execute-SPN 
{
    [CmdletBinding()]
    param
    (
        [String[]] 
        $SPNArgs
    )

    Write-Verbose "Running command: setspn.exe $SPNArgs" 
             
    $spnOutput = & setspn.exe $SPNArgs

    if($LASTEXITCODE -ne 0)
    {
        throw New-TerminatingError -ErrorType InvalidSPNCall -FormatArgs @($SPNArgs,$LASTEXITCODE) -ErrorCategory InvalidArgument
    } 

    $spnOutput 
}

Export-ModuleMember -Function *-TargetResource