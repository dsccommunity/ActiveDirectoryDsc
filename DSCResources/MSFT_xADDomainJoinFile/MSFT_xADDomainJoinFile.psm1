$moduleRoot = Split-Path `
    -Path $MyInvocation.MyCommand.Path `
    -Parent

#region LocalizedData
$Culture = 'en-us'
if (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath $PSUICulture))
{
    $Culture = $PSUICulture
}
Import-LocalizedData `
    -BindingVariable LocalizedData `
    -Filename MSFT_xADDomainJoinFile.psd1 `
    -BaseDirectory $moduleRoot `
    -UICulture $Culture
#endregion


function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ComputerName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RequestFile
    )

    Write-Verbose -Message ( @( "$($MyInvocation.MyCommand): "
        $($LocalizedData.GettingRequestODJMessage)
        ) -join '')

    Assert-Module -ModuleName 'ActiveDirectory'

    # It is not possible to determine the state of the ODJ except for the OU
    # So most parameters are not returned.
    $returnValue = @{
        DomainName = $DomainName
        ComputerName = $ComputerName
        RequestFile = $RequestFile
    }

    $Domain = Get-ADDomain -Identity $DomainName
    $Parameters = @{
        searchbase = $Domain.DistinguishedName
        filter = { name -eq $ComputerName }
    }

    $Computer = Get-ADComputer @Parameters
    if ($Computer)
    {
        $returnValue += @{
            Path = (Get-ADObjectParentDN -DN $Computer.DistinguishedName)
        }
    } # if

    #Output the target resource
    $returnValue
} # Get-TargetResource


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ComputerName,

        [System.String]
        $Path,

        [System.String]
        $DomainController,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RequestFile
    )

    Write-Verbose -Message ( @( "$($MyInvocation.MyCommand): "
        $($LocalizedData.ApplyingRequestODJMessage)
        ) -join '')

    # If the request file already exists then throw an error
    # This is the safest thing to do, because once a request
    # file is deleted there is no way of recreating it except
    # by the DJOIN /REUSE flag which resets the Secure Channel.
    if (Test-Path -Path $RequestFile)
    {
        $errorId = 'RequestFileExistsError'
        $errorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errorMessage = $($LocalizedData.RequestFileExistsError) `
            -f $RequestFile
        $exception = New-Object -TypeName System.ArgumentException `
            -ArgumentList $errorMessage
        $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
            -ArgumentList $exception, $errorId, $errorCategory, $null

        $PSCmdlet.ThrowTerminatingError($errorRecord)
    } # if

    # We don't need to check if Join-Domain should be called because
    # Set-TargetResource wouldn't fire unless it wasn't.
    Join-Domain @PSBoundParameters
} # Set-TargetResource


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ComputerName,

        [System.String]
        $Path,

        [System.String]
        $DomainController,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RequestFile
    )

    # Flag to signal whether settings are correct
    [Boolean] $desiredConfigurationMatch = $true

    Write-Verbose -Message ( @("$($MyInvocation.MyCommand): "
        $($LocalizedData.CheckingRequestODJMessage)
        ) -join '')

    # Check the if the Account already exists
    if (Test-ComputerAccount @PSBoundParameters)
    {
        # The Account exists 
        Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.ComputerAccountExistsMessage) `
                -f $DomainName,$ComputerName `
            ) -join '' )
    } # if
    else
    {
        Write-Verbose -Message ( @(
        "$($MyInvocation.MyCommand): "
        $($LocalizedData.ComputerAccountDoesNotExistMessage) `
            -f $DomainName,$ComputerName `
        ) -join '' )
        $desiredConfigurationMatch = $false
    } # if
    return $desiredConfigurationMatch
} # Test-TargetResource


<#
.SYNOPSIS
Uses DJoin.exe to provision a machine and create an ODJ Request File.
#>
function Join-Domain {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ComputerName,

        [System.String]
        $Path,

        [System.String]
        $DomainController,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RequestFile
    )

    Write-Verbose -Message ( @(
        "$($MyInvocation.MyCommand): "
        $($LocalizedData.ODJRequestStartMessage) `
            -f $DomainName,$ComputerName,$RequestFile `
        ) -join '' )

    $DJoinParameters = @(
        '/PROVISION'
        '/DOMAIN',$DomainName
        '/MACHINE',$ComputerName )
    if ($Path)
    {
        $DJoinParameters += @( '/MACHINEOU',$Path )
    } # if

    if ($DomainController)
    {
        $DJoinParameters += @( '/DCNAME',$DomainController )
    } # if

    $DJoinParameters += @( '/SAVEFILE',$RequestFile )
    $Result = & djoin.exe @DjoinParameters

    if ($LASTEXITCODE -ne 0)
    {
        Write-Verbose -Message $Result

        $errorId = 'DjoinError'
        $errorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errorMessage = $($LocalizedData.DjoinError) `
            -f $LASTEXITCODE
        $exception = New-Object -TypeName System.ArgumentException `
            -ArgumentList $errorMessage
        $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
            -ArgumentList $exception, $errorId, $errorCategory, $null

        $PSCmdlet.ThrowTerminatingError($errorRecord)
    } # if

    Write-Verbose -Message ( @(
        "$($MyInvocation.MyCommand): "
        $($LocalizedData.ODJRequestCompleteMessage) `
            -f $DomainName,$ComputerName,$RequestFile `
        ) -join '' )
} # function Join-Domain


<#
.SYNOPSIS
Does the computer object already exist in the Domain?
#>
function Test-ComputerAccount
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ComputerName,

        [System.String]
        $Path,

        [System.String]
        $DomainController,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RequestFile
    )
    # It does not matter if Path was specified, if a computer object with
    # the same name exists in the domain, we need to know.
    $Domain = Get-ADDomain -Identity $DomainName
    $Parameters = @{
        searchbase = $Domain.DistinguishedName
        filter = { name -eq $ComputerName }
    }
    if ($DomainController)
    {
        server = $DomainController
    }

    $Computer = Get-ADComputer @Parameters
    if ($Computer)
    {
        return $True
    }
    else
    {
        return $False
    } # if

} # function Test-ComputerAccount

## Import the common AD functions
$adCommonFunctions = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath '\MSFT_xADCommon\MSFT_xADCommon.ps1';
. $adCommonFunctions;

Export-ModuleMember -Function *-TargetResource
