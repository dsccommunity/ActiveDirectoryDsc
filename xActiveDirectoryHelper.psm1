# Set Global Module Verbose
$VerbosePreference = 'Continue' 

# Load Localization Data 
Import-LocalizedData LocalizedData -filename xActiveDirectory.strings.psd1 -ErrorAction SilentlyContinue
Import-LocalizedData USLocalizedData -filename xActiveDirectory.strings.psd1 -UICulture en-US -ErrorAction SilentlyContinue

function New-TerminatingError 
{
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ErrorType,

        [parameter(Mandatory = $false)]
        [String[]]
        $FormatArgs,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorCategory]
        $ErrorCategory = [System.Management.Automation.ErrorCategory]::OperationStopped,

        [parameter(Mandatory = $false)]
        [Object]
        $TargetObject = $null
    )

    $errorMessage = $LocalizedData.$ErrorType
    
    if(!$errorMessage)
    {
        $errorMessage = ($LocalizedData.NoKeyFound -f $ErrorType)

        if(!$errorMessage)
        {
            $errorMessage = ("No Localization key found for key: {0}" -f $ErrorType)
        }
    }

    $errorMessage = ($errorMessage -f $FormatArgs)

    $callStack = Get-PSCallStack 

    # Get Name of calling script
    if($callStack[1] -and $callStack[1].ScriptName)
    {
        $scriptPath = $callStack[1].ScriptName

        $callingScriptName = $scriptPath.Split('\')[-1].Split('.')[0]
    
        $errorId = "$callingScriptName.$ErrorType"
    }
    else
    {
        $errorId = $ErrorType
    }


    Write-Verbose -Message "$($USLocalizedData.$ErrorType -f $FormatArgs) | ErrorType: $errorId"

    $exception = New-Object System.Exception $errorMessage;
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $ErrorCategory, $TargetObject

    return $errorRecord
}

function Assert-Module 
{ 
    [CmdletBinding()] 
    param 
    ( 
        [parameter(Mandatory = $true)]
        [string]$ModuleName
    ) 

    # This will check for all the modules that are loaded or otherwise
    if(!(Get-Module -Name $ModuleName))
    {
        if (!(Get-Module -Name $ModuleName -ListAvailable)) 
        { 
            throw New-TerminatingError -ErrorType ModuleNotFound -FormatArgs @($ModuleName) -ErrorCategory ObjectNotFound -TargetObject $ModuleName 
        }
        else
        {
            Write-Verbose -Message "PowerShell Module '$ModuleName' is installed on the $env:COMPUTERNAME"

            Write-Verbose "Loading $ModuleName Module"
           
            $CurrentVerbose = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            $null = Import-Module -Name $ModuleName -ErrorAction Stop
            $VerbosePreference = $CurrentVerbose
        }
    }
}