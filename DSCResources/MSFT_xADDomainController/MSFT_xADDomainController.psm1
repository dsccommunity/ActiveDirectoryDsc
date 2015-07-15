#
# xADDomainController: DSC resource to install a domain controller in Active
# Directory.
#

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [String]$DatabasePath,

        [String]$LogPath,

        [String]$SysvolPath
    )

    $returnValue = @{
        DomainName = $DomainName
        Ensure = $false
    }

    try
    {
        Write-Verbose -Message "Resolving '$($DomainName)' ..."
        $domain = Get-ADDomain -Identity $DomainName -Credential $DomainAdministratorCredential
        if ($domain -ne $null)
        {
            Write-Verbose -Message "Domain '$($fullDomainName)' is present. Looking for DCs ..."
            try
            {
                $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -Credential $DomainAdministratorCredential
                Write-Verbose -Message "Found domain controller '$($dc.Name)' in domain '$($dc.Domain)'."
                if ($dc.Domain -eq $DomainName)
                {
                    Write-Verbose -Message "Current node '$($dc.Name)' is already a domain controller for domain '$($dc.Domain)'."
                    $returnValue.Ensure = $true
                }
            }
            catch
            {
                if ($error[0]) {Write-Verbose $error[0].Exception}
                Write-Verbose -Message "Current node does not host a domain controller."
            }
        }
    }
    catch
    {
        if ($error[0]) {Write-Verbose $error[0].Exception}
        Write-Verbose -Message "Current node is not running AD WS, and hence is not a domain controller."
    }
    $returnValue
}

function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [String]$DatabasePath,

        [String]$LogPath,

        [String]$SysvolPath
    )

    # Debug can pause Install-ADDSDomainController, so we remove it.
    $parameters = $PSBoundParameters.Remove("Debug");

    Write-Verbose -Message "Checking if domain '$($DomainName)' is present ..."
    $domain = $null;
    try
    {
        $domain = Get-ADDomain -Identity $DomainName -Credential $DomainAdministratorCredential
    }
    catch
    {
        if ($error[0]) {Write-Verbose $error[0].Exception}
        throw (new-object -TypeName System.InvalidOperationException -ArgumentList "Domain '$($DomainName)' could not be found.")
    }

    Write-Verbose -Message "Verified that domain '$($DomainName)' is present, continuing ..."
    $params = @{
        DomainName = $DomainName
        SafeModeAdministratorPassword = $SafemodeAdministratorPassword.Password
        Credential = $DomainAdministratorCredential
        NoRebootOnCompletion = $true
        Force = $true
    }
    if ($DatabasePath -ne $null)
    {
        $params.Add("DatabasePath", $DatabasePath)
    }
    if ($LogPath -ne $null)
    {
        $params.Add("LogPath", $LogPath)
    }
    if ($SysvolPath -ne $null)
    {
        $params.Add("SysvolPath", $SysvolPath)
    }

    Install-ADDSDomainController @params
    Write-Verbose -Message "Node is now a domain controller for '$($DomainName)'."

    # Signal to the LCM to reboot the node to compensate for the one we
    # suppressed from Install-ADDSDomainController
    $global:DSCMachineStatus = 1 
}

function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [String]$DatabasePath,

        [String]$LogPath,

        [String]$SysvolPath
    )

    try
    {
        $parameters = $PSBoundParameters.Remove("Debug");
        $existingResource = Get-TargetResource @PSBoundParameters
        $existingResource.Ensure
    }
    catch
    {
        if ($error[0]) {Write-Verbose $error[0].Exception}
        Write-Verbose -Message "Domain '$($Name)' is NOT present on the current node."
        $false
    }
}


Export-ModuleMember -Function *-TargetResource

