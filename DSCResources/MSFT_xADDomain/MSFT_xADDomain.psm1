#
# xADDomain: DSC resource to install a new Active Directory forest
# configuration, or a child domain in an existing forest.
#

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [String]$ParentDomainName,

        [String]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [PSCredential]$DnsDelegationCredential,

        [String]$DatabasePath,

        [String]$LogPath,

        [String]$SysvolPath
    )

    try
    {
        $fullDomainName = $DomainName
        if ($ParentDomainName)
        {
            $fullDomainName = $DomainName + "." + $ParentDomainName
        }

        Write-Verbose -Message "Resolving '$($fullDomainName)' ..."
        $domain = Get-ADDomain -Identity $fullDomainName -Credential $DomainAdministratorCredential
        if ($domain -ne $null)
        {
            Write-Verbose -Message "Domain '$($fullDomainName)' is present. Looking for DCs ..."
            try
            {
                $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -Credential $DomainAdministratorCredential
                Write-Verbose -Message "Found domain controller '$($dc.Name)' in domain '$($dc.Domain)'."
                Write-Verbose -Message "Found parent domain '$($domain.ParentDomain)', expected '$($ParentDomainName)'."
                if (($dc.Domain -eq $DomainName) -and ((!($dc.ParentDomain) -and !($ParentDomainName)) -or ($dc.ParentDomain -eq $ParentDomainName)))
                {
                    Write-Verbose -Message "Current node '$($dc.Name)' is already a domain controller for domain '$($dc.Domain)'."
                }
            }
            catch
            {
                Write-Verbose -Message "Current node does not host a domain controller."
            }
        }
    }
    catch
    {
        if ($error[0]) {Write-Verbose $error[0].Exception}
        Write-Verbose -Message "Current node is not running AD WS, and hence is not a domain controller."
    }
    @{
        DomainName = $dc.Domain
    }
}

function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [String]$ParentDomainName,

        [String]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [PSCredential]$DnsDelegationCredential,

        [String]$DatabasePath,

        [String]$LogPath,

        [String]$SysvolPath
    )

    # Debug can pause Install-ADDSForest/Install-ADDSDomain, so we remove it.
    $parameters = $PSBoundParameters.Remove("Debug");

    $fullDomainName = $DomainName
    if ($ParentDomainName)
    {
        $fullDomainName = $DomainName + "." + $ParentDomainName
    }

    Write-Verbose -Message "Checking if domain '$($fullDomainName)' is present ..."
    $domain = $null;
    try
    {
        $domain = Get-ADDomain -Identity $fullDomainName -Credential $DomainAdministratorCredential
    }
    catch
    {
    }
    if ($domain -ne $null)
    {
        throw (new-object -TypeName System.InvalidOperationException -ArgumentList "Domain '$($Name)' is already present, but it is not hosted by this node.")
    }

    Write-Verbose -Message "Verified that domain '$($DomainName)' is not already present, continuing ..."
    if (($ParentDomainName -eq $null) -or ($ParentDomainName -eq ""))
    {
        Write-Verbose -Message "Domain '$($DomainName)' is NOT present. Creating forest '$($DomainName)' ..."
        $params = @{
            DomainName = $DomainName
            SafeModeAdministratorPassword = $SafemodeAdministratorPassword.Password
            InstallDns = $true
            NoRebootOnCompletion = $true
            Force = $true
        }
        if ($DomainNetbiosName.length -gt 0)
        {
            $params.Add("NewDomainNetbiosName", $DomainNetbiosName)
        }
        if ($DnsDelegationCredential -ne $null)
        {
            $params.Add("DnsDelegationCredential", $DnsDelegationCredential)
            $params.Add("CreateDnsDelegation", $true)
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

        Install-ADDSForest @params 
        Write-Verbose -Message "Created forest '$($DomainName)'."
    }
    else
    {
        Write-Verbose -Message "Domain '$($DomainName)' is NOT present. Creating domain '$($DomainName)' as a child of '$($ParentDomainName)' ..."
        $params = @{
            NewDomainName = $DomainName
            ParentDomainName = $ParentDomainName
            DomainType = "ChildDomain"
            SafeModeAdministratorPassword = $SafemodeAdministratorPassword.Password
            Credential = $DomainAdministratorCredential
            InstallDns = $true
            NoRebootOnCompletion = $true
            Force = $true
        }
        if ($DomainNetbiosName.length -gt 0)
        {
            $params.Add("NewDomainNetbiosName", $DomainNetbiosName)
        }
        if ($DnsDelegationCredential -ne $null)
        {
            $params.Add("DnsDelegationCredential", $DnsDelegationCredential)
            $params.Add("CreateDnsDelegation", $true)
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

        Install-ADDSDomain @params
        Write-Verbose -Message "Created domain '$($DomainName)'."
    }

    if ($error[0]) {Write-Verbose $error[0].Exception}

    # Signal to the LCM to reboot the node to compensate for the one we
    # suppressed from Install-ADDSForest/Install-ADDSDomain
    $global:DSCMachineStatus = 1
}

function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [String]$ParentDomainName,

        [String]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [PSCredential]$DnsDelegationCredential,

        [String]$DatabasePath,

        [String]$LogPath,

        [String]$SysvolPath
    )
    try
    {
        $parameters = $PSBoundParameters.Remove("Debug");
        $existingResource = Get-TargetResource @PSBoundParameters
        
        $fullDomainName = $DomainName
        if ($ParentDomainName)
        {
            $fullDomainName = $DomainName + "." + $ParentDomainName
        }
        $existingResource.DomainName -eq $fullDomainName
    }
    catch
    {
        Write-Verbose -Message "Domain '$($Name)' is NOT present on the current node."
        $false
    }
}


Export-ModuleMember -Function *-TargetResource

