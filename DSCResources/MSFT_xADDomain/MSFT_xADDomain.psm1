function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [String]$ParentDomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [PSCredential]$DnsDelegationCredential
    )

    $returnValue = @{
        DomainName = $DomainName
        Ensure     = 'Absent'
    }

    try
    {
        $fullDomainName = $DomainName
        if( $ParentDomainName )
        {
          $fullDomainName = $DomainName + "." + $ParentDomainName
        }

        Write-Verbose -Message "Resolving $fullDomainName..."
        $domain = Get-ADDomain -Identity $fullDomainName -Credential $DomainAdministratorCredential
        if( $domain -ne $null )
        {
            Write-Verbose -Message "Domain $fullDomainName is present. Looking for DCs"
            try
            {
                $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -Credential $DomainAdministratorCredential
                Write-Verbose -Message "Got Domain Controller $($dc.Name) in domain $($dc.Domain). Parent domain was $($dc.ParentDomain), $ParentDomainName was asked for"
                if(($dc.Domain -eq $DomainName) -and ( ( !($dc.ParentDomain) -and  !($ParentDomainName) ) -or ($dc.ParentDomain -eq $ParentDomainName)))
                {
                    Write-Verbose -Message "Current node $($dc.Name) is already a domain controller for $($dc.Domain). Parent Domain "
                    $returnValue.Ensure = 'Present'
                }
            }
            catch
            {
                Write-Verbose -Message "The local computer does not host a domain controller"
            }
        }
    }
    catch
    {
        Write-Verbose -Message "Target Machine is not running AD WS, and hence is not a domain controller"
    }
    $returnValue
}


function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [String]$ParentDomainName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [PSCredential]$DnsDelegationCredential
    )
    
    $parameters = $PSBoundParameters.Remove("Debug");

    $fullDomainName = $DomainName
    if( $ParentDomainName )
    {
      $fullDomainName = $DomainName + "." + $ParentDomainName
    }
    
    Write-Verbose -Message "Checking if Domain $fullDomainName is present ..."
    # Check if the domain exists
    $domain = $null;
    try
    {
        $domain = Get-ADDomain -Identity $fullDomainName -Credential $DomainAdministratorCredential
    }
    catch
    {
    }
    if( $domain -ne $null )
    {
        Write-Error -Message "Domain $DomainName is already present, but is not hosted by this node. Returning error"
        throw (new-object -TypeName System.InvalidOperationException -ArgumentList "Domain $DomainName is already present, but is not hosted by this node")
    }

    Write-Verbose -Message "Verified that Domain $DomainName is not already present in the network. Going on to create the domain."
    if( ( $ParentDomainName -eq $null ) -or ( $ParentDomainName -eq "" ) )
    {
        Write-Verbose -Message "Domain $DomainName is NOT present. Creating Forest $DomainName ..."
    
        $params = @{ DomainName = $DomainName; SafeModeAdministratorPassword = $SafemodeAdministratorPassword.Password; NoRebootOnCompletion = $true; InstallDns = $true; Force = $true }
        if( $DnsDelegationCredential -ne $null )
        {
            $params.Add( "DnsDelegationCredential", $DnsDelegationCredential )
            $params.Add( "CreateDnsDelegation", $true )
        }
        Install-ADDSForest @params 
                    
        Write-Verbose -Message "Created Forest $DomainName"
    }
    else
    {
        Write-Verbose -Message "Domain $DomainName is NOT present. Creating domain $DomainName as a child of $ParentDomainName..."
        Import-Module -Name ADDSDeployment
        $params = @{ NewDomainName = $DomainName; ParentDomainName = $ParentDomainName; DomainType = [Microsoft.DirectoryServices.Deployment.Types.DomainType]::ChildDomain; SafeModeAdministratorPassword = $SafemodeAdministratorPassword.Password; Credential = $DomainAdministratorCredential; NoRebootOnCompletion = $true; InstallDns = $true; Force = $true }
        if( $DnsDelegationCredential -ne $null )
        {
            $params.Add( "DnsDelegationCredential", $DnsDelegationCredential )
            $params.Add( "CreateDnsDelegation", $true )
        }
        Install-ADDSDomain @params        
        Write-Verbose -Message "Created Domain $DomainName"
    }
    
    Write-Verbose -Message "Indicating to LCM that system needs reboot."
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

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword,

        [PSCredential]$DnsDelegationCredential
    )
    try
    {
        $parameters = $PSBoundParameters.Remove("Debug");
        $existingResource = Get-TargetResource @PSBoundParameters
        ($existingResource.Ensure -eq 'Present')
    }
    # If the domain doesn't exist
    catch
    {
        Write-Verbose -Message "Domain $DomainName is NOT present on the node"
        $false
    } 
}

