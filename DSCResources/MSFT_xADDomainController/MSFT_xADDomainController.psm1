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
        [PSCredential]$SafemodeAdministratorPassword
    )

    $returnValue = @{
        DomainName = $DomainName
        Ensure     = 'Absent'
    }

    try
    {
        Write-Verbose -Message "Resolving $DomainName..."
        $domain = Get-ADDomain -Identity $DomainName -Credential $DomainAdministratorCredential
        if( $domain -ne $null )
        {
            Write-Verbose -Message "Domain $DomainName is present. Looking for DCs"
            try
            {
                $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -Credential $DomainAdministratorCredential
                Write-Verbose -Message "Got Domain Controller $($dc.Name) in domain $($dc.Domain)."
                if($dc.Domain -eq $DomainName)
                {
                    Write-Verbose -Message "Current node $($dc.Name) is already a domain controller for $($dc.Domain)."
                    $returnValue.Ensure = 'Present'
                }
            }
            catch
            {
                Write-Verbose -Message "No domain controllers could be contacted for $DomainName"
            }
        }
    }
    catch
    {
        Write-Error -Message "Target Machine is not running AD WS, and hence is not a domain controller"
        throw $_
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
        [PSCredential]$SafemodeAdministratorPassword
    )
    
    $parameters = $PSBoundParameters.Remove("Debug");

    Write-Verbose -Message "Checking if Domain $DomainName is present ..."
    # Check if the domain exists
    $domain = $null;
    try
    {
        $domain = Get-ADDomain -Identity $DomainName -Credential $DomainAdministratorCredential
    }
    catch
    {
        Write-Error -Message "Domain $DomainName could not be found. Assert a domain resource first."
        throw (new-object -TypeName System.InvalidOperationException -ArgumentList "Domain $DomainName could not be found.")
    }

    Write-Verbose -Message "Verified that Domain $DomainName is present in the network. Going on to create the domain controller."

    Install-ADDSDomainController -DomainName $DomainName -Force -Verbose:$false -NoRebootOnCompletion `
                        -SafeModeAdministratorPassword $SafemodeAdministratorPassword.Password `
                        -Credential $DomainAdministratorCredential
                
    Write-Verbose -Message "Node is now a domain controller for $DomainName"
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

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [Parameter(Mandatory)]
        [PSCredential]$SafemodeAdministratorPassword
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
        Write-Error -Message "Domain $DomainName is NOT present on the node"
        throw $_
    } 
}
