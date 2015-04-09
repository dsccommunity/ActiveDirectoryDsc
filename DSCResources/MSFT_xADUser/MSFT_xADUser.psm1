function Get-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,
        
        [PSCredential]$Password,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present"                   
    )

    try
    {
        Write-Verbose -Message "Checking if the user $UserName in domain $DomainName is present ..."
        $user = Get-AdUser -Identity $UserName -Credential $DomainAdministratorCredential
        Write-Verbose -Message "User $UserName in domain $DomainName is present."
        $Ensure = "Present"
    }
    # User not found
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message "User $UserName account in domain $DomainName is NOT present"
        $Ensure = "Absent"
    }
    catch
    {
        Write-Error -Message "Unhandled exception looking up $UserName account in domain $DomainName."
        throw $_
    }

    @{
        DomainName = $DomainName
        UserName = $UserName
        Ensure = $Ensure
    }
}

function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$UserName,
        
        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [PSCredential]$Password,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present"                    
    )
    try
    {
        ValidateProperties @PSBoundParameters -Apply
    }
    catch
    {
        Write-Error -Message "Error setting AD User $UserName in domain $DomainName. $_"
        throw $_
    }
}

function Test-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$UserName,
        
        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [PSCredential]$Password,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present"          
    )

    try
    {
        $parameters = $PSBoundParameters.Remove("Debug");
        ValidateProperties @PSBoundParameters    
    }
    catch
    {
        Write-Error -Message "Error testing AD User $UserName in domain $DomainName. $_"
        throw $_
    }
}

function ValidateProperties
{
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,

        [PSCredential]$Password,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present",          

        [Switch]$Apply
    )

    $result = $true
    # Check if user exists and if user exists validate the password
    try
    {
        Write-Verbose -Message "Checking if the user $UserName in domain $DomainName is present ..."
        $user = Get-AdUser -Identity $UserName -Credential $DomainAdministratorCredential
        Write-Verbose -Message "User $UserName in domain $DomainName is present."
        
        if( $Ensure -eq "Absent" )
        {
            if( $Apply )
            {
                Remove-ADUser -Identity $UserName -Credential $DomainAdministratorCredential -Confirm:$false
                return
            }
            else
            {
                return $false
            }
        }
        
        if($Apply)
        {
            # If account is not enabled, enable it. Needed for password validation
            If(!($user.Enabled))
            {
                Set-AdUser -Identity $UserName -Enabled $true -Credential $DomainAdministratorCredential
                Write-Verbose -Message "Enabled $UserName account in domain $DomainName."
            }
        }
        
        # If password is specified, check if it is valid
        if($Password)
        {
            Write-Verbose -Message "Checking if the user $UserName password is valid ..."
            Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement'
            
            Write-Verbose -Message "Creating connection to the domain $DomainName ..."
            $prnContext = new-object System.DirectoryServices.AccountManagement.PrincipalContext(
                            "Domain", $DomainName, $DomainAdministratorCredential.UserName, `
                            $DomainAdministratorCredential.GetNetworkCredential().Password)

            # This can return true or false
            $result = $prnContext.ValidateCredentials($UserName,$Password.GetNetworkCredential().Password)
            if($result)
            {
                Write-Verbose -Message "User $UserName password is valid"
                return $true
            }
            else
            {
                Write-Verbose -Message "User $UserName password is NOT valid"
                if($Apply)
                {
                    Set-AdAccountPassword -Reset -Identity $UserName -NewPassword $Password.Password -Credential $DomainAdministratorCredential
                    Write-Verbose -Message "User $UserName password has been reset"
                }
                else
                {
                    return $false
                }
            }
        }
        else
        {
            Write-Verbose -Message "User $UserName account in domain $DomainName is present"
            return $true
        }
    }
    # User not found
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message "User $UserName account in domain $DomainName is NOT present"
        if($Apply)
        {
            if( $Ensure -ne "Absent" )
            {
                $params = @{ Name = $UserName; Enabled = $true; Credential = $DomainAdministratorCredential }
                if( $Password )
                {
                    $params.Add( "AccountPassword", $Password.Password )
                }
                New-AdUser @params
                Write-Verbose -Message "User $UserName account in domain $DomainName has been created"
            }
        }
        else
        {
            return ( $Ensure -eq "Absent" )
        }
    }
}

Export-ModuleMember -Function *-TargetResource
