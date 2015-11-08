#
# xADOrganizationalUnit: DSC resource to create a new Active Directory OU
#

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$OUName,

        [Parameter(Mandatory)]
        [string]$OUPath,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,
        
        [bool]$Force,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present"
    )

    try
    {
        Write-Verbose -Message "Checking if the OU '$($OUName)' in domain '$($DomainName)' is present ..."
        $OU = Get-ADOrganizationalUnit -Identity "OU=$($OUName),$($OUPath)" -Credential $DomainAdministratorCredential
        Write-Verbose -Message "Found '$($OUName)' in domain '$($DomainName)'."
        $Ensure = "Present"
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message "OU '$($OUName)' in domain '$($DomainName)' is NOT present."
        $Ensure = "Absent"
    }
    catch
    {
        Write-Error -Message "Error looking up OU '$($UserName)' in domain '$($DomainName)'."
        throw $_
    }

    @{
        DomainName = $DomainName
        OUName = $OUName
        OUPath = $OUPath
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
        [string]$OUName,

        [Parameter(Mandatory)]
        [string]$OUPath,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,
        
        [bool]$Force,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present"
    )
    try
    {
        ValidateProperties @PSBoundParameters -Apply
    }
    catch
    {
        Write-Error -Message "Error configuring OU '$($OUName)' in domain '$($DomainName)'."
        throw $_
    }
}

function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$OUName,

        [Parameter(Mandatory)]
        [string]$OUPath,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,
        
        [bool]$Force,

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
        Write-Error -Message "Error testing OU '$($OUName)' in domain '$($DomainName)'."
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
        [string]$OUName,

        [Parameter(Mandatory)]
        [string]$OUPath,

        [Parameter(Mandatory)]
        [PSCredential]$DomainAdministratorCredential,
        
        [bool]$Force,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present",

        [Switch]$Apply
    )

    $result = $true
    try
    {
        Write-Verbose -Message "Checking if the OU '$($OUName)' in domain '$($DomainName)' is present ..."
        $OU = Get-ADOrganizationalUnit -Identity "OU=$OUName,$OUPath" -Credential $DomainAdministratorCredential
        Write-Verbose -Message "Found '$($OUName)' in domain '$($DomainName)'."
        
        if ($Ensure -eq "Absent")
        {
            if ($Apply)
            {
                Set-ADOrganizationalUnit -Identity "OU=$OUName,$OUPath" -ProtectedFromAccidentalDeletion $false -Credential $DomainAdministratorCredential
                Remove-ADOrganizationalUnit -Identity "OU=$OUName,$OUPath" -Credential $DomainAdministratorCredential -Confirm:$false
                return
            }
            else
            {
                return $false
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message "OU '$($OUName)' in domain '$($DomainName)' is NOT present."
        if ($Apply)
        {
            if ($Ensure -ne "Absent")
            {
                $params = @{
                    Name = $OUName
                    Path = $OUPath
                    Credential = $DomainAdministratorCredential
                }
                New-ADOrganizationalUnit @params
                Write-Verbose -Message "Successfully created OU '$($OUName)' in domain '$($DomainName)'."
            }
        }
        else
        {
            return ($Ensure -eq "Absent")
        }
    }
}


Export-ModuleMember -Function *-TargetResource

