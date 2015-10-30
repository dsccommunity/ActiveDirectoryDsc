<#
Introduction

The xOu module is a part of the ALM Ranger DevOps solutions (vsardevops.codeplex.com), which consists of code as config guidance, quick reference posters and supporting resources.
This module contains the xAdOrganizationalUnit resource. This resource allows configuration of Organizational Units (OUs) in Active Directory (AD).
#>

# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
RoleNotFoundError        = Please ensure that the PowerShell module for role '{0}' is installed
UpdatingOU               = Updating OU '{0}'
DeletingOU               = Deleting OU '{0}'
CreatingOU               = Creating OU '{0}'
OUInDesiredState         = OU '{0}' exists and is in the desired state
OUNotInDesiredState      = OU '{0}' exists but is not in the desired state
OUExistsButShouldNot     = OU '{0}' exists when it should not exist
OUDoesNotExistButShould  = OU '{0}' does not exist when it should exist
'@
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (    
        [parameter(Mandatory)] 
        [System.String] $Name,

        [parameter(Mandatory)] 
        [System.String] $Path
    )
    
    Assert-Module -ModuleName 'ActiveDirectory';
    $ou = Get-ADOrganizationalUnit -Filter { Name -eq $Name } -SearchBase $Path -SearchScope OneLevel -Properties ProtectedFromAccidentalDeletion, Description

    $targetResource = @{
        Name = $Name
        Path = $Path
        Ensure = 'Present'
        ProtectedFromAccidentalDeletion = if ($ou.ProtectedFromAccidentalDeletion) { 'Yes' } else { 'No' }
        Description = $ou.Description
    }

    if ($ou -eq $null) {
        $targetResource['Ensure'] = 'Absent'
    }

    return $targetResource

} # end function Get-TargetResource

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (    
        [parameter(Mandatory)] 
        [System.String] $Name,

        [parameter(Mandatory)] 
        [System.String] $Path,
        
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $Credential,

        [ValidateNotNull()]
        [ValidateSet('No', 'Yes')]
        [System.String] $ProtectedFromAccidentalDeletion = 'Yes',

        [ValidateNotNull()]
        [System.String]
        $Description = ''
    )

    $targetResource = Get-TargetResource -Name $Name -Path $Path
    
    if ($targetResource.Ensure -eq 'Present')
    {
        if ($Ensure -eq 'Present')
        {
            ## Organizational unit exists
            if ([System.String]::IsNullOrEmpty($Description)) {
                $isCompliant = (($targetResource.Name -eq $Name) -and
                                    ($targetResource.Path -eq $Path) -and
                                        ($targetResource.ProtectedFromAccidentalDeletion -eq $ProtectedFromAccidentalDeletion))
            }
            else {
                $isCompliant = (($targetResource.Name -eq $Name) -and
                                    ($targetResource.Path -eq $Path) -and
                                        ($targetResource.ProtectedFromAccidentalDeletion -eq $ProtectedFromAccidentalDeletion) -and
                                            ($targetResource.Description -eq $Description))
            }

            if ($isCompliant)
            {
                Write-Verbose ($LocalizedData.OUInDesiredState -f $targetResource.Name)
            }
            else
            {
                Write-Verbose ($LocalizedData.OUNotInDesiredState -f $targetResource.Name)
            }
        }
        else
        {
            $isCompliant = $false
            Write-Verbose ($LocalizedData.OUExistsButShouldNot -f $targetResource.Name)
        }
    }
    else
    {
        ## Organizational unit does not exist
        if ($Ensure -eq 'Present')
        {
            $isCompliant = $false
            Write-Verbose ($LocalizedData.OUDoesNotExistButShould -f $targetResource.Name)
        }
        else
        {
            $isCompliant = $true
            Write-Verbose ($LocalizedData.OUInDesiredState -f $targetResource.Name)
        }
    }

    return $isCompliant

} #end function Test-TargetResource

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (    
        [parameter(Mandatory)] 
        [System.String] $Name,

        [parameter(Mandatory)] 
        [System.String] $Path,
        
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $Credential,

        [ValidateNotNull()]
        [ValidateSet('No', 'Yes')]
        [System.String] $ProtectedFromAccidentalDeletion = 'Yes',

        [ValidateNotNull()]
        [System.String]
        $Description = ''
    )

    Assert-Module -ModuleName 'ActiveDirectory';
    $targetResource = Get-TargetResource -Name $Name -Path $Path
    
    if ($targetResource.Ensure -eq 'Present')
    {
        $ou = Get-ADOrganizationalUnit -Filter { Name -eq $Name } -SearchBase $Path -SearchScope OneLevel
        if ($Ensure -eq 'Present')
        {
            Write-Verbose ($LocalizedData.UpdatingOU -f $targetResource.Name)
            $setADOrganizationalUnitParams = @{
                Identity = $ou
                Description = $Description
                ProtectedFromAccidentalDeletion = ($ProtectedFromAccidentalDeletion -eq 'Yes')
            }
            if ($Credential)
            {
                $setADOrganizationalUnitParams['Credential'] = $Credential
            }
            Set-ADOrganizationalUnit @setADOrganizationalUnitParams
        }
        else
        {
            Write-Verbose ($LocalizedData.DeletingOU -f $targetResource.Name)
            if ($targetResource.ProtectedFromAccidentalDeletion -eq 'Yes')
            {
                $setADOrganizationalUnitParams = @{
                    Identity = $ou
                    ProtectedFromAccidentalDeletion = ($ProtectedFromAccidentalDeletion -eq 'Yes')
                }
                if ($Credential)
                {
                    $setADOrganizationalUnitParams['Credential'] = $Credential
                }
                Set-ADOrganizationalUnit @setADOrganizationalUnitParams
            }

            $removeADOrganizationalUnitParams = @{
                Identity = $ou
            }
            if ($Credential)
            {
                $removeADOrganizationalUnitParams['Credential'] = $Credential
            }
            Remove-ADOrganizationalUnit @removeADOrganizationalUnitParams
        }
    }
    else
    {
        Write-Verbose ($LocalizedData.CreatingOU -f $targetResource.Name)
        $newADOrganizationalUnitParams = @{
            Name = $Name
            Path = $Path
            Description = $Description
            ProtectedFromAccidentalDeletion = ($ProtectedFromAccidentalDeletion -eq "Yes")
        }
        if ($Credential) {
            $newADOrganizationalUnitParams['Credential'] = $Credential
        }
        New-ADOrganizationalUnit @newADOrganizationalUnitParams
    }

} #end function Set-TargetResource

# Internal function to assert if the role specific module is installed or not
function Assert-Module
{
    [CmdletBinding()]
    param (
        [System.String] $ModuleName = 'ActiveDirectory'
    )

    if (-not (Get-Module -Name $ModuleName -ListAvailable))
    {
        $errorMsg = $($LocalizedData.RoleNotFoundError) -f $moduleName;
        $exception = New-Object System.InvalidOperationException $errorMessage;
        $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null;
        throw $errorRecord;
    }
} #end function Assert-Module

Export-ModuleMember -Function *-TargetResource
