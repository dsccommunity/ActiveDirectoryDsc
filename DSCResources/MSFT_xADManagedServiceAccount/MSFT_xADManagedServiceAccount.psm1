## Import the common AD functions
$adCommonFunctions = Join-Path `
    -Path (Split-Path -Path $PSScriptRoot -Parent) `
    -ChildPath '\MSFT_xADCommon\MSFT_xADCommon.psm1'
Import-Module -Name $adCommonFunctions

# Localized messages
data LocalizedData
{
    # culture='en-US'
    ConvertFrom-StringData @'
        AddingManagedServiceAccount           = Adding AD Managed Service Account '{0}'.
        UpdatingManagedServiceAccount         = Updating AD Managed Service Account '{0}'.
        RemovingManagedServiceAccount         = Removing AD Managed Service Account '{0}'.
        MovingManagedServiceAccount           = Moving AD Managed Service Account '{0}' to '{1}'.
        ManagedServiceAccountNotFound         = AD Managed Service Account '{0}' was not found.
        NotDesiredPropertyState               = AD Managed Service Account '{0}' is not correct. Expected '{1}', actual '{2}'.
        UpdatingManagedServiceAccountProperty = Updating AD Managed Service Account property '{0}' to '{1}'.
        AddingManagedServiceAccountError      = Error adding AD Managed Service Account '{0}'.
        UpdatingManagedServiceAccountError    = Error updating AD Managed Service Account '{0}'.
        MovingManagedServiceAccountError      = Error moving AD Managed Service Account '{0}'.
        RemovingManagedServiceAccountError    = Error removing AD Managed Service Account '{0}'.
'@
}

<#
    .SYNOPSIS
        Gets the specified managed service account.

    .PARAMETER ServiceAccountName
        Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to use to perform the task.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServiceAccountName,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController
    )

    Assert-Module -ModuleName 'ActiveDirectory'
    $adServiceAccountParams = Get-ADCommonParameters @PSBoundParameters

    $targetResource = @{
        ServiceAccountName = $ServiceAccountName
        Path = $null
        Description = $null
        DisplayName = $null
        Ensure = 'Absent'
        Credential = $Credential
        DomainController = $DomainController
    }

    try
    {
        $adServiceAccount = Get-ADServiceAccount @adServiceAccountParams -Property Name,DistinguishedName,Description,DisplayName

        $targetResource['Path'] = Get-ADObjectParentDN -DN $adServiceAccount.DistinguishedName
        $targetResource['Description'] = $adServiceAccount.Description
        $targetResource['DisplayName'] = $adServiceAccount.DisplayName

        if ($adServiceAccount)
        {
            $targetResource['Ensure'] = 'Present'
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose ($LocalizedData.ManagedServiceAccountNotFound -f $ServiceAccountName)
    }
    return $targetResource
} #end function Get-TargetResource

<#
    .SYNOPSIS
        Tests the state of the managed service account.

    .PARAMETER ServiceAccountName
        Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER Path
        Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created.

    .PARAMETER Ensure
        Specifies whether the user account is created or deleted.

    .PARAMETER Description
        Specifies a description of the object (ldapDisplayName 'description').

    .PARAMETER DisplayName
        Specifies the display name of the object (ldapDisplayName 'displayName').

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to use to perform the task.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServiceAccountName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController
    )

    $getTargetResource = Get-TargetResource @PSBoundParameters
    $targetResourceInCompliance = $true

    if ($Path -and ($getTargetResource.Path -ne $Path))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Path', $Path, $getTargetResource.Path)
        $targetResourceInCompliance = $false
    }

    if ($Description -and ($getTargetResource.Description -ne $Description))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Description', $Description, $getTargetResource.Description)
        $targetResourceInCompliance = $false
    }

    if ($DisplayName -and ($getTargetResource.DisplayName -ne $DisplayName))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'DisplayName', $DisplayName, $getTargetResource.DisplayName)
        $targetResourceInCompliance = $false
    }

    if ($getTargetResource.Ensure -ne $Ensure)
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Ensure', $Ensure, $getTargetResource.Ensure)
        $targetResourceInCompliance = $false
    }

    return $targetResourceInCompliance
} #end function Test-TargetResource

<#
    .SYNOPSIS
        Adds, removes, or updates the managed service account.

    .PARAMETER ServiceAccountName
        Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER Path
        Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created.

    .PARAMETER Ensure
        Specifies whether the user account is created or deleted.

    .PARAMETER Description
        Specifies a description of the object (ldapDisplayName 'description').

    .PARAMETER DisplayName
        Specifies the display name of the object (ldapDisplayName 'displayName').

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to use to perform the task.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServiceAccountName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController
    )

    Assert-Module -ModuleName 'ActiveDirectory'
    $adServiceAccountParams = Get-ADCommonParameters @PSBoundParameters

    try
    {
        # Get the service account
        $adServiceAccount = Get-ADServiceAccount @adServiceAccountParams -Property Name,DistinguishedName,Description,DisplayName
    }
    catch
    {
        # The service account doesn't exist
        if ($Ensure -eq 'Present')
        {
            Write-Verbose ($LocalizedData.AddingManagedServiceAccount -f $ServiceAccountName)

            $adServiceAccountParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter

            if ($Description)
            {
                $adServiceAccountParams['Description'] = $Description
            }

            if ($DisplayName)
            {
                $adServiceAccountParams['DisplayName'] = $DisplayName
            }

            if ($Path)
            {
                $adServiceAccountParams['Path'] = $Path
            }

            # Create service account
            try
            {
                $adServiceAccount = New-ADServiceAccount @adServiceAccountParams -RestrictToSingleComputer -Enabled $true -PassThru
            }
            catch
            {
                Write-Error -Message ($LocalizedData.AddingManagedServiceAccountError -f $ServiceAccountName)
                throw $_
            }

            return
        }
        elseif ($Ensure -eq 'Absent')
        {
            # Do nothing - account should be absent and is
            return
        }
    }

    if ($Ensure -eq 'Present')
    {
        $setADServiceAccountParams = $adServiceAccountParams.Clone()
        $setADServiceAccountParams['Identity'] = $adServiceAccount.DistinguishedName

        $targetResourceInCompliance = $true

        # Update existing group properties
        if ($Description -and ($Description -ne $adServiceAccount.Description))
        {
            Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'Description', $Description)
            $setADServiceAccountParams['Description'] = $Description
            $targetResourceInCompliance = $false
        }

        if ($DisplayName -and ($DisplayName -ne $adServiceAccount.DisplayName))
        {
            Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'DisplayName', $DisplayName)
            $setADServiceAccountParams['DisplayName'] = $DisplayName
            $targetResourceInCompliance = $false
        }

        if (-not $targetResourceInCompliance)
        {
            Write-Verbose ($LocalizedData.UpdatingManagedServiceAccount -f $ServiceAccountName)
            try
            {
                Set-ADServiceAccount @setADServiceAccountParams
            }
            catch
            {
                Write-Error -Message ($LocalizedData.UpdatingManagedServiceAccountError -f $ServiceAccountName)
                throw $_
            }
        }

        # Move service account if the path is not correct
        if ($Path -and ($Path -ne (Get-ADObjectParentDN -DN $adServiceAccount.DistinguishedName)))
        {
            Write-Verbose ($LocalizedData.MovingManagedServiceAccount -f $ServiceAccountName, $Path)
            $moveADObjectParams = $adServiceAccountParams.Clone()
            $moveADObjectParams['Identity'] = $adServiceAccount.DistinguishedName

            try
            {
                Move-ADObject @moveADObjectParams -TargetPath $Path
            }
            catch
            {
                Write-Error -Message ($LocalizedData.MovingManagedServiceAccountError -f $ServiceAccountName)
                throw $_
            }
        }
    }
    elseif ($Ensure -eq 'Absent')
    {
        # Remove existing service account
        Write-Verbose ($LocalizedData.RemovingManagedServiceAccount -f $ServiceAccountName)

        try
        {
            Remove-ADServiceAccount @adServiceAccountParams -Confirm:$false
        }
        catch
        {
            Write-Error -Message ($LocalizedData.RemovingManagedServiceAccountError -f $ServiceAccountName)
            throw $_
        }
    }
} #end function Set-TargetResource

Export-ModuleMember -Function *-TargetResource
