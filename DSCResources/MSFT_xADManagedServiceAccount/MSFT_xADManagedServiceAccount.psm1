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
        RetrievingServiceAccount              = Retrieving AD Managed Service Account '{0}' ...
        NotDesiredPropertyState               = AD Managed Service Account '{0}' is not correct. Expected '{1}', actual '{2}'.
        MSAInDesiredState                     = AD Managed Service Account '{0}' is in the desired state.
        MSANotInDesiredState                  = AD Managed Service Account '{0}' is NOT in the desired state.
        UpdatingManagedServiceAccountProperty = Updating AD Managed Service Account property '{0}' to '{1}'.
        AddingManagedServiceAccountError      = Error adding AD Managed Service Account '{0}'.
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
        AccountType = 'Single'
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
        if ( $adServiceAccount.ObjectClass -eq 'msDS-ManagedServiceAccount' )
        {
            $targetResource['AccountType'] = 'Single'
        }
        elseif ( $adServiceAccount.ObjectClass -eq 'msDS-GroupManagedServiceAccount' )
        {
            $targetResource['AccountType'] = 'Group'
        }

        if ($adServiceAccount)
        {
            $targetResource['Ensure'] = 'Present'
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose ($LocalizedData.ManagedServiceAccountNotFound -f $ServiceAccountName)
    }
    catch
    {
        Write-Error -Message ($LocalizedData.RetrievingServiceAccount -f $ServiceAccountName);
        throw $_;
    }
    return $targetResource
} #end function Get-TargetResource

<#
    .SYNOPSIS
        Tests the state of the managed service account.

    .PARAMETER ServiceAccountName
        Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER AccountType
        Specifies the type of managed service account, whether it should be a group or single computer service account

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
        [ValidateSet('Group', 'Single')]
        [System.String]
        $AccountType = 'Single',

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

    $getTargetResourceParameters = @{
        ServiceAccountName = $ServiceAccountName
        Credential         = $Credential
        DomainController   = $DomainController
    }

    @($getTargetResourceParameters.Keys) | ForEach-Object {
        if( !$PSBoundParameters.ContainsKey($_) )
        {
            $getTargetResourceParameters.Remove($_)
        }
    }

    $getTargetResource = Get-TargetResource @getTargetResourceParameters
    $targetResourceInCompliance = $true

    if ($Ensure -eq 'Absent')
    {
        if ($getTargetResource.Ensure -eq 'Present')
        {
            Write-Verbose ($LocalizedData.NotDesiredPropertyState -f `
                            'Ensure', $PSBoundParameters.Ensure, $getTargetResource.Ensure)
            $targetResourceInCompliance = $false
        }
    }
    else
    {
        # Add ensure as it may not explicitly be passed and we want to enumerate it
        $PSBoundParameters['Ensure']      = $Ensure;
        $PSBoundParameters['AccountType'] = $AccountType;

        foreach ($parameter in $PSBoundParameters.Keys)
        {
            if ($getTargetResource.ContainsKey($parameter))
            {
                # This check is required to be able to explicitly remove values with an empty string, if required
                if (([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter)) -and
                    ([System.String]::IsNullOrEmpty($getTargetResource.$parameter)))
                {
                    # Both values are null/empty and therefore we are compliant
                }
                elseif ($PSBoundParameters.$parameter -ne $getTargetResource.$parameter)
                {
                    Write-Verbose -Message ($LocalizedData.NotDesiredPropertyState -f `
                                            $parameter, $PSBoundParameters.$parameter, $getTargetResource.$parameter);
                    $targetResourceInCompliance = $false;
                }
            }
        } #end foreach PSBoundParameter

    }

    if ($targetResourceInCompliance)
    {
        Write-Verbose -Message ($LocalizedData.MSAInDesiredState -f $ServiceAccountName)
        return $true
    }
    else
    {
        Write-Verbose -Message ($LocalizedData.MSANotInDesiredState -f $ServiceAccountName)
        return $false
    }
} #end function Test-TargetResource

<#
    .SYNOPSIS
        Adds, removes, or updates the managed service account.

    .PARAMETER ServiceAccountName
       Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER AccountType
        Specifies the type of managed service account, whether it should be a group or single computer service account

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
        [ValidateSet('Group', 'Single')]
        [System.String]
        $AccountType = 'Single',

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

        if ($Ensure -eq 'Present')
        {
            $setADServiceAccountParams = $adServiceAccountParams.Clone()
            $setADServiceAccountParams['Identity'] = $adServiceAccount.DistinguishedName

            if ( $PSBoundParameters.ContainsKey('AccountType') -and $AccountType -ne $adServiceAccount.AccountType)
            {
                Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'AccountType', $AccountType)
                # TODO: Need to recreate service account
                # Possible logic:
                # Remove-ADServiceAccount
                # Then New-ADServiceAccount
                # This may mean pulling the code for a creating new account and making it a separate
            }

            # Update existing group properties
            if ($PSBoundParameters.ContainsKey('Description') -and $Description -ne $adServiceAccount.Description)
            {
                Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'Description', $Description)
                $setADServiceAccountParams['Description'] = $Description
            }
            if ($PSBoundParameters.ContainsKey('DisplayName') -and $DisplayName -ne $adServiceAccount.DisplayName)
            {
                Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'DisplayName', $DisplayName)
                $setADServiceAccountParams['DisplayName'] = $DisplayName
            }

            Write-Verbose ($LocalizedData.UpdatingManagedServiceAccount -f $ServiceAccountName)
            Set-ADServiceAccount @setADServiceAccountParams

            # Move group if the path is not correct
            if ($Path -and ($Path -ne (Get-ADObjectParentDN -DN $adServiceAccount.DistinguishedName)))
            {
                Write-Verbose ($LocalizedData.MovingManagedServiceAccount -f $ServiceAccountName, $Path)
                $moveADObjectParams = $adServiceAccountParams.Clone()
                $moveADObjectParams['Identity'] = $adServiceAccount.DistinguishedName
                Move-ADObject @moveADObjectParams -TargetPath $Path
            }
        }elseif ($Ensure -eq 'Absent')
        {
            # Remove existing service account
            Write-Verbose ($LocalizedData.RemovingManagedServiceAccount -f $ServiceAccountName)
            Remove-ADServiceAccount @adServiceAccountParams -Confirm:$false
        }

    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
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
            if ( $AccountType -eq 'Single' )
            {
                New-ADServiceAccount @adServiceAccountParams -RestrictToSingleComputer -Enabled $true -PassThru
            }
            elseif( $AccountType -eq 'Group' )
            {
                # TODO: Create logic to create new group managed service account
            }
        }
        elseif ($Ensure -eq 'Absent')
        {
            # Do nothing - account should be absent and is
            return
        }
    }
    catch # Need to add some specific catch errors maybe
    {
        Write-Error -Message ($LocalizedData.AddingManagedServiceAccountError -f $ServiceAccountName)
        throw $_
    }
} #end function Set-TargetResource

Export-ModuleMember -Function *-TargetResource
