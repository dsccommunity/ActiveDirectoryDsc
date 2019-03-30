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
        RetrievingPrincipalMembers            = Retrieving Principals Allowed To Retrieve Managed Password based on '{0}' property.
'@
}

<#
    .SYNOPSIS
        Gets the specified managed service account.

    .PARAMETER ServiceAccountName
        Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER MembershipAttribute
        Specifies the Attribute to use to describe the Identity used for Members ("SamAccountName","DistinguishedName","ObjectGUID","SID")

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
        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

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
        ServiceAccountName  = $ServiceAccountName
        Path                = $null
        Description         = $null
        DisplayName         = $null
        AccountType         = $null
        Ensure              = $null
        Enabled             = $null
        Members             = @()
        MembershipAttribute = $MembershipAttribute
        Credential          = $Credential
        DomainController    = $DomainController
    }

    try
    {
        $adServiceAccount = Get-ADServiceAccount @adServiceAccountParams `
                                -Property Name,DistinguishedName,Description,DisplayName,ObjectClass,Enabled,PrincipalsAllowedToRetrieveManagedPassword, `
                                            SamAccountName,DistinguishedName,SID,ObjectGUID

        $targetResource['Ensure']            = 'Present'
        $targetResource['Path']              = Get-ADObjectParentDN -DN $adServiceAccount.DistinguishedName
        $targetResource['Description']       = $adServiceAccount.Description
        $targetResource['DisplayName']       = $adServiceAccount.DisplayName
        $targetResource['Enabled']           = [System.Boolean] $adServiceAccount.Enabled

        if ( $adServiceAccount.ObjectClass -eq 'msDS-ManagedServiceAccount' )
        {
            $targetResource['AccountType'] = 'Single'
        }
        elseif ( $adServiceAccount.ObjectClass -eq 'msDS-GroupManagedServiceAccount' )
        {
            Write-Verbose -Message ($LocalizedData.RetrievingPrincipalMembers -f $MembershipAttribute)
            $adServiceAccount.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object {
                $member = (Get-ADObject -Identity $_ -Property $MembershipAttribute).$MembershipAttribute
                $targetResource['Members'] += $member
            }

            $targetResource['AccountType'] = 'Group'
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose ($LocalizedData.ManagedServiceAccountNotFound -f $ServiceAccountName)
        $targetResource['Ensure'] = 'Absent'
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

    .PARAMETER Enabled
        Specifies whether the user account is enabled or disabled.

    .PARAMETER Description
        Specifies a description of the object (ldapDisplayName 'description').

    .PARAMETER DisplayName
        Specifies the display name of the object (ldapDisplayName 'displayName').

    .PARAMETER Members
        Specifies the members of the object (ldapDisplayName 'PrincipalsAllowedToRetrieveManagedPassword')

    .PARAMETER MembershipAttribute
        Specifies the Attribute to use to describe the Identity used for Members ("SamAccountName","DistinguishedName","ObjectGUID","SID")

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
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled = $true,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String[]]
        $Members,

        [Parameter()]
        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

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

    $outOfComplianceParams = Test-TargetResourceHelper @PSBoundParameters

    if ($Ensure -eq 'Absent')
    {
        if ($outOfComplianceParams.ContainsKey('Ensure') -eq 'Present')
        {
            Write-Verbose ($LocalizedData.NotDesiredPropertyState -f `
                            'Ensure', $outOfComplianceParams.Ensure.Expected, $outOfComplianceParams.Ensure.Actual)
        }
    }
    else
    {
        $outOfComplianceParams.GetEnumerator() | ForEach-Object {
            $parameter = $_.name
            $expected = $_.value.Expected
            $actual = $_.value.Actual

            Write-Verbose -Message ($LocalizedData.NotDesiredPropertyState -f `
                    $parameter, $expected, $actual);
        }
    }

    <#
    $getTargetResourceParameters = @{
        ServiceAccountName  = $ServiceAccountName
        Credential          = $Credential
        DomainController    = $DomainController
        MembershipAttribute = $MembershipAttribute
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
        $PSBoundParameters['Enabled']     = $Enabled;

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
                elseif ($parameter -eq 'Members')
                {
                    # Members is only for Group MSAs, if it's single computer, we can skip over this parameter
                    if ($PSBoundParameters.AccountType -eq 'Group')
                    {
                        $testMembersParams = @{
                            ExistingMembers = $getTargetResource.Members -as [System.String[]];
                            Members = $Members;
                        }
                        if (-not (Test-Members @testMembersParams))
                        {
                            $existingMembers = $testMembersParams['ExistingMembers'] -join ',';
                            $desiredMembers = $Members -join ',';
                            Write-Verbose -Message ($LocalizedData.NotDesiredPropertyState -f `
                                                    'Members', $desiredMembers, $existingMembers);
                            $targetResourceInCompliance = $false;
                        }
                    }
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
    #>

    if ($outOfComplianceParams.Count -eq 0)
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

    .PARAMETER Enabled
        Specifies whether the user account is enabled or disabled.

    .PARAMETER Description
        Specifies a description of the object (ldapDisplayName 'description').

    .PARAMETER DisplayName
        Specifies the display name of the object (ldapDisplayName 'displayName').

    .PARAMETER Members
        Specifies the members of the object (ldapDisplayName 'PrincipalsAllowedToRetrieveManagedPassword')

    .PARAMETER MembershipAttribute
        Specifies the Attribute to use to describe the Identity used for Members ("SamAccountName","DistinguishedName","ObjectGUID","SID")

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
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled = $true,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String[]]
        $Members,

        [Parameter()]
        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

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

    $adServiceAccountParams = Get-ADCommonParameters @PSBoundParameters
    $setADServiceAccountParams = $adServiceAccountParams.Clone()

    $outOfComplianceParams = Test-TargetResourceHelper @PSBoundParameters

    try
    {
        $updateProperties = $false

        $outOfComplianceParams.Keys | ForEach-Object {
            if($outOfComplianceParams.ContainsKey('Ensure') -and $Ensure -eq 'Present')
            {
                if ($outOfComplianceParams.Ensure.Actual -eq 'Ensure')
                {
                    $parameter = $_
                    if ( $parameter -eq 'AccountType')
                    {
                        Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'AccountType', $AccountType)
                        Remove-ADServiceAccount @adServiceAccountParams -Confirm:$false
                        New-ADServiceAccountHelper @PSBoundParameters
                    }
                    elseif ( $parameter -eq 'Members')
                    {
                        if([system.string]::IsNullOrEmpty($Members))
                        {
                            $Members = @()
                        }
                        $ListMembers = $Members -join ','

                        Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'Members', $ListMembers)
                        $setADServiceAccountParams['PrincipalsAllowedToRetrieveManagedPassword'] = $Members
                        $UpdateAccount = $true
                    }
                    elseif ($parameter -eq 'Path')
                    {
                        Write-Verbose ($LocalizedData.MovingManagedServiceAccount -f $ServiceAccountName, $Path)
                        Move-ADObject @adServiceAccountParams -TargetPath $Path
                    }
                    else {
                        Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f $parameter, $PSBoundParameters.$parameter)
                        $setADServiceAccountParams[$parameter] = $PSBoundParameters.$parameter
                        $updateProperties = $true
                    }

                    if ($updateProperties)
                    {
                        Set-ADServiceAccount @setADServiceAccountParams
                    }
                }
                elseif ($outOfComplianceParams.Ensure.Actual -eq 'Absent')
                {
                    New-ADServiceAccountHelper @PSBoundParameters
                }
            }
            elseif($outOfComplianceParams.ContainsKey('Ensure') -and $Ensure -eq 'Absent')
            {
                # Account currently exists, but we want to remove it
                Write-Verbose ($LocalizedData.RemovingManagedServiceAccount -f $ServiceAccountName)
                Remove-ADServiceAccount @adServiceAccountParams -Confirm:$false
            }
        }
    }
    catch
    {
        Write-Error -Message ($LocalizedData.AddingManagedServiceAccountError -f $ServiceAccountName)
        throw $_
    }

<#
    $getTargetResourceParameters = @{
        ServiceAccountName  = $ServiceAccountName
        Credential          = $Credential
        DomainController    = $DomainController
        MembershipAttribute = $MembershipAttribute
    }

    @($getTargetResourceParameters.Keys) | ForEach-Object {
        if( !$PSBoundParameters.ContainsKey($_) )
        {
            $getTargetResourceParameters.Remove($_)
        }
    }

    $targetResource = Get-TargetResource @getTargetResourceParameters

    try
    {
        if ($Ensure -eq 'Present')
        {
            if ($targetResource.Ensure -eq 'Present')
            {
                # Need Distinguished Name
                $adServiceAccount = Get-ADServiceAccount @adServiceAccountParams -Property DistinguishedName
                $setADServiceAccountParams['Identity'] = $adServiceAccount.DistinguishedName

                # Account already exists, lets check if we need to update properties
                $UpdateAccount = $false

                if ($PSBoundParameters.ContainsKey('AccountType') -and $AccountType -ne $targetResource.AccountType)
                {
                    Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'AccountType', $AccountType)
                    Remove-ADServiceAccount @adServiceAccountParams -Confirm:$false
                    New-ADServiceAccountHelper @PSBoundParameters
                }

                # Update existing group properties
                if ($PSBoundParameters.ContainsKey('Description') -and $Description -ne $targetResource.Description)
                {
                    Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'Description', $Description)
                    $setADServiceAccountParams['Description'] = $Description
                    $UpdateAccount = $true
                }
                if ($PSBoundParameters.ContainsKey('DisplayName') -and $DisplayName -ne $targetResource.DisplayName)
                {
                    Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'DisplayName', $DisplayName)
                    $setADServiceAccountParams['DisplayName'] = $DisplayName
                    $UpdateAccount = $true
                }
                if ($PSBoundParameters.ContainsKey('Enabled') -and $Enabled -ne $targetResource.Enabled)
                {
                    Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'Enabled', $Enabled)
                    $setADServiceAccountParams['Enabled'] = $Enabled
                    $UpdateAccount = $true
                }

                if ($targetResource.AccountType -eq 'Group' -and $PSBoundParameters.ContainsKey('Members') -and (-not (Test-Members -ExistingMembers $targetResource.Members -Members $Members)) )
                {
                    if([system.string]::IsNullOrEmpty($Members))
                    {
                        $Members = @()
                    }
                    $ListMembers = $Members -join ','

                    Write-Verbose ($LocalizedData.UpdatingManagedServiceAccountProperty -f 'Members', $ListMembers)
                    $setADServiceAccountParams['PrincipalsAllowedToRetrieveManagedPassword'] = $Members
                    $UpdateAccount = $true
                }

                if($UpdateAccount)
                {
                    Write-Verbose ($LocalizedData.UpdatingManagedServiceAccount -f $ServiceAccountName)
                    Set-ADServiceAccount @setADServiceAccountParams
                }

                # Move group if the path is not correct
                if ($PSBoundParameters.ContainsKey('Path') -and $Path -ne $targetResource.Path)
                {
                    Write-Verbose ($LocalizedData.MovingManagedServiceAccount -f $ServiceAccountName, $Path)
                    $moveADObjectParams = $adServiceAccountParams.Clone()
                    $moveADObjectParams['Identity'] = $ServiceAccountName
                    Move-ADObject @moveADObjectParams -TargetPath $Path
                }
            }elseif ($targetResource.Ensure -eq 'Absent')
            {
                # Account does not exist yet, let's create it
                New-ADServiceAccountHelper @PSBoundParameters
            }
        }elseif ($Ensure -eq 'Absent') {
            if ($targetResource.Ensure -eq 'Present')
            {
                # Account currently exists, but we want to remove it
                Write-Verbose ($LocalizedData.RemovingManagedServiceAccount -f $ServiceAccountName)
                Remove-ADServiceAccount @adServiceAccountParams -Confirm:$false
            }
            elseif ($targetResource.Ensure -eq 'Absent')
            {
                # Do nothing - account should be absent and is
                return
            }
        }
    }
    catch
    {
        Write-Error -Message ($LocalizedData.AddingManagedServiceAccountError -f $ServiceAccountName)
        throw $_
    }
    #>
} #end function Set-TargetResource

<#
    .SYNOPSIS
        Adds the managed service account.

    .PARAMETER ServiceAccountName
       Specifies the Security Account Manager (SAM) account name of the managed service account (ldapDisplayName 'sAMAccountName').

    .PARAMETER AccountType
        Specifies the type of managed service account, whether it should be a group or single computer service account

    .PARAMETER Path
        Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created.

    .PARAMETER Ensure
        Specifies whether the user account is created or deleted.

    .PARAMETER Enabled
        Specifies whether the user account is enabled or disabled.

    .PARAMETER Description
        Specifies a description of the object (ldapDisplayName 'description').

    .PARAMETER DisplayName
        Specifies the display name of the object (ldapDisplayName 'displayName').

    .PARAMETER Members
        Specifies the members of the object (ldapDisplayName 'PrincipalsAllowedToRetrieveManagedPassword')

    .PARAMETER MembershipAttribute
        Specifies the Attribute to use to describe the Identity used for Members ("SamAccountName","DistinguishedName","ObjectGUID","SID")

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to use to perform the task.
#>
Function New-ADServiceAccountHelper
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
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled = $true,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String[]]
        $Members,

        [Parameter()]
        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

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

    Write-Verbose ($LocalizedData.AddingManagedServiceAccount -f $ServiceAccountName)

    $adServiceAccountParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter
    $adServiceAccountParams['Enabled'] = $Enabled

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
        New-ADServiceAccount @adServiceAccountParams -RestrictToSingleComputer -PassThru
    }
    elseif( $AccountType -eq 'Group' )
    {
        if ($Members)
        {
            $adServiceAccountParams['PrincipalsAllowedToRetrieveManagedPassword'] = $Members
        }

        $DomainName = Get-DomainName
        $DNSHostName = '{0}.{1}' -f $ServiceAccountName, $DomainName
        $adServiceAccountParams['DNSHostName'] = $DNSHostName

        New-ADServiceAccount @adServiceAccountParams -PassThru
    }
} #end function New-ADServiceAccountHelper


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

    .PARAMETER Enabled
        Specifies whether the user account is enabled or disabled.

    .PARAMETER Description
        Specifies a description of the object (ldapDisplayName 'description').

    .PARAMETER DisplayName
        Specifies the display name of the object (ldapDisplayName 'displayName').

    .PARAMETER Members
        Specifies the members of the object (ldapDisplayName 'PrincipalsAllowedToRetrieveManagedPassword')

    .PARAMETER MembershipAttribute
        Specifies the Attribute to use to describe the Identity used for Members ("SamAccountName","DistinguishedName","ObjectGUID","SID")

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to use to perform the task.
#>
function Test-TargetResourceHelper
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
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
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled = $true,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String[]]
        $Members,

        [Parameter()]
        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

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
        ServiceAccountName  = $ServiceAccountName
        Credential          = $Credential
        DomainController    = $DomainController
        MembershipAttribute = $MembershipAttribute
    }

    @($getTargetResourceParameters.Keys) | ForEach-Object {
        if( !$PSBoundParameters.ContainsKey($_) )
        {
            $getTargetResourceParameters.Remove($_)
        }
    }

    $getTargetResource = Get-TargetResource @getTargetResourceParameters
    $outOfComplianceParams = @{}

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
            elseif ($parameter -eq 'MembershipAttribute')
            {
                # Skip this parameter as it doesn't matter
            }
            elseif ($parameter -eq 'Members')
            {
                # Members is only for Group MSAs, if it's single computer, we can skip over this parameter
                if ($PSBoundParameters.AccountType -eq 'Group')
                {
                    $testMembersParams = @{
                        ExistingMembers = $getTargetResource.Members -as [System.String[]]
                        Members = $Members
                    }
                    if (-not (Test-Members @testMembersParams))
                    {
                        $expectedMembers = $Members -join ','
                        $actualMembers = $testMembersParams['ExistingMembers'] -join ','
                        $outOfComplianceParams[$parameter] = @{
                            'Expected' = $expectedMembers
                            'Actual' = $actualMembers
                        }
                    }
                }
            }
            elseif ($PSBoundParameters.$parameter -ne $getTargetResource.$parameter)
            {
                $outOfComplianceParams[$parameter] = @{
                    'Expected' = $PSBoundParameters.$parameter
                    'Actual' = $getTargetResource.$parameter
                }
            }
        }
    } #end foreach PSBoundParameter

    return $outOfComplianceParams
}

Export-ModuleMember -Function *-TargetResource
