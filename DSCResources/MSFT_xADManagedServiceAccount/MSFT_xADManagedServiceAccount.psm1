[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
param()

# Localized messages
data LocalizedData {
    # culture="en-US"
    ConvertFrom-StringData @'
        RoleNotFoundError              = Please ensure that the PowerShell module for role '{0}' is installed.
        RetrievingADUserError          = Error looking up Active Directory Service Account '{0}' ({0}@{1}).
        PasswordParameterConflictError = Parameter '{0}' cannot be set to '{1}' when the '{2}' parameter is specified.
        UnsupportedPropertyUpdate      = Parameter '{0}' cannot be set to '{1}' because it cannot be changed after creation.

        RetrievingADUser               = Retrieving Active Directory Service Account '{0}' ({0}@{1}) ...
        CreatingADDomainConnection     = Creating connection to Active Directory domain '{0}' ...
        CheckingADUserPassword         = Checking Active Directory Service Account '{0}' password ...
        ADUserIsPresent                = Active Directory Service Account '{0}' ({0}@{1}) is present.
        ADUserNotPresent               = Active Directory Service Account '{0}' ({0}@{1}) was NOT present.
        ADUserNotDesiredPropertyState  = Service Account '{0}' property is NOT in the desired state. Expected '{1}', actual '{2}'.

        AddingADUser                   = Adding Active Directory Service Account '{0}'.
        RemovingADUser                 = Removing Active Directory Service Account '{0}'.
        UpdatingADUser                 = Updating Active Directory Service Account '{0}'.
        SettingADUserPassword          = Setting Active Directory Service Account password.
        UpdatingADUserProperty         = Updating Service Account property '{0}' with/to '{1}'.
        RemovingADUserProperty         = Removing Service Account property '{0}' with '{1}'.
        MovingADUser                   = Moving Service Account from '{0}' to '{1}'.
        RenamingADUser                 = Renaming Service Account from '{0}' to '{1}'.
'@
}

## Create a property map that maps the DSC resource parameters to the
## Active Directory user attributes.
$adPropertyMap = @(
    @{ Parameter = 'AccountExpirationDate'; }
    @{ Parameter = 'AccountNotDelegated'; }
    @{ Parameter = 'CompoundIdentitySupported'; }
    @{ Parameter = 'Description'; }
    @{ Parameter = 'DisplayName'; }
    @{ Parameter = 'DNSHostName'; }
    @{ Parameter = 'Enabled'; UseCmdletParameter = $true}
    @{ Parameter = 'ManagedPasswordIntervalInDays'; }
    @{ Parameter = 'Path'; ADProperty = 'distinguishedName'; }
    @{ Parameter = 'PrincipalsAllowedToDelegateToAccount'; UseCmdletParameter = $true}
    @{ Parameter = 'PrincipalsAllowedToRetrieveManagedPassword'; UseCmdletParameter = $true }
    @{ Parameter = 'ServicePrincipalName'; UseCmdletParameter = $true }
    @{ Parameter = 'TrustedForDelegation'; }
    @{ Parameter = 'RestrictToSingleComputer'; ADProperty = 'ObjectClass'; UseCmdletParameter = $true  }
    @{ Parameter = 'UserName'; ADProperty = "samAccountName" }
)

function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        ## Name of the domain where the user account is located (only used if password is managed)
        [Parameter(Mandatory)]
        [System.String] $DomainName,

        # Specifies the Security Account Manager (SAM) account name of the user (ldapDisplayName 'sAMAccountName')
        [Parameter(Mandatory)]
        [System.String] $UserName,

        ## Specifies whether the user account is created or deleted
        [ValidateSet('Present', 'Absent')]
        [System.String] $Ensure = 'Present',

        # Specifies the DNS Hostname of the object
        [Parameter()]
        [System.String] $DNSHostName,

        ## Specifies the display name of the object (ldapDisplayName 'displayName')
        [ValidateNotNull()]
        [System.String] $DisplayName,

        ## Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created
        [ValidateNotNull()]
        [System.String] $Path,

        ## Specifies the user's given name (ldapDisplayName 'givenName')
        [ValidateNotNull()]
        [System.String[]] $ServicePrincipalName,

        ## Specifies a description of the object (ldapDisplayName 'description')
        [ValidateNotNull()]
        [System.String] $Description,

        ## Specifies if the account is enabled (default True)
        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,

        ## Specifies whether when the account expires
        [ValidateNotNull()]
        [System.DateTime] $AccountExpirationDate,

        ## Specifies whether the account is delegated
        [ValidateNotNull()]
        [System.Boolean] $AccountNotDelegated,

        ## Specifies whether the account is trusted for delegation
        [ValidateNotNull()]
        [System.Boolean] $TrustedForDelegation,

        [ValidateNotNull()]
        [System.Boolean] $CompoundIdentitySupported,

        [ValidateNotNull()]
        [System.Boolean] $RestrictToSingleComputer,

        [ValidateNotNull()]
        [System.Uint32] $ManagedPasswordIntervalInDays,

        [ValidateNotNull()]
        [System.String[]] $PrincipalsAllowedToDelegateToAccount,

        [ValidateNotNull()]
        [System.String[]] $PrincipalsAllowedToRetrieveManagedPassword,

        ## Specifies the Active Directory Domain Services instance to use to perform the task.
        [ValidateNotNull()]
        [System.String] $DomainController,

        ## Specifies the user account credentials to use to perform this task. Ideally this should just be called 'Credential' but is here for backwards compatibility
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        ## Specifies the authentication context type when testing user passwords #61
        [ValidateSet('Default', 'Negotiate')]
        [System.String] $PasswordAuthentication = 'Default'
    )

    Assert-Module -ModuleName 'ActiveDirectory';

    try {
        $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;

        $adProperties = @();
        ## Create an array of the AD propertie names to retrieve from the property map
        foreach ($property in $adPropertyMap) {
            if ($property.ADProperty) {
                $adProperties += $property.ADProperty;
            }
            else {
                $adProperties += $property.Parameter;
            }
        }

        Write-Verbose -Message ($LocalizedData.RetrievingADUser -f $UserName, $DomainName);
        $adUser = Get-ADServiceAccount @adCommonParameters -Properties $adProperties;
        Write-Verbose -Message ($LocalizedData.ADUserIsPresent -f $UserName, $DomainName);
        $Ensure = 'Present';
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose -Message ($LocalizedData.ADUserNotPresent -f $UserName, $DomainName);
        $Ensure = 'Absent';
    }
    catch {
        Write-Error -Message ($LocalizedData.RetrievingADUserError -f $UserName, $DomainName);
        throw $_;
    }

    $targetResource = @{
        DomainName        = $DomainName;
        UserName          = $UserName;
        DistinguishedName = $adUser.DistinguishedName; ## Read-only property
        Ensure            = $Ensure;
        DomainController  = $DomainController;
    }

    ## Retrieve each property from the ADPropertyMap and add to the hashtable
    foreach ($property in $adPropertyMap) {
        if ($property.Parameter -eq 'Path') {
            ## The path returned is not the parent container
            if (-not [System.String]::IsNullOrEmpty($adUser.DistinguishedName)) {
                $targetResource['Path'] = Get-ADObjectParentDN -DN $adUser.DistinguishedName;
            }
        }
        elseif ($property.Parameter -eq 'RestrictToOutboundAuthenticationOnly') {
            ## Unable to query RestrictToOutboundAuthenticationOnly
            $targetResource['RestrictToOutboundAuthenticationOnly'] = $null
        }
        elseif ($property.Parameter -eq 'RestrictToSingleComputer') {
            ## Identity ObjectClass
            if ($adUser.ObjectClass -eq 'msDS-GroupManagedServiceAccount') {
                $targetResource['RestrictToSingleComputer'] = $false;
            }
            elseif ($adUser.ObjectClass -eq 'msDS-ManagedServiceAccount') {
                $targetResource['RestrictToSingleComputer'] = $true;
            }
        }
        elseif ($property.ADProperty) {
            ## The AD property name is different to the function parameter to use this
            $targetResource[$property.Parameter] = $adUser.($property.ADProperty);
        }
        else {
            ## The AD property name matches the function parameter
            $targetResource[$property.Parameter] = $adUser.($property.Parameter);
        }
    }
    return $targetResource;

} #end function Get-TargetResource

function Test-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        ## Name of the domain where the user account is located (only used if password is managed)
        [Parameter(Mandatory)]
        [System.String] $DomainName,

        # Specifies the Security Account Manager (SAM) account name of the user (ldapDisplayName 'sAMAccountName')
        [Parameter(Mandatory)]
        [System.String] $UserName,

        ## Specifies whether the user account is created or deleted
        [ValidateSet('Present', 'Absent')]
        [System.String] $Ensure = 'Present',

        # Specifies the DNS Hostname of the object
        [Parameter()]
        [System.String] $DNSHostName,

        ## Specifies the display name of the object (ldapDisplayName 'displayName')
        [ValidateNotNull()]
        [System.String] $DisplayName,

        ## Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created
        [ValidateNotNull()]
        [System.String] $Path,

        ## Specifies the user's given name (ldapDisplayName 'givenName')
        [ValidateNotNull()]
        [System.String[]] $ServicePrincipalName,

        ## Specifies a description of the object (ldapDisplayName 'description')
        [ValidateNotNull()]
        [System.String] $Description,

        ## Specifies if the account is enabled (default True)
        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,

        ## Specifies whether when the account expires
        [ValidateNotNull()]
        [System.DateTime] $AccountExpirationDate,

        ## Specifies whether the account is delegated
        [ValidateNotNull()]
        [System.Boolean] $AccountNotDelegated,

        ## Specifies whether the account is trusted for delegation
        [ValidateNotNull()]
        [System.Boolean] $TrustedForDelegation,

        [ValidateNotNull()]
        [System.Boolean] $CompoundIdentitySupported,

        [ValidateNotNull()]
        [System.Boolean] $RestrictToSingleComputer,

        [ValidateNotNull()]
        [System.Uint32] $ManagedPasswordIntervalInDays,

        [ValidateNotNull()]
        [System.String[]] $PrincipalsAllowedToDelegateToAccount,

        [ValidateNotNull()]
        [System.String[]] $PrincipalsAllowedToRetrieveManagedPassword,

        ## Specifies the Active Directory Domain Services instance to use to perform the task.
        [ValidateNotNull()]
        [System.String] $DomainController,

        ## Specifies the user account credentials to use to perform this task. Ideally this should just be called 'Credential' but is here for backwards compatibility
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        ## Specifies the authentication context type when testing user passwords #61
        [ValidateSet('Default', 'Negotiate')]
        [System.String] $PasswordAuthentication = 'Default'
    )

    if ($PSBoundParameters['Username'] -inotmatch '[a-z0-9]+\$$') {
        $PSBoundParameters['Username'] = ('{0}$' -f $UserName);
    }

    Assert-Parameters @PSBoundParameters;
    $targetResource = Get-TargetResource @PSBoundParameters;
    $isCompliant = $true;

    if ($Ensure -eq 'Absent') {
        if ($targetResource.Ensure -eq 'Present') {
            Write-Verbose -Message ($LocalizedData.ADUserNotDesiredPropertyState -f 'Ensure', $PSBoundParameters.Ensure, $targetResource.Ensure);
            $isCompliant = $false;
        }
    }
    else {
        ## Add common name, ensure and enabled as they may not be explicitly passed and we want to enumerate them
        $PSBoundParameters['Ensure'] = $Ensure;
        $PSBoundParameters['Enabled'] = $Enabled;

        foreach ($parameter in $PSBoundParameters.Keys) {
            if ($PSBoundParameters[$parameter] -is [system.array]) {
                $PSBoundParameters[$parameter] | % {
                    $compareString = $_

                    if ($parameter -eq 'PrincipalsAllowedToDelegateToAccount' -or $parameter -eq 'PrincipalsAllowedToRetrieveManagedPassword') {
                        if ($compareString -match '.+\\(.+)') {
                            $compareString = $matches[1]
                        }
                        $compareString = (Get-ADObject -Filter "samaccountname -eq '$compareString'").DistinguishedName
                    }

                    if (@($targetResource.$parameter).contains($compareString) -eq $false -and $PSBoundParameters[$parameter].count -ne @($targetResource.$parameter).count) {
                        Write-Verbose -Message ($LocalizedData.ADUserNotDesiredPropertyState -f $parameter, (@($PSBoundParameters.$parameter) -join ','), (@($targetResource.$parameter) -join ','));
                        $isCompliant = $false;
                        break
                    }
                }
            }
            # Only check properties that are returned by Get-TargetResource
            elseif ($targetResource.ContainsKey($parameter)) {
                ## This check is required to be able to explicitly remove values with an empty string, if required
                if (([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter)) -and ([System.String]::IsNullOrEmpty($targetResource.$parameter))) {
                    # Both values are null/empty and therefore we are compliant
                }
                elseif ($PSBoundParameters.$parameter -ne $targetResource.$parameter) {
                    Write-Verbose -Message ($LocalizedData.ADUserNotDesiredPropertyState -f $parameter, $PSBoundParameters.$parameter, $targetResource.$parameter);
                    $isCompliant = $false;
                }
            }
        } #end foreach PSBoundParameter
    }

    return $isCompliant;

} #end function Test-TargetResource

function Set-TargetResource {
    [CmdletBinding()]
    param
    (
        ## Name of the domain where the user account is located (only used if password is managed)
        [Parameter(Mandatory)]
        [System.String] $DomainName,

        # Specifies the Security Account Manager (SAM) account name of the user (ldapDisplayName 'sAMAccountName')
        [Parameter(Mandatory)]
        [System.String] $UserName,

        ## Specifies whether the user account is created or deleted
        [ValidateSet('Present', 'Absent')]
        [System.String] $Ensure = 'Present',

        # Specifies the DNS Hostname of the object
        [Parameter()]
        [System.String] $DNSHostName,

        ## Specifies the display name of the object (ldapDisplayName 'displayName')
        [ValidateNotNull()]
        [System.String] $DisplayName,

        ## Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created
        [ValidateNotNull()]
        [System.String] $Path,

        ## Specifies the user's given name (ldapDisplayName 'givenName')
        [ValidateNotNull()]
        [System.String[]] $ServicePrincipalName,

        ## Specifies a description of the object (ldapDisplayName 'description')
        [ValidateNotNull()]
        [System.String] $Description,

        ## Specifies if the account is enabled (default True)
        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,

        ## Specifies whether when the account expires
        [ValidateNotNull()]
        [System.DateTime] $AccountExpirationDate,

        ## Specifies whether the account is delegated
        [ValidateNotNull()]
        [System.Boolean] $AccountNotDelegated,

        ## Specifies whether the account is trusted for delegation
        [ValidateNotNull()]
        [System.Boolean] $TrustedForDelegation,

        [ValidateNotNull()]
        [System.Boolean] $CompoundIdentitySupported,

        [ValidateNotNull()]
        [System.Boolean] $RestrictToSingleComputer,

        [ValidateNotNull()]
        [System.Uint32] $ManagedPasswordIntervalInDays,

        [ValidateNotNull()]
        [System.String[]] $PrincipalsAllowedToDelegateToAccount,

        [ValidateNotNull()]
        [System.String[]] $PrincipalsAllowedToRetrieveManagedPassword,

        ## Specifies the Active Directory Domain Services instance to use to perform the task.
        [ValidateNotNull()]
        [System.String] $DomainController,

        ## Specifies the user account credentials to use to perform this task. Ideally this should just be called 'Credential' but is here for backwards compatibility
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        ## Specifies the authentication context type when testing user passwords #61
        [ValidateSet('Default', 'Negotiate')]
        [System.String] $PasswordAuthentication = 'Default'
    )

    Assert-Parameters @PSBoundParameters;
    $targetResource = Get-TargetResource @PSBoundParameters;

    ## Add common name, ensure and enabled as they may not be explicitly passed
    $PSBoundParameters['Ensure'] = $Ensure;
    $PSBoundParameters['Enabled'] = $Enabled;

    if ($Ensure -eq 'Present') {
        if ($targetResource.Ensure -eq 'Absent') {
            ## User does not exist and needs creating
            $newADUserParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter;
            if ($PSBoundParameters.ContainsKey('Path')) {
                $newADUserParams['Path'] = $Path;
            }
            if ($PSBoundParameters.ContainsKey('DNSHostName')) {
                $newADUserParams['DNSHostName'] = $DNSHostName;
            }
            if ($PSBoundParameters.ContainsKey('ManagedPasswordIntervalInDays')) {
                $newADUserParams['ManagedPasswordIntervalInDays'] = $ManagedPasswordIntervalInDays;
            }
            if ($PSBoundParameters.ContainsKey('RestrictToSingleComputer')) {
                $newADUserParams['RestrictToSingleComputer'] = $RestrictToSingleComputer;
            }
            Write-Verbose -Message ($LocalizedData.AddingADUser -f $UserName);
            $newaduserparams
            New-ADServiceAccount @newADUserParams -SamAccountName $UserName;
            ## Now retrieve the newly created user
            $targetResource = Get-TargetResource @PSBoundParameters;
        }

        $setADUserParams = Get-ADCommonParameters @PSBoundParameters;
        $replaceUserProperties = @{};
        $removeUserProperties = @{};
        foreach ($parameter in $PSBoundParameters.Keys) {
            ## Only check/action properties specified/declared parameters that match one of the function's
            ## parameters. This will ignore common parameters such as -Verbose etc.
            if ($targetResource.ContainsKey($parameter)) {
                if ($parameter -eq 'Path' -and ($PSBoundParameters.Path -ne $targetResource.Path)) {
                    ## Cannot move users by updating the DistinguishedName property
                    $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
                    ## Using the SamAccountName for identity with Move-ADObject does not work, use the DN instead
                    $adCommonParameters['Identity'] = $targetResource.DistinguishedName;
                    Write-Verbose -Message ($LocalizedData.MovingADUser -f $targetResource.Path, $PSBoundParameters.Path);
                    Move-ADObject @adCommonParameters -TargetPath $PSBoundParameters.Path;
                }
                elseif ($parameter -eq 'Username' -and ($PSBoundParameters.username -ne $targetResource.username)) {
                    ## Cannot rename users by updating the CN property directly
                    $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
                    ## Using the SamAccountName for identity with Rename-ADObject does not work, use the DN instead
                    $adCommonParameters['Identity'] = $targetResource.DistinguishedName;
                    Write-Verbose -Message ($LocalizedData.RenamingADUser -f $targetResource.username, $PSBoundParameters.username);
                    Rename-ADObject @adCommonParameters -NewName $PSBoundParameters.username;
                    [ref] $null = Set-ADServiceAccount @adCommonParameters -samaccountname ('{0}$' -f ($PSBoundParameters.username -replace '\$$'));
                }
                elseif ($parameter -eq 'RestrictToSingleComputer') {
                    Write-Verbose -Message ($LocalizedData.UnsupportedPropertyUpdate -f 'RestrictToSingleComputer', $RestrictToSingleComputer);
                }
                elseif ($parameter -eq 'ManagedPasswordIntervalInDays') {
                    Write-Verbose -Message ($LocalizedData.UnsupportedPropertyUpdate -f 'ManagedPasswordIntervalInDays', $ManagedPasswordIntervalInDays);
                }
                elseif ($parameter -eq 'Enabled' -and ($PSBoundParameters.$parameter -ne $targetResource.$parameter)) {
                    ## We cannot enable/disable an account with -Add or -Replace parameters, but inform that
                    ## we will change this as it is out of compliance (it always gets set anyway)
                    Write-Verbose -Message ($LocalizedData.UpdatingADUserProperty -f $parameter, $PSBoundParameters.$parameter);
                }
                elseif ($PSBoundParameters.$parameter -is [System.Array] -and (($PSBoundParameters.$parameter -join ',') -ne ($targetResource.$parameter -join ','))) {
                    $ValueToSet = $PSBoundParameters.$parameter
                    #Setting Array property
                    Write-Verbose -Message ($LocalizedData.UpdatingADUserProperty -f $parameter, ($ValueToSet -join ','));

                    ## Find the associated AD property
                    $adProperty = $adPropertyMap | Where-Object { $_.Parameter -eq $parameter };

                    if ($parameter -eq 'PrincipalsAllowedToDelegateToAccount' -or $parameter -eq 'PrincipalsAllowedToRetrieveManagedPassword') {
                        $Principals = $ValueToSet
                        $ValueToSet = @()
                        $Principals | % {
                            if ($_ -match '.+\\(.+)') {
                                $ValueToSet += $matches[1]
                            }
                            else {
                                $ValueToSet += $_
                            }
                        }
                    }

                    if ([System.String]::IsNullOrEmpty($adProperty)) {
                        ## We can't do anything is an empty AD property!
                    }
                    elseif ([System.String]::IsNullOrEmpty($ValueToSet)) {
                        ## We are removing properties
                        ## Only remove if the existing value in not null or empty
                        if (-not ([System.String]::IsNullOrEmpty($targetResource.$parameter))) {
                            Write-Verbose -Message ($LocalizedData.RemovingADUserProperty -f $parameter, $ValueToSet);
                            if ($adProperty.UseCmdletParameter -eq $true) {
                                if ($adProperty.Parameter -imatch "ServicePrincipalName") {
                                    ($targetResource.$parameter).Split(",").Trim() | % {
                                        Set-ADServiceAccount -Identity $UserName -ServicePrincipalNames @{"Remove" = $_}
                                    }
                                }
                                else {
                                    ## We need to pass the parameter explicitly to Set-ADUser, not via -Remove
                                    $setADUserParams[$adProperty.Parameter] = $ValueToSet;
                                }
                            }
                            elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty)) {
                                $removeUserProperties[$adProperty.Parameter] = $targetResource.$parameter;
                            }
                            else {
                                $removeUserProperties[$adProperty.ADProperty] = $targetResource.$parameter;
                            }
                        }
                    } #end if remove existing value
                    else {
                        ## We are replacing the existing value
                        if ($adProperty.UseCmdletParameter -eq $true) {
                            if ($adProperty.Parameter -imatch "ServicePrincipalName") {
                                if ($targetResource.$parameter) {
                                    ($targetResource.$parameter).Split(",").Trim() | % {
                                        Set-ADServiceAccount -Identity $UserName -ServicePrincipalNames @{"Remove" = $_}
                                    }
                                }
                                $ValueToSet | % {
                                    Set-ADServiceAccount -Identity $UserName -ServicePrincipalNames @{Add = $_}
                                }
                            }
                            else {
                                $ValueToSet
                                ## We need to pass the parameter explicitly to Set-ADUser, not via -Remove
                                $setADUserParams[$adProperty.Parameter] = $ValueToSet;
                            }
                        }
                        elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty)) {
                            $replaceUserProperties[$adProperty.Parameter] = $ValueToSet;
                        }
                        else {
                            $replaceUserProperties[$adProperty.ADProperty] = $ValueToSet;
                        }
                    } #end if replace existing value
                    $setADUserParams.serviceprincipalname
                }
                elseif ($ValueToSet -ne $targetResource.$parameter) {
                    $ValueToSet = $PSBoundParameters.$parameter

                    ## Find the associated AD property
                    $adProperty = $adPropertyMap | Where-Object { $_.Parameter -eq $parameter };

                    if ($parameter -eq 'PrincipalsAllowedToDelegateToAccount' -or $parameter -eq 'PrincipalsAllowedToRetrieveManagedPassword') {
                        if ($ValueToSet -match '.+\\(.+)') {
                            $ValueToSet = $matches[1]
                        }
                    }

                    if ([System.String]::IsNullOrEmpty($adProperty)) {
                        ## We can't do anything is an empty AD property!
                    }
                    elseif ([System.String]::IsNullOrEmpty($ValueToSet)) {
                        ## We are removing properties
                        ## Only remove if the existing value in not null or empty
                        if (-not ([System.String]::IsNullOrEmpty($targetResource.$parameter))) {
                            Write-Verbose -Message ($LocalizedData.RemovingADUserProperty -f $parameter, $ValueToSet);
                            if ($adProperty.UseCmdletParameter -eq $true) {
                                if ($adProperty.Parameter -imatch "ServicePrincipalName") {
                                    if ($targetResource.$parameter) {
                                        ($targetResource.$parameter).Split(",").Trim() | % {
                                            Set-ADServiceAccount -Identity $UserName -ServicePrincipalNames @{"Remove" = $_}
                                        }
                                    }
                                }
                                else {
                                    ## We need to pass the parameter explicitly to Set-ADUser, not via -Remove
                                    $setADUserParams[$adProperty.Parameter] = $ValueToSet;
                                }
                            }
                            elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty)) {
                                $removeUserProperties[$adProperty.Parameter] = $targetResource.$parameter;
                            }
                            else {
                                $removeUserProperties[$adProperty.ADProperty] = $targetResource.$parameter;
                            }
                        }
                    } #end if remove existing value
                    else {
                        ## We are replacing the existing value
                        Write-Verbose -Message ($LocalizedData.UpdatingADUserProperty -f $parameter, $ValueToSet);
                        if ($adProperty.UseCmdletParameter -eq $true) {
                            if ($adProperty.Parameter -imatch "ServicePrincipalName") {
                                ($targetResource.$parameter).Split(",").Trim() | % {
                                    Set-ADServiceAccount -Identity $UserName -ServicePrincipalNames @{Remove = $_}
                                }
                                $ValueToSet | % {
                                    Set-ADServiceAccount -Identity $UserName -ServicePrincipalNames @{Add = $_}
                                }
                            }
                            else {
                                ## We need to pass the parameter explicitly to Set-ADUser, not via -Replace
                                $setADUserParams[$adProperty.Parameter] = $ValueToSet;
                            }
                        }
                        elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty)) {
                            $replaceUserProperties[$adProperty.Parameter] = $ValueToSet;
                        }
                        else {
                            $replaceUserProperties[$adProperty.ADProperty] = $ValueToSet;
                        }
                    } #end if replace existing value
                }

            } #end if TargetResource parameter
        } #end foreach PSBoundParameter

        ## Only pass -Remove and/or -Replace if we have something to set/change
        if ($replaceUserProperties.Count -gt 0) {
            $setADUserParams['Replace'] = $replaceUserProperties;
        }
        if ($removeUserProperties.Count -gt 0) {
            $setADUserParams['Remove'] = $removeUserProperties;
        }

        Write-Verbose -Message ($LocalizedData.UpdatingADUser -f $UserName);
        [ref] $null = Set-ADServiceAccount @setADUserParams;
    }
    elseif (($Ensure -eq 'Absent') -and ($targetResource.Ensure -eq 'Present')) {
        ## User exists and needs removing
        Write-Verbose ($LocalizedData.RemovingADUser -f $UserName);
        $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
        [ref] $null = Remove-ADServiceAccount @adCommonParameters -Confirm:$false;
    }

} #end function Set-TargetResource

# Internal function to validate unsupported options/configurations
function Assert-Parameters {
    [CmdletBinding()]
    param
    (
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $Password,

        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,

        [Parameter(ValueFromRemainingArguments)]
        $IgnoredArguments
    )

    ## We cannot test/set passwords on disabled AD accounts
    if (($PSBoundParameters.ContainsKey('Password')) -and ($Enabled -eq $false)) {
        $throwInvalidArgumentErrorParams = @{
            ErrorId      = 'xADServiceAccount_DisabledAccountPasswordConflict';
            ErrorMessage = $LocalizedData.PasswordParameterConflictError -f 'Enabled', $false, 'Password';
        }
        ThrowInvalidArgumentError @throwInvalidArgumentErrorParams;
    }

} #end function Assert-Parameters

# Internal function to test the validity of a user's password.
function Test-Password {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.String] $DomainName,

        [Parameter(Mandatory)]
        [System.String] $UserName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Password,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        ## Specifies the authentication context type when testing user passwords #61
        [Parameter(Mandatory)]
        [ValidateSet('Default', 'Negotiate')]
        [System.String] $PasswordAuthentication
    )

    Write-Verbose -Message ($LocalizedData.CreatingADDomainConnection -f $DomainName);
    Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement';

    if ($DomainAdministratorCredential) {
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            $DomainName,
            $DomainAdministratorCredential.UserName,
            $DomainAdministratorCredential.GetNetworkCredential().Password
        );
    }
    else {
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            $DomainName,
            $null,
            $null
        );
    }
    Write-Verbose -Message ($LocalizedData.CheckingADUserPassword -f $UserName);

    if ($PasswordAuthentication -eq 'Negotiate') {
        return $principalContext.ValidateCredentials(
            $UserName,
            $Password.GetNetworkCredential().Password,
            [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate -bor
            [System.DirectoryServices.AccountManagement.ContextOptions]::Signing -bor
            [System.DirectoryServices.AccountManagement.ContextOptions]::Sealing
        );
    }
    else {
        ## Use default authentication context
        return $principalContext.ValidateCredentials(
            $UserName,
            $Password.GetNetworkCredential().Password
        );
    }

} #end function Test-Password

## Import the common AD functions
$adCommonFunctions = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath '\MSFT_xADCommon\MSFT_xADCommon.ps1';
. $adCommonFunctions;

Export-ModuleMember -Function *-TargetResource
