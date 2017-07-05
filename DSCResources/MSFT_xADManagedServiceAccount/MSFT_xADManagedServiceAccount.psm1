[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
param()

# Localized messages
data LocalizedData {
    # culture="en-US"
    ConvertFrom-StringData @'
        RoleNotFoundError              = Please ensure that the PowerShell module for role '{0}' is installed.
        RetrievingADServiceAccountError          = Error looking up Active Directory Service Account '{0}' ({0}@{1}).
        PasswordParameterConflictError = Parameter '{0}' cannot be set to '{1}' when the '{2}' parameter is specified.
        UnsupportedPropertyUpdate      = Parameter '{0}' cannot be set to '{1}' because it cannot be changed after creation.

        RetrievingADServiceAccount               = Retrieving Active Directory Service Account '{0}' ({0}@{1}) ...
        CreatingADDomainConnection     = Creating connection to Active Directory domain '{0}' ...
        CheckingADServiceAccountPassword         = Checking Active Directory Service Account '{0}' password ...
        ADServiceAccountIsPresent                = Active Directory Service Account '{0}' ({0}@{1}) is present.
        ADServiceAccountNotPresent               = Active Directory Service Account '{0}' ({0}@{1}) was NOT present.
        ADServiceAccountNotDesiredPropertyState  = Service Account '{0}' property is NOT in the desired state. Expected '{1}', actual '{2}'.

        AddingADServiceAccount                   = Adding Active Directory Service Account '{0}'.
        RemovingADServiceAccount                 = Removing Active Directory Service Account '{0}'.
        UpdatingADServiceAccount                 = Updating Active Directory Service Account '{0}'.
        SettingADServiceAccountPassword          = Setting Active Directory Service Account password.
        UpdatingADServiceAccountProperty         = Updating Service Account property '{0}' with/to '{1}'.
        RemovingADServiceAccountProperty         = Removing Service Account property '{0}' with '{1}'.
        MovingADServiceAccount                   = Moving Service Account from '{0}' to '{1}'.
        RenamingADServiceAccount                 = Renaming Service Account from '{0}' to '{1}'.
'@
}

## Create a property map that maps the DSC resource parameters to the
## Active Directory user attributes.
$adPropertyMap = @(
    @{ Parameter = 'AccountExpirationDate'; }
    @{ Parameter = 'AccountNotDelegated'; }
    @{ Parameter = 'CompoundIdentitySupported'; ForceSingle = $true; }
    @{ Parameter = 'Description'; }
    @{ Parameter = 'DisplayName'; }
    @{ Parameter = 'DNSHostName'; }
    @{ Parameter = 'Enabled'; }
    @{ Parameter = 'ManagedPasswordIntervalInDays'; ForceSingle = $true; }
    @{ Parameter = 'Path'; ADProperty = 'distinguishedName'; }
    @{ Parameter = 'PrincipalsAllowedToDelegateToAccount'; UseCmdletParameter = $true; ToArray = $true; }
    @{ Parameter = 'PrincipalsAllowedToRetrieveManagedPassword'; UseCmdletParameter = $true; ToArray = $true; }
    @{ Parameter = 'ServicePrincipalName'; UseCmdletParameter = $true; ToArray = $true; }
    @{ Parameter = 'TrustedForDelegation'; }
    @{ Parameter = 'RestrictToSingleComputer'; ADProperty = 'ObjectClass'; UseCmdletParameter = $true  }
    @{ Parameter = 'UserName'; ADProperty = "samAccountName" }
)

function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
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
        [System.uInt32] $ManagedPasswordIntervalInDays,

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

        Write-Verbose -Message ($LocalizedData.RetrievingADServiceAccount -f $UserName, $DomainName);
        $ADServiceAccount = Get-ADServiceAccount @adCommonParameters -Properties $adProperties;
        Write-Verbose -Message ($LocalizedData.ADServiceAccountIsPresent -f $UserName, $DomainName);
        $Ensure = 'Present';
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose -Message ($LocalizedData.ADServiceAccountNotPresent -f $UserName, $DomainName);
        $Ensure = 'Absent';
    }
    catch {
        Write-Error -Message ($LocalizedData.RetrievingADServiceAccountError -f $UserName, $DomainName);
        throw $_;
    }

    $targetResource = @{
        DomainName        = $DomainName;
        DistinguishedName = $ADServiceAccount.DistinguishedName; ## Read-only property
        Ensure            = $Ensure;
    }

    ## Retrieve each property from the ADPropertyMap and add to the hashtable
    foreach ($property in $adPropertyMap) {
        if ($property.Parameter -eq 'Path') {
            ## The path returned is not the parent container
            if (-not [System.String]::IsNullOrEmpty($ADServiceAccount.DistinguishedName)) {
                $targetResource['Path'] = Get-ADObjectParentDN -DN $ADServiceAccount.DistinguishedName;
            }
        }
        elseif ($property.Parameter -eq 'RestrictToOutboundAuthenticationOnly') {
            ## Unable to query RestrictToOutboundAuthenticationOnly
            $targetResource['RestrictToOutboundAuthenticationOnly'] = $null
        }
        elseif ($property.Parameter -eq 'RestrictToSingleComputer') {
            ## Identity ObjectClass
            if ($ADServiceAccount.ObjectClass -eq 'msDS-GroupManagedServiceAccount') {
                ADServiceAccount
                $targetResource['RestrictToSingleComputer'] = $true;
            }
        }
        elseif ($property.ADProperty) {
            ## The AD property name is different to the function parameter to use this
            $targetResource[$property.Parameter] = $ADServiceAccount.($property.ADProperty);
        }
        else {
            ## The AD property name matches the function parameter
            $targetResource[$property.Parameter] = $ADServiceAccount.($property.Parameter);
        }
        if ($Property.ForceSingle) {
            $targetResource[$property.Parameter] = @($targetResource[$property.Parameter])[0]
        }
        if ($Property.ToArray) {
            $targetResource[$property.Parameter] = ($targetResource[$property.Parameter]) | ConvertTo-Array
        }
    }

    return $targetResource;

} #end function Get-TargetResource

function Test-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
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
        [System.uInt32] $ManagedPasswordIntervalInDays,

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

    $PSBoundParameters['Username'] = ('{0}$' -f $UserName);

    Assert-Parameters @PSBoundParameters;
    $targetResource = Get-TargetResource @PSBoundParameters;
    $isCompliant = $true;

    if ($Ensure -eq 'Absent') {
        if ($targetResource.Ensure -eq 'Present') {
            Write-Verbose -Message ($LocalizedData.ADServiceAccountNotDesiredPropertyState -f 'Ensure', $PSBoundParameters.Ensure, $targetResource.Ensure);
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
                        $compareString = (Get-ADObject -Filter "samaccountname -eq '$_'").DistinguishedName
                    }

                    if (@($targetResource.$parameter).contains($compareString) -eq $false -and $PSBoundParameters[$parameter].count -eq @($targetResource."$parameter").count) { 
                        Write-Verbose -Message ($LocalizedData.ADServiceAccountNotDesiredPropertyState -f $parameter, (@($targetResource."$parameter") -join ','), (@($PSBoundParameters."$parameter") -join ','));
                        $isCompliant = $false;
                        break
                    }
                }
            }
            # Only check properties that are returned by Get-TargetResource
            elseif ($targetResource.ContainsKey($parameter)) {
                ## This check is required to be able to explicitly remove values with an empty string, if required
                if ($parameter -eq "username" -and $targetResource."$parameter" -notlike '*$') {
                    $targetResource."$parameter" += "$"
                }
                if (([System.String]::IsNullOrEmpty($PSBoundParameters."$parameter")) -and ([System.String]::IsNullOrEmpty($targetResource."$parameter"))) {
                    # Both values are null/empty and therefore we are compliant
                }
                elseif ($PSBoundParameters."$parameter" -ne $targetResource."$parameter") {
                    Write-Verbose -Message ($LocalizedData.ADServiceAccountNotDesiredPropertyState -f $parameter, $PSBoundParameters."$parameter", $targetResource."$parameter") -Verbose;
                    $isCompliant = $false;
                }
            }
        } #end foreach PSBoundParameter
    }

    return $isCompliant;

} #end function Test-TargetResource

function Set-TargetResource {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
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
        [System.uInt32] $ManagedPasswordIntervalInDays,

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
    $PSBoundParameters['Username'] = ('{0}$' -f $UserName);

    if ($Ensure -eq 'Present') {
        if ($targetResource.Ensure -eq 'Absent') {
            ## User does not exist and needs creating
            $newADServiceAccountParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter;
            if ($PSBoundParameters.ContainsKey('Path')) {
                $newADServiceAccountParams['Path'] = $Path;
            }
            Write-Verbose -Message ($LocalizedData.AddingADServiceAccount -f $UserName);
            New-ADServiceAccount @newADServiceAccountParams -SamAccountName $UserName -DNSHostName $DNSHostName;
            ## Now retrieve the newly created user
            $targetResource = Get-TargetResource @PSBoundParameters;
        }

        $setADServiceAccountParams = Get-ADCommonParameters @PSBoundParameters;
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
                    Write-Verbose -Message ($LocalizedData.MovingADServiceAccount -f $targetResource.Path, $PSBoundParameters.Path);
                    Move-ADObject @adCommonParameters -TargetPath $PSBoundParameters.Path;
                }
                elseif ($parameter -eq 'Username' -and ($UserName -ne $targetResource.username)) {
                    ## Cannot rename users by updating the CN property directly
                    $adCommonParameters = Get-ADCommonParameters -Identity $PSBoundParameters['Username'] @PSBoundParameters;
                    ## Using the SamAccountName for identity with Rename-ADObject does not work, use the DN instead
                    $adCommonParameters['Identity'] = $targetResource.DistinguishedName;
                    Write-Verbose -Message ($LocalizedData.RenamingADServiceAccount -f $targetResource.username, $PSBoundParameters.username);
                    Rename-ADObject @adCommonParameters -NewName $PSBoundParameters.username;
                    [ref] $null = Set-ADServiceAccount @adCommonParameters -samaccountname ('{0}$' -f $PSBoundParameters.username);
                }
                elseif ($parameter -eq 'RestrictToSingleComputer') {
                    Write-Verbose -Message ($LocalizedData.UnsupportedPropertyUpdate -f 'RestrictToSingleComputer', $RestrictToSingleComputer);
                }
                elseif ($parameter -eq 'Enabled' -and ($PSBoundParameters.$parameter -ne $targetResource.$parameter)) {
                    ## We cannot enable/disable an account with -Add or -Replace parameters, but inform that
                    ## we will change this as it is out of compliance (it always gets set anyway)
                    Write-Verbose -Message ($LocalizedData.UpdatingADServiceAccountProperty -f $parameter, $PSBoundParameters.$parameter);
                }
                elseif ($PSBoundParameters.$parameter -is [System.Array] -and (($PSBoundParameters.$parameter -join ',') -ne ($targetResource.$parameter -join ','))) {
                    #Setting Array property
                    Write-Verbose -Message ($LocalizedData.UpdatingADServiceAccountProperty -f $parameter, ($PSBoundParameters.$parameter -join ','));

                    ## Find the associated AD property
                    $adProperty = $adPropertyMap | Where-Object { $_.Parameter -eq $parameter };

                    if ([System.String]::IsNullOrEmpty($adProperty)) {
                        ## We can't do anything is an empty AD property!
                    }
                    elseif ([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter)) {
                        ## We are removing properties
                        ## Only remove if the existing value in not null or empty
                        if (-not ([System.String]::IsNullOrEmpty($targetResource.$parameter))) {
                            Write-Verbose -Message ($LocalizedData.RemovingADServiceAccountProperty -f $parameter, $PSBoundParameters.$parameter);
                            if ($adProperty.UseCmdletParameter -eq $true) {
                                ## We need to pass the parameter explicitly to Set-ADServiceAccount, not via -Remove
                                $setADServiceAccountParams[$adProperty.Parameter] = $PSBoundParameters.$parameter;
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
                            ## We need to pass the parameter explicitly to Set-ADServiceAccount, not via -Replace
                            $setADServiceAccountParams[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                        }
                        elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty)) {
                            $replaceUserProperties[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                        }
                        else {
                            $replaceUserProperties[$adProperty.ADProperty] = $PSBoundParameters.$parameter;
                        }
                    } #end if replace existing value
                }
                elseif ($PSBoundParameters.$parameter -ne $targetResource.$parameter) {
                    ## Find the associated AD property
                    $adProperty = $adPropertyMap | Where-Object { $_.Parameter -eq $parameter };

                    if ([System.String]::IsNullOrEmpty($adProperty)) {
                        ## We can't do anything is an empty AD property!
                    }
                    elseif ([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter)) {
                        ## We are removing properties
                        ## Only remove if the existing value in not null or empty
                        if (-not ([System.String]::IsNullOrEmpty($targetResource.$parameter))) {
                            Write-Verbose -Message ($LocalizedData.RemovingADServiceAccountProperty -f $parameter, $PSBoundParameters.$parameter);
                            if ($adProperty.UseCmdletParameter -eq $true) {
                                ## We need to pass the parameter explicitly to Set-ADServiceAccount, not via -Remove
                                $setADServiceAccountParams[$adProperty.Parameter] = $PSBoundParameters.$parameter;
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
                        Write-Verbose -Message ($LocalizedData.UpdatingADServiceAccountProperty -f $parameter, $PSBoundParameters.$parameter);
                        if ($adProperty.UseCmdletParameter -eq $true) {
                            ## We need to pass the parameter explicitly to Set-ADServiceAccount, not via -Replace
                            $setADServiceAccountParams[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                        }
                        elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty)) {
                            $replaceUserProperties[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                        }
                        else {
                            $replaceUserProperties[$adProperty.ADProperty] = $PSBoundParameters.$parameter;
                        }
                    } #end if replace existing value
                }

            } #end if TargetResource parameter
        } #end foreach PSBoundParameter

        ## Only pass -Remove and/or -Replace if we have something to set/change
        if ($replaceUserProperties.Count -gt 0) {
            $setADServiceAccountParams['Replace'] = $replaceUserProperties;
        }
        if ($removeUserProperties.Count -gt 0) {
            $setADServiceAccountParams['Remove'] = $removeUserProperties;
        }

        Write-Verbose -Message ($LocalizedData.UpdatingADServiceAccount -f $UserName);
        [ref] $null = Set-ADServiceAccount @setADServiceAccountParams -Enabled $Enabled;
    }
    elseif (($Ensure -eq 'Absent') -and ($targetResource.Ensure -eq 'Present')) {
        ## User exists and needs removing
        Write-Verbose ($LocalizedData.RemovingADServiceAccount -f $UserName);
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
    Write-Verbose -Message ($LocalizedData.CheckingADServiceAccountPassword -f $UserName);

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
