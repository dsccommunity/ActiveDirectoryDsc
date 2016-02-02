# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
        RoleNotFoundError              = Please ensure that the PowerShell module for role '{0}' is installed.
        RetrievingADUserError          = Error looking up Active Directory user '{0}' ({0}@{1}).
        PasswordParameterConflictError = Parameter '{0}' cannot be set to '{1}' when the '{2}' parameter is specified.
        
        RetrievingADUser               = Retrieving Active Directory user '{0}' ({0}@{1}) ...
        CreatingADDomainConnection     = Creating connection to Active Directory domain '{0}' ...
        CheckingADUserPassword         = Checking Active Directory user '{0}' password ...
        ADUserIsPresent                = Active Directory user '{0}' ({0}@{1}) is present.
        ADUserNotPresent               = Active Directory user '{0}' ({0}@{1}) was NOT present.
        ADUserNotDesiredPropertyState  = User '{0}' property is NOT in the desired state. Expected '{1}', actual '{2}'.
        
        AddingADUser                   = Adding Active Directory user '{0}'.
        RemovingADUser                 = Removing Active Directory user '{0}'.
        UpdatingADUser                 = Updating Active Directory user '{0}'.
        SettingADUserPassword          = Setting Active Directory user password.
        UpdatingADUserProperty         = Updating user property '{0}' with/to '{1}'.
        RemovingADUserProperty         = Removing user property '{0}' with '{1}'.
        MovingADUser                   = Moving user from '{0}' to '{1}'.
        RenamingADUser                 = Renaming user from '{0}' to '{1}'.
'@
}

## Create a property map that maps the DSC resource parameters to the
## Active Directory user attributes.
$adPropertyMap = @(
    @{ Parameter = 'CommonName'; ADProperty = 'cn'; }
    @{ Parameter = 'UserPrincipalName'; }
    @{ Parameter = 'DisplayName'; }
    @{ Parameter = 'Path'; ADProperty = 'distinguishedName'; }
    @{ Parameter = 'GivenName'; }
    @{ Parameter = 'Initials'; }
    @{ Parameter = 'Surname'; ADProperty = 'sn'; }
    @{ Parameter = 'Description'; }
    @{ Parameter = 'StreetAddress'; }
    @{ Parameter = 'POBox'; }
    @{ Parameter = 'City'; ADProperty = 'l'; }
    @{ Parameter = 'State'; ADProperty = 'st'; }
    @{ Parameter = 'PostalCode'; }
    @{ Parameter = 'Country'; ADProperty = 'c'; }
    @{ Parameter = 'Department'; }
    @{ Parameter = 'Division'; }
    @{ Parameter = 'Company'; }
    @{ Parameter = 'Office'; ADProperty = 'physicalDeliveryOfficeName'; }
    @{ Parameter = 'JobTitle'; ADProperty = 'title'; }
    @{ Parameter = 'EmailAddress'; ADProperty = 'mail'; }
    @{ Parameter = 'EmployeeID'; }
    @{ Parameter = 'EmployeeNumber'; }
    @{ Parameter = 'HomeDirectory'; }
    @{ Parameter = 'HomeDrive'; }
    @{ Parameter = 'HomePage'; ADProperty = 'wWWHomePage'; }
    @{ Parameter = 'ProfilePath'; }
    @{ Parameter = 'LogonScript'; ADProperty = 'scriptPath'; }
    @{ Parameter = 'Notes'; ADProperty = 'info'; }
    @{ Parameter = 'OfficePhone'; ADProperty = 'telephoneNumber'; }
    @{ Parameter = 'MobilePhone'; ADProperty = 'mobile'; }
    @{ Parameter = 'Fax'; ADProperty = 'facsimileTelephoneNumber'; }
    @{ Parameter = 'Pager'; }
    @{ Parameter = 'IPPhone'; }
    @{ Parameter = 'HomePhone'; }
    @{ Parameter = 'Enabled'; }
    @{ Parameter = 'Manager'; }
    @{ Parameter = 'PasswordNeverExpires'; UseCmdletParameter = $true; }
    @{ Parameter = 'CannotChangePassword'; UseCmdletParameter = $true; }
)

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        ## Only used if password is managed.
        [Parameter(Mandatory)]
        [System.String] $DomainName,
        
        # SamAccountName
        [Parameter(Mandatory)]
        [System.String] $UserName,
        
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $Password,

        [ValidateSet('Present', 'Absent')]
        [System.String] $Ensure = 'Present',
        
        # Common name (CN)
        [ValidateNotNull()]
        [System.String] $CommonName = $UserName,

        [ValidateNotNull()]
        [System.String] $UserPrincipalName,
        
        [ValidateNotNull()]
        [System.String] $DisplayName,
        
        [ValidateNotNull()]
        [System.String] $Path,
        
        [ValidateNotNull()]
        [System.String] $GivenName,
        
        [ValidateNotNull()]
        [System.String] $Initials,
        
        [ValidateNotNull()]
        [System.String] $Surname,
        
        [ValidateNotNull()]
        [System.String] $Description,

        [ValidateNotNull()]
        [System.String] $StreetAddress,

        [ValidateNotNull()]
        [System.String] $POBox,

        [ValidateNotNull()]
        [System.String] $City,

        [ValidateNotNull()]
        [System.String] $State,

        [ValidateNotNull()]
        [System.String] $PostalCode,

        [ValidateNotNull()]
        [System.String] $Country,

        [ValidateNotNull()]
        [System.String] $Department,

        [ValidateNotNull()]
        [System.String] $Division,

        [ValidateNotNull()]
        [System.String] $Company,

        [ValidateNotNull()]
        [System.String] $Office,

        [ValidateNotNull()]
        [System.String] $JobTitle,

        [ValidateNotNull()]
        [System.String] $EmailAddress,
        
        [ValidateNotNull()]
        [System.String] $EmployeeID,

        [ValidateNotNull()]
        [System.String] $EmployeeNumber,

        [ValidateNotNull()]
        [System.String] $HomeDirectory,

        [ValidateNotNull()]
        [System.String] $HomeDrive,

        [ValidateNotNull()]
        [System.String] $HomePage,
        
        [ValidateNotNull()]
        [System.String] $ProfilePath,
        
        [ValidateNotNull()]
        [System.String] $LogonScript,
        
        [ValidateNotNull()]
        [System.String] $Notes,
        
        [ValidateNotNull()]
        [System.String] $OfficePhone,
        
        [ValidateNotNull()]
        [System.String] $MobilePhone,

        [ValidateNotNull()]
        [System.String] $Fax,

        [ValidateNotNull()]
        [System.String] $HomePhone,

        [ValidateNotNull()]
        [System.String] $Pager,

        [ValidateNotNull()]
        [System.String] $IPPhone,

        ## User's manager specified as a Distinguished Name (DN)
        [ValidateNotNull()]
        [System.String] $Manager,
        
        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,

        [ValidateNotNull()]
        [System.Boolean] $CannotChangePassword,
        
        [ValidateNotNull()]
        [System.Boolean] $PasswordNeverExpires,
        
        [ValidateNotNull()]
        [System.String] $DomainController,
        
        ## Ideally this should just be called 'Credential' but is here for backwards compatibility
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $DomainAdministratorCredential
    )
    
    Assert-Module -ModuleName 'ActiveDirectory';

    try
    {
        $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
        
        $adProperties = @();
        ## Create an array of the AD propertie names to retrieve from the property map
        foreach ($property in $adPropertyMap)
        {
            if ($property.ADProperty)
            {
                $adProperties += $property.ADProperty;
            }
            else 
            {
                $adProperties += $property.Parameter;
            }
        }

        Write-Verbose -Message ($LocalizedData.RetrievingADUser -f $UserName, $DomainName);
        $adUser = Get-ADUser @adCommonParameters -Properties $adProperties;
        Write-Verbose -Message ($LocalizedData.ADUserIsPresent -f $UserName, $DomainName);
        $Ensure = 'Present';
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message ($LocalizedData.ADUserNotPresent -f $UserName, $DomainName);
        $Ensure = 'Absent';
    }
    catch
    {
        Write-Error -Message ($LocalizedData.RetrievingADUserError -f $UserName, $DomainName);
        throw $_;
    }

    $targetResource = @{
        DomainName        = $DomainName;
        Password          = $Password;
        UserName          = $UserName;
        DistinguishedName = $adUser.DistinguishedName; ## Read-only property
        Ensure            = $Ensure;
        DomainController  = $DomainController;
    }

    ## Retrieve each property from the ADPropertyMap and add to the hashtable
    foreach ($property in $adPropertyMap)
    {
        if ($property.Parameter -eq 'Path') {
            ## The path returned is not the parent container
            if (-not [System.String]::IsNullOrEmpty($adUser.DistinguishedName))
            {
                $targetResource['Path'] = Get-ADObjectParentDN -DN $adUser.DistinguishedName;
            }
        }
        elseif ($property.ADProperty)
        {
            ## The AD property name is different to the function parameter to use this
            $targetResource[$property.Parameter] = $adUser.($property.ADProperty);
        }
        else
        {
            ## The AD property name matches the function parameter
            $targetResource[$property.Parameter] = $adUser.($property.Parameter);
        }
    }
    return $targetResource;

} #end function Get-TargetResource

function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        ## Only used if password is managed.
        [Parameter(Mandatory)]
        [System.String] $DomainName,
        
        # SamAccountName
        [Parameter(Mandatory)]
        [System.String] $UserName,
        
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $Password,

        [ValidateSet('Present', 'Absent')]
        [System.String] $Ensure = 'Present',
        
        # Common name (CN)
        [ValidateNotNull()]
        [System.String] $CommonName = $UserName,
        
        [ValidateNotNull()]
        [System.String] $UserPrincipalName,
        
        [ValidateNotNull()]
        [System.String] $DisplayName,
        
        [ValidateNotNull()]
        [System.String] $Path,
        
        [ValidateNotNull()]
        [System.String] $GivenName,
        
        [ValidateNotNull()]
        [System.String] $Initials,
        
        [ValidateNotNull()]
        [System.String] $Surname,
        
        [ValidateNotNull()]
        [System.String] $Description,

        [ValidateNotNull()]
        [System.String] $StreetAddress,

        [ValidateNotNull()]
        [System.String] $POBox,

        [ValidateNotNull()]
        [System.String] $City,

        [ValidateNotNull()]
        [System.String] $State,

        [ValidateNotNull()]
        [System.String] $PostalCode,

        [ValidateNotNull()]
        [System.String] $Country,

        [ValidateNotNull()]
        [System.String] $Department,

        [ValidateNotNull()]
        [System.String] $Division,

        [ValidateNotNull()]
        [System.String] $Company,

        [ValidateNotNull()]
        [System.String] $Office,

        [ValidateNotNull()]
        [System.String] $JobTitle,

        [ValidateNotNull()]
        [System.String] $EmailAddress,
        
        [ValidateNotNull()]
        [System.String] $EmployeeID,

        [ValidateNotNull()]
        [System.String] $EmployeeNumber,

        [ValidateNotNull()]
        [System.String] $HomeDirectory,

        [ValidateNotNull()]
        [System.String] $HomeDrive,

        [ValidateNotNull()]
        [System.String] $HomePage,
        
        [ValidateNotNull()]
        [System.String] $ProfilePath,
        
        [ValidateNotNull()]
        [System.String] $LogonScript,
        
        [ValidateNotNull()]
        [System.String] $Notes,
        
        [ValidateNotNull()]
        [System.String] $OfficePhone,
        
        [ValidateNotNull()]
        [System.String] $MobilePhone,

        [ValidateNotNull()]
        [System.String] $Fax,

        [ValidateNotNull()]
        [System.String] $HomePhone,

        [ValidateNotNull()]
        [System.String] $Pager,

        [ValidateNotNull()]
        [System.String] $IPPhone,

        ## User's manager specified as a Distinguished Name (DN)
        [ValidateNotNull()]
        [System.String] $Manager,
        
        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,

        [ValidateNotNull()]
        [System.Boolean] $CannotChangePassword,
        
        [ValidateNotNull()]
        [System.Boolean] $PasswordNeverExpires,
        
        [ValidateNotNull()]
        [System.String] $DomainController,
        
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $DomainAdministratorCredential
    )

    Validate-Parameters @PSBoundParameters;
    $targetResource = Get-TargetResource @PSBoundParameters;
    $isCompliant = $true;

    if ($Ensure -eq 'Absent')
    {
        if ($targetResource.Ensure -eq 'Present')
        {
            Write-Verbose -Message ($LocalizedData.ADUserNotDesiredPropertyState -f 'Ensure', $PSBoundParameters.Ensure, $targetResource.Ensure);
            $isCompliant = $false;
        }
    }
    else
    {
        ## Add common name, ensure and enabled as they may not be explicitly passed and we want to enumerate them
        $PSBoundParameters['Ensure'] = $Ensure;
        $PSBoundParameters['Enabled'] = $Enabled;
    
        foreach ($parameter in $PSBoundParameters.Keys)
        {
            if ($parameter -eq 'Password')
            {
                $testPasswordParams = @{
                    Username = $UserName;
                    Password = $Password;
                    DomainName = $DomainName;
                }
                if ($DomainAdministratorCredential)
                {
                    $testPasswordParams['DomainAdministratorCredential'] = $DomainAdministratorCredential;
                }
                if (-not (Test-Password @testPasswordParams))
                {
                    Write-Verbose -Message ($LocalizedData.ADUserNotDesiredPropertyState -f 'Password', '<Password>', '<Password>');
                    $isCompliant = $false;
                }
            }
            # Only check properties that are returned by Get-TargetResource
            elseif ($targetResource.ContainsKey($parameter))
            {
                ## This check is required to be able to explicitly remove values with an empty string, if required
                if (([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter)) -and ([System.String]::IsNullOrEmpty($targetResource.$parameter)))
                {
                    # Both values are null/empty and therefore we are compliant
                }
                elseif ($PSBoundParameters.$parameter -ne $targetResource.$parameter)
                {
                    Write-Verbose -Message ($LocalizedData.ADUserNotDesiredPropertyState -f $parameter, $PSBoundParameters.$parameter, $targetResource.$parameter);
                    $isCompliant = $false;
                }
            }
        } #end foreach PSBoundParameter
    }

    return $isCompliant;

} #end function Test-TargetResource

function Set-TargetResource
{
    param
    (
        ## Only used if password is managed.
        [Parameter(Mandatory)]
        [System.String] $DomainName,
        
        # SamAccountName
        [Parameter(Mandatory)]
        [System.String] $UserName,
        
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $Password,

        [ValidateSet('Present', 'Absent')]
        [System.String] $Ensure = 'Present',
        
        [ValidateNotNull()]
        [System.String] $CommonName = $UserName,

        [ValidateNotNull()]
        [System.String] $UserPrincipalName,
        
        [ValidateNotNull()]
        [System.String] $DisplayName,
        
        [ValidateNotNull()]
        [System.String] $Path,
        
        [ValidateNotNull()]
        [System.String] $GivenName,
        
        [ValidateNotNull()]
        [System.String] $Initials,
        
        [ValidateNotNull()]
        [System.String] $Surname,
        
        [ValidateNotNull()]
        [System.String] $Description,

        [ValidateNotNull()]
        [System.String] $StreetAddress,

        [ValidateNotNull()]
        [System.String] $POBox,

        [ValidateNotNull()]
        [System.String] $City,

        [ValidateNotNull()]
        [System.String] $State,

        [ValidateNotNull()]
        [System.String] $PostalCode,

        [ValidateNotNull()]
        [System.String] $Country,

        [ValidateNotNull()]
        [System.String] $Department,

        [ValidateNotNull()]
        [System.String] $Division,

        [ValidateNotNull()]
        [System.String] $Company,

        [ValidateNotNull()]
        [System.String] $Office,

        [ValidateNotNull()]
        [System.String] $JobTitle,

        [ValidateNotNull()]
        [System.String] $EmailAddress,
        
        [ValidateNotNull()]
        [System.String] $EmployeeID,

        [ValidateNotNull()]
        [System.String] $EmployeeNumber,

        [ValidateNotNull()]
        [System.String] $HomeDirectory,

        [ValidateNotNull()]
        [System.String] $HomeDrive,

        [ValidateNotNull()]
        [System.String] $HomePage,
        
        [ValidateNotNull()]
        [System.String] $ProfilePath,
        
        [ValidateNotNull()]
        [System.String] $LogonScript,
        
        [ValidateNotNull()]
        [System.String] $Notes,
        
        [ValidateNotNull()]
        [System.String] $OfficePhone,
        
        [ValidateNotNull()]
        [System.String] $MobilePhone,

        [ValidateNotNull()]
        [System.String] $Fax,

        [ValidateNotNull()]
        [System.String] $HomePhone,

        [ValidateNotNull()]
        [System.String] $Pager,

        [ValidateNotNull()]
        [System.String] $IPPhone,

        ## User's manager specified as a Distinguished Name (DN)
        [ValidateNotNull()]
        [System.String] $Manager,
        
        [ValidateNotNull()]
        [System.Boolean] $Enabled = $true,
        
        [ValidateNotNull()]
        [System.Boolean] $CannotChangePassword,
        
        [ValidateNotNull()]
        [System.Boolean] $PasswordNeverExpires,
        
        [ValidateNotNull()]
        [System.String] $DomainController,
        
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $DomainAdministratorCredential
    )

    Validate-Parameters @PSBoundParameters;
    $targetResource = Get-TargetResource @PSBoundParameters;

    ## Add common name, ensure and enabled as they may not be explicitly passed
    $PSBoundParameters['Ensure'] = $Ensure;
    $PSBoundParameters['Enabled'] = $Enabled;

    if ($Ensure -eq 'Present')
    {
        if ($targetResource.Ensure -eq 'Absent') {
            ## User does not exist and needs creating
            $newADUserParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter;
            if ($PSBoundParameters.ContainsKey('Path'))
            {
                $newADUserParams['Path'] = $Path;
            }
            Write-Verbose -Message ($LocalizedData.AddingADUser -f $UserName);
            New-ADUser @newADUserParams -SamAccountName $UserName;
            ## Now retrieve the newly created user
            $targetResource = Get-TargetResource @PSBoundParameters;
        }

        $setADUserParams = Get-ADCommonParameters @PSBoundParameters;
        $replaceUserProperties = @{};
        $removeUserProperties = @{};
        foreach ($parameter in $PSBoundParameters.Keys)
        {
            ## Only check/action properties specified/declared parameters that match one of the function's
            ## parameters. This will ignore common parameters such as -Verbose etc.
            if ($targetResource.ContainsKey($parameter))
            {
                if ($parameter -eq 'Path' -and ($PSBoundParameters.Path -ne $targetResource.Path))
                {
                    ## Cannot move users by updating the DistinguishedName property
                    $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
                    ## Using the SamAccountName for identity with Move-ADObject does not work, use the DN instead
                    $adCommonParameters['Identity'] = $targetResource.DistinguishedName;
                    Write-Verbose -Message ($LocalizedData.MovingADUser -f $targetResource.Path, $PSBoundParameters.Path);
                    Move-ADObject @adCommonParameters -TargetPath $PSBoundParameters.Path;
                }
                elseif ($parameter -eq 'CommonName' -and ($PSBoundParameters.CommonName -ne $targetResource.CommonName))
                {
                    ## Cannot rename users by updating the CN property directly
                    $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
                    ## Using the SamAccountName for identity with Rename-ADObject does not work, use the DN instead
                    $adCommonParameters['Identity'] = $targetResource.DistinguishedName;
                    Write-Verbose -Message ($LocalizedData.RenamingADUser -f $targetResource.CommonName, $PSBoundParameters.CommonName);
                    Rename-ADObject @adCommonParameters -NewName $PSBoundParameters.CommonName;
                }
                elseif ($parameter -eq 'Password')
                {
                    $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
                    Write-Verbose -Message ($LocalizedData.SettingADUserPassword -f $UserName);
                    Set-ADAccountPassword @adCommonParameters -Reset -NewPassword $Password.Password;
                }
                elseif ($parameter -eq 'Enabled' -and ($PSBoundParameters.$parameter -ne $targetResource.$parameter))
                {
                    ## We cannot enable/disable an account with -Add or -Replace parameters, but inform that
                    ## we will change this as it is out of compliance (it always gets set anyway)
                    Write-Verbose -Message ($LocalizedData.UpdatingADUserProperty -f $parameter, $PSBoundParameters.$parameter);
                }
                elseif ($PSBoundParameters.$parameter -ne $targetResource.$parameter)
                {
                    ## Find the associated AD property
                    $adProperty = $adPropertyMap | Where-Object { $_.Parameter -eq $parameter };
                    
                    if ([System.String]::IsNullOrEmpty($adProperty))
                    {
                        ## We can't do anything is an empty AD property!
                    }
                    elseif ([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter))
                    {
                        ## We are removing properties
                        ## Only remove if the existing value in not null or empty
                        if (-not ([System.String]::IsNullOrEmpty($targetResource.$parameter)))
                        {
                            Write-Verbose -Message ($LocalizedData.RemovingADUserProperty -f $parameter, $PSBoundParameters.$parameter);
                            if ($adProperty.UseCmdletParameter -eq $true)
                            {
                                ## We need to pass the parameter explicitly to Set-ADUser, not via -Remove
                                $setADUserParams[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                            }
                            elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty))
                            {
                                $removeUserProperties[$adProperty.Parameter] = $targetResource.$parameter;
                            }
                            else
                            {
                                $removeUserProperties[$adProperty.ADProperty] = $targetResource.$parameter;
                            }
                        }
                    } #end if remove existing value
                    else
                    {
                        ## We are replacing the existing value
                        Write-Verbose -Message ($LocalizedData.UpdatingADUserProperty -f $parameter, $PSBoundParameters.$parameter);
                        if ($adProperty.UseCmdletParameter -eq $true)
                        {
                            ## We need to pass the parameter explicitly to Set-ADUser, not via -Replace
                            $setADUserParams[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                        }
                        elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty))
                        {
                            $replaceUserProperties[$adProperty.Parameter] = $PSBoundParameters.$parameter;
                        }
                        else
                        {
                            $replaceUserProperties[$adProperty.ADProperty] = $PSBoundParameters.$parameter;
                        }
                    } #end if replace existing value
                }
            
            } #end if TargetResource parameter
        } #end foreach PSBoundParameter
        
        ## Only pass -Remove and/or -Replace if we have something to set/change
        if ($replaceUserProperties.Count -gt 0)
        {        
            $setADUserParams['Replace'] = $replaceUserProperties;
        }
        if ($removeUserProperties.Count -gt 0)
        {        
            $setADUserParams['Remove'] = $removeUserProperties;
        }
        
        Write-Verbose -Message ($LocalizedData.UpdatingADUser -f $UserName);
        Set-ADUser @setADUserParams -Enabled $Enabled;
    }
    elseif (($Ensure -eq 'Absent') -and ($targetResource.Ensure -eq 'Present'))
    {
        ## User exists and needs removing
        Write-Verbose ($LocalizedData.RemovingADUser -f $UserName);
        $adCommonParameters = Get-ADCommonParameters @PSBoundParameters;
        Remove-ADUser @adCommonParameters -Confirm:$false;
    }

} #end function Set-TargetResource

# Internal function to validate unsupported options/configurations
function Validate-Parameters
{
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
    if (($PSBoundParameters.ContainsKey('Password')) -and ($Enabled -eq $false))
    {
        $throwInvalidArgumentErrorParams = @{
            ErrorId = 'xADUser_DisabledAccountPasswordConflict';
            ErrorMessage = $LocalizedData.PasswordParameterConflictError -f 'Enabled', $false, 'Password';
        }
        ThrowInvalidArgumentError @throwInvalidArgumentErrorParams;
    }

} #end function Validate-Parameters

# Internal function to test the validity of a user's password.
function Test-Password
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.String] $DomainName,

        [Parameter(Mandatory)]
        [System.String] $UserName,
    
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential] $Password,
        
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential] $DomainAdministratorCredential
    )

    Write-Verbose -Message ($LocalizedData.CreatingADDomainConnection -f $DomainName);
    Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement';
            
    if ($DomainAdministratorCredential)
    {
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                                'Domain', $DomainName, $DomainAdministratorCredential.UserName, `
                                    $DomainAdministratorCredential.GetNetworkCredential().Password);
    }
    else
    {
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $DomainName, $null, $null);
    }
    Write-Verbose -Message ($LocalizedData.CheckingADUserPassword -f $UserName);
    return $principalContext.ValidateCredentials($UserName, $Password.GetNetworkCredential().Password);

} #end function Test-Password

# Internal function to build common parameters for the Active Directory cmdlets
function Get-ADCommonParameters
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $CommonName,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainAdministratorCredential,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [Parameter(ValueFromRemainingArguments)]
        $IgnoredArguments,

        [System.Management.Automation.SwitchParameter]
        $UseNameParameter
    )
    
    ## The Get-ADUser, Set-ADUser and Remove-ADUser cmdlets take an -Identity parameter, but the New-ADUser cmdlet uses the -Name parameter
    if ($UseNameParameter)
    {
        if ($PSBoundParameters.ContainsKey('CommonName'))
        {
            $adUserParameters = @{ Name = $CommonName; }
        }
        else
        {
            $adUserParameters = @{ Name = $UserName; }
        }
    }
    else
    {
        $adUserParameters = @{ Identity = $UserName; }
    }

    if ($DomainAdministratorCredential)
    {
        $adUserParameters['Credential'] = $DomainAdministratorCredential;
    }
    if ($DomainController)
    {
        $adUserParameters['Server'] = $DomainController;
    }
    return $adUserParameters;

} #end function Get-ADCommonParameters

# Internal function to assert if the role specific module is installed or not
function Assert-Module
{
    [CmdletBinding()]
    param
    (
        [System.String] $ModuleName = 'ActiveDirectory'
    )

    if (-not (Get-Module -Name $ModuleName -ListAvailable))
    {
        $errorId = 'xADUser_ModuleNotFound';
        $errorMessage = $LocalizedData.RoleNotFoundError -f $moduleName;
        ThrowInvalidOperationError -ErrorId $errorId -ErrorMessage $errorMessage;
    }
} #end function Assert-Module

# Internal function to get an Active Directory object's parent Distinguished Name
function Get-ADObjectParentDN
{
    <#
        Copyright (c) 2016 The University Of Vermont
        All rights reserved.

        Redistribution and use in source and binary forms, with or without modification, are permitted provided that
        the following conditions are met:
        
        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
           following disclaimer.
        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
           following disclaimer in the documentation and/or other materials provided with the distribution.
        3. Neither the name of the University nor the names of its contributors may be used to endorse or promote
           products derived from this software without specific prior written permission.

        THIS SOFTWARE IS PROVIDED BY THE AUTHOR “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
        LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
        IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
        CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
        OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
        CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
        THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        http://www.uvm.edu/~gcd/code-license/
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.String]
        $DN
    )
    
    # https://www.uvm.edu/~gcd/2012/07/listing-parent-of-ad-object-in-powershell/
    $distinguishedNameParts = $DN -split '(?<![\\]),';
    $distinguishedNameParts[1..$($distinguishedNameParts.Count-1)] -join ',';

} #end function Get-ADObjectParentDN

function ThrowInvalidOperationError
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorMessage
    )

    $exception = New-Object -TypeName System.InvalidOperationException -ArgumentList $ErrorMessage;
    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation;
    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $exception, $ErrorId, $errorCategory, $null;
    throw $errorRecord;
}

function ThrowInvalidArgumentError
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorMessage
    )

    $exception = New-Object -TypeName System.ArgumentException -ArgumentList $ErrorMessage;
    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument;
    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $exception, $ErrorId, $errorCategory, $null;
    throw $errorRecord;

} #end function ThrowInvalidArgumentError

Export-ModuleMember -Function *-TargetResource
