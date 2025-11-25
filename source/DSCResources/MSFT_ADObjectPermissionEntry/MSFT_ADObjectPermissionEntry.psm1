$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Get the current state of the object permission entry.

    .PARAMETER Path
        Active Directory path of the target object to add or remove the
        permission entry, specified as a Distinguished Name.

    .PARAMETER IdentityReference
        Indicates the identity of the principal for the permission entry.

    .PARAMETER AccessControlType
        Indicates whether to Allow or Deny access to the target object.

    .PARAMETER ObjectType
        The schema GUID or display name of the object to which the access rule
        applies.

    .PARAMETER ActiveDirectorySecurityInheritance
        One of the 'ActiveDirectorySecurityInheritance' enumeration values that
        specifies the inheritance type of the access rule.

    .PARAMETER InheritedObjectType
        The schema GUID or display name of the child object type that can
        inherit this access rule.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.String]
        $IdentityReference,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Allow', 'Deny')]
        [System.String]
        $AccessControlType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ObjectType,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Children', 'Descendents', 'None', 'SelfAndChildren')]
        [System.String]
        $ActiveDirectorySecurityInheritance,

        [Parameter(Mandatory = $true)]
        [System.String]
        $InheritedObjectType
    )

    if (-not (Test-IsGuid -InputString $ObjectType))
    {
        $ObjectType = Get-ADSchemaGuid -DisplayName $ObjectType
    }

    if (-not (Test-IsGuid -InputString $InheritedObjectType))
    {
        $InheritedObjectType = Get-ADSchemaGuid -DisplayName $InheritedObjectType
    }

    $ADDrivePSPath = Get-ADDrivePSPath

    # Return object, by default representing an absent ace
    $returnValue = @{
        Ensure                             = 'Absent'
        Path                               = $Path
        IdentityReference                  = $IdentityReference
        ActiveDirectoryRights              = [System.String[]] @()
        AccessControlType                  = $AccessControlType
        ObjectType                         = $ObjectType
        ActiveDirectorySecurityInheritance = $ActiveDirectorySecurityInheritance
        InheritedObjectType                = $InheritedObjectType
    }

    try
    {
        # Get the current acl
        $acl = Get-Acl -Path ($ADDrivePSPath + $Path) -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException]
    {
        Write-Verbose -Message ($script:localizedData.ObjectPathIsAbsent -f $Path)
        $acl = $null
    }
    catch
    {
        throw $_
    }

    if ($null -ne $acl)
    {
        foreach ($access in $acl.Access)
        {
            if ($access.IsInherited -eq $false)
            {
                <#
                    Check if the ace does match the parameters. If yes, the target
                    ace has been found, return present with the assigned rights.
                #>
                if ($access.IdentityReference.Value -eq $IdentityReference -and
                    $access.AccessControlType -eq $AccessControlType -and
                    $access.ObjectType.Guid -eq $ObjectType -and
                    $access.InheritanceType -eq $ActiveDirectorySecurityInheritance -and
                    $access.InheritedObjectType.Guid -eq $InheritedObjectType)
                {
                    $returnValue['Ensure'] = 'Present'
                    $returnValue['ActiveDirectoryRights'] = [System.String[]] $access.ActiveDirectoryRights.ToString().Split(',').ForEach( { $_.Trim() })
                }
            }
        }
    }

    if ($returnValue.Ensure -eq 'Present')
    {
        Write-Verbose -Message ($script:localizedData.ObjectPermissionEntryFound -f $Path)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ObjectPermissionEntryNotFound -f $Path)
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Add or remove the object permission entry.

    .PARAMETER Ensure
        Indicates if the access will be added (Present) or will be removed
        (Absent). Default is 'Present'.

    .PARAMETER Path
        Active Directory path of the target object to add or remove the
        permission entry, specified as a Distinguished Name.

    .PARAMETER IdentityReference
        Indicates the identity of the principal for the permission entry.

    .PARAMETER ActiveDirectoryRights
        A combination of one or more of the ActiveDirectoryRights enumeration
        values that specifies the rights of the access rule. Default is
        'GenericAll'.

    .PARAMETER AccessControlType
        Indicates whether to Allow or Deny access to the target object.

    .PARAMETER ObjectType
        The schema GUID or display name of the object to which the access rule
        applies.

    .PARAMETER ActiveDirectorySecurityInheritance
        One of the 'ActiveDirectorySecurityInheritance' enumeration values that
        specifies the inheritance type of the access rule.

    .PARAMETER InheritedObjectType
        The schema GUID or display name of the child object type that can
        inherit this access rule.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.String]
        $IdentityReference,

        [Parameter()]
        [ValidateSet('AccessSystemSecurity', 'CreateChild', 'Delete', 'DeleteChild', 'DeleteTree', 'ExtendedRight', 'GenericAll', 'GenericExecute', 'GenericRead', 'GenericWrite', 'ListChildren', 'ListObject', 'ReadControl', 'ReadProperty', 'Self', 'Synchronize', 'WriteDacl', 'WriteOwner', 'WriteProperty')]
        [System.String[]]
        $ActiveDirectoryRights = 'GenericAll',

        [Parameter(Mandatory = $true)]
        [ValidateSet('Allow', 'Deny')]
        [System.String]
        $AccessControlType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ObjectType,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Children', 'Descendents', 'None', 'SelfAndChildren')]
        [System.String]
        $ActiveDirectorySecurityInheritance,

        [Parameter(Mandatory = $true)]
        [System.String]
        $InheritedObjectType
    )

    if (-not (Test-IsGuid -InputString $ObjectType))
    {
        $ObjectType = Get-ADSchemaGuid -DisplayName $ObjectType
    }

    if (-not (Test-IsGuid -InputString $InheritedObjectType))
    {
        $InheritedObjectType = Get-ADSchemaGuid -DisplayName $InheritedObjectType
    }

    $ADDrivePSPath = Get-ADDrivePSPath

    # Get the current acl
    $acl = Get-Acl -Path ($ADDrivePSPath + $Path)

    if ($Ensure -eq 'Present')
    {
        Write-Verbose -Message ($script:localizedData.AddingObjectPermissionEntry -f $Path)

        $ntAccount = New-Object -TypeName 'System.Security.Principal.NTAccount' -ArgumentList $IdentityReference

        $ace = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList @(
            $ntAccount,
            $ActiveDirectoryRights,
            $AccessControlType,
            $ObjectType,
            $ActiveDirectorySecurityInheritance,
            $InheritedObjectType
        )

        $acl.AddAccessRule($ace)
    }
    else
    {
        <#
            Iterate through all ace entries to find the desired ace, which
            should be absent. If found, remove the ace from the acl.
        #>
        foreach ($access in $acl.Access)
        {
            if ($access.IsInherited -eq $false)
            {
                if ($access.IdentityReference.Value -eq $IdentityReference -and
                    $access.AccessControlType -eq $AccessControlType -and
                    $access.ObjectType.Guid -eq $ObjectType -and
                    $access.InheritanceType -eq $ActiveDirectorySecurityInheritance -and
                    $access.InheritedObjectType.Guid -eq $InheritedObjectType)
                {
                    Write-Verbose -Message ($script:localizedData.RemovingObjectPermissionEntry -f $Path)

                    $acl.RemoveAccessRule($access)
                }
            }
        }
    }

    # Set the updated acl to the object
    $acl |
        Set-Acl -Path ($ADDrivePSPath + $Path)
}

<#
    .SYNOPSIS
        Test the object permission entry.

    .PARAMETER Ensure
        Indicates if the access will be added (Present) or will be removed
        (Absent). Default is 'Present'.

    .PARAMETER Path
        Active Directory path of the target object to add or remove the
        permission entry, specified as a Distinguished Name.

    .PARAMETER IdentityReference
        Indicates the identity of the principal for the permission entry.

    .PARAMETER ActiveDirectoryRights
        A combination of one or more of the ActiveDirectoryRights enumeration
        values that specifies the rights of the access rule. Default is
        'GenericAll'.

    .PARAMETER AccessControlType
        Indicates whether to Allow or Deny access to the target object.

    .PARAMETER ObjectType
        The schema GUID or display name of the object to which the access rule
        applies.

    .PARAMETER ActiveDirectorySecurityInheritance
        One of the 'ActiveDirectorySecurityInheritance' enumeration values that
        specifies the inheritance type of the access rule.

    .PARAMETER InheritedObjectType
        The schema GUID or display name of the child object type that can
        inherit this access rule.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.String]
        $IdentityReference,

        [Parameter()]
        [ValidateSet('AccessSystemSecurity', 'CreateChild', 'Delete', 'DeleteChild', 'DeleteTree', 'ExtendedRight', 'GenericAll', 'GenericExecute', 'GenericRead', 'GenericWrite', 'ListChildren', 'ListObject', 'ReadControl', 'ReadProperty', 'Self', 'Synchronize', 'WriteDacl', 'WriteOwner', 'WriteProperty')]
        [System.String[]]
        $ActiveDirectoryRights = 'GenericAll',

        [Parameter(Mandatory = $true)]
        [ValidateSet('Allow', 'Deny')]
        [System.String]
        $AccessControlType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ObjectType,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Children', 'Descendents', 'None', 'SelfAndChildren')]
        [System.String]
        $ActiveDirectorySecurityInheritance,

        [Parameter(Mandatory = $true)]
        [System.String]
        $InheritedObjectType
    )

    # Get the current state
    $getTargetResourceSplat = @{
        Path                               = $Path
        IdentityReference                  = $IdentityReference
        AccessControlType                  = $AccessControlType
        ObjectType                         = $ObjectType
        ActiveDirectorySecurityInheritance = $ActiveDirectorySecurityInheritance
        InheritedObjectType                = $InheritedObjectType
    }
    $currentState = Get-TargetResource @getTargetResourceSplat

    # Always check, if the ensure state is desired
    $returnValue = $currentState.Ensure -eq $Ensure

    # Only check the Active Directory rights, if ensure is set to present
    if ($Ensure -eq 'Present')
    {
        # Convert to array to a string for easy compare
        [System.String] $currentActiveDirectoryRights = ($currentState.ActiveDirectoryRights |
                Sort-Object) -join ', '

        [System.String] $desiredActiveDirectoryRights = ($ActiveDirectoryRights |
                Sort-Object) -join ', '

        $returnValue = $returnValue -and $currentActiveDirectoryRights -eq $desiredActiveDirectoryRights
    }

    if ($returnValue)
    {
        Write-Verbose -Message ($script:localizedData.ObjectPermissionEntryInDesiredState -f $Path)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ObjectPermissionEntryNotInDesiredState -f $Path)
    }

    return $returnValue
}

<#
    .SYNOPSIS
        Returns this computers's full PSPath for the AD Drive.

    .DESCRIPTION
        This is used to retrieve the full PSPath for the AD Drive, which varies between operating systems.

#>
function Get-ADDrivePSPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    # Need to use the full PSPath to avoid issues when escaping paths - https://github.com/dsccommunity/ActiveDirectoryDsc/issues/675
    # The full PSPath varies between operating systems, so we obtain it dynamically - https://github.com/dsccommunity/ActiveDirectoryDsc/issues/724

    Assert-ADPSDrive

    $adDrivePSPath = (Get-Item -Path 'AD:').PSPath
    Write-Verbose -Message ($script:localizedData.RetrievedADDrivePSPath -f $adDrivePSPath)
    return $adDrivePSPath
}

<#
    .SYNOPSIS
        Retrieves the schemaIDGUID or rightsGUID of an Active Directory object based on its display name.

    .DESCRIPTION
        This function searches the Active Directory schema for an object with the matching lDAPDisplayName, 
        or the Extended Rights container for an object with the matching displayName.

    .PARAMETER DisplayName
        The lDAPDisplayName (for schema objects) or displayName (for extended rights) to search for.

    .OUTPUTS
        System.String

        If a matching entry is found, the corresponding GUID (schemaIDGUID or rightsGUID) is returned.

    .EXAMPLE
        PS C:\> Get-ADSchemaGuid -DisplayName "user"

        Returns the schemaIDGUID of the schema object with lDAPDisplayName "user".

    .EXAMPLE
        PS C:\> Get-ADSchemaGuid -DisplayName "Send As"

        Returns the rightsGUID of the Extended Rights object with displayName "Send As".
#>
function Get-ADSchemaGuid
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DisplayName
    )

    try
    {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
    }
    catch
    {
        throw ($script:localizedData.FailedToRetrieveRootDSE -f $_)
    }

    $escapedDisplayName = Get-EscapedLdapFilterValue -Value $DisplayName

    # Search the schema for a matching lDAPDisplayName
    try
    {
        $schemaResults = @(Get-ADObject `
            -SearchBase $rootDse.schemaNamingContext `
            -LDAPFilter "(&(schemaIDGUID=*)(lDAPDisplayName=$escapedDisplayName))" `
            -Properties 'lDAPDisplayName','schemaIDGUID' `
            -ErrorAction Stop)
    }
    catch
    {
        throw ($script:localizedData.ErrorSearchingSchema -f $DisplayName, $_)
    }

    if ($schemaResults.Count -gt 1)
    {
        throw ($script:localizedData.ErrorMultipleSchemaObjectsFound -f $DisplayName)
    }
    elseif ($schemaResults.Count -eq 1)
    {
        return ([System.Guid]$schemaResults[0].schemaIDGUID).Guid
    }

    # If not found in the schema: search the Extended Rights container
    try
    {
        $rightsResults = @(Get-ADObject `
            -SearchBase "CN=Extended-Rights,$($rootDse.configurationNamingContext)" `
            -LDAPFilter "(&(objectClass=controlAccessRight)(displayName=$escapedDisplayName))" `
            -Properties 'displayName','rightsGUID' `
            -ErrorAction Stop)
    }
    catch
    {
        throw ($script:localizedData.ErrorSearchingExtendedRights -f $DisplayName, $_)
    }

    if ($rightsResults.Count -gt 1)
    {
        throw ($script:localizedData.ErrorMultipleExtendedRightsFound -f $DisplayName)
    }
    elseif ($rightsResults.Count -eq 1)
    {
        return ([System.Guid]$rightsResults[0].rightsGUID).Guid
    }

    throw ($script:localizedData.NoMatchingGuidFound -f $DisplayName)
}

<#
    .SYNOPSIS
        Checks whether a string is a valid GUID.

    .DESCRIPTION
        The 'Test-IsGuid' function uses the .NET method [System.Guid]::TryParse() to 
        determine whether the provided string is a valid GUID (Globally Unique Identifier).

    .PARAMETER InputString
        The string to be tested for a valid GUID format.

    .OUTPUTS
        System.Boolean

        Returns $true if the string is a valid GUID, otherwise returns $false.

    .EXAMPLE
        Test-IsGuid "550e8400-e29b-41d4-a716-446655440000"

        Returns 'True' because the string is a valid GUID.

    .EXAMPLE
        Test-IsGuid "abc"

        Returns 'False' because the string is not a valid GUID.
#>
function Test-IsGuid
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $InputString
    )

    $nullGuid = [System.Guid]::Empty
    return [System.Guid]::TryParse($InputString, [ref]$nullGuid)
}

<#
    .SYNOPSIS
        Escapes a string for safe use in an LDAP filter according to RFC 4515.

    .DESCRIPTION
        This function replaces special characters in the input string with their corresponding 
        escape sequences for use in LDAP filters (e.g., in Active Directory queries). It prevents 
        syntax errors or unexpected behavior when constructing LDAP search filters.

        The following characters are escaped:
        \ => \5c
        * => \2a
        ( => \28
        ) => \29
        NULL byte (ASCII 0) => \00

    .PARAMETER Value
        The input string to be escaped, such as a username or part of an LDAP search filter.

    .EXAMPLE
        PS> Get-EscapedLdapFilterValue -Value 'Smith (Admin)*'
        Smith \28Admin\29\2a

    .EXAMPLE
        PS> $filter = "(cn=$(Get-EscapedLdapFilterValue -Value 'Admin*'))"
        PS> $filter
        (cn=Admin\2a)
#>
function Get-EscapedLdapFilterValue
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Value
    )

    $escaped = $Value -replace '\\', '\5c'
    $escaped = $escaped -replace '\*', '\2a'
    $escaped = $escaped -replace '\(', '\28'
    $escaped = $escaped -replace '\)', '\29'
    $escaped = $escaped -replace "`0", '\00'

    return $escaped
}
