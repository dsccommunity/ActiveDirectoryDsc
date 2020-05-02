$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Returns the current state of the Active Directory group.

    .PARAMETER GroupName
         Name of the Active Directory group.

    .PARAMETER Credential
        Credentials used to enact the change upon.

    .PARAMETER DomainController
        Active Directory domain controller to enact the change upon.

        .PARAMETER MembershipAttribute
        Active Directory attribute used to perform membership operations.
        Default value is 'SamAccountName'.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Get-ADGroup                   | ActiveDirectory
            Get-ADGroupMember             | ActiveDirectory
            Assert-Module                 | ActiveDirectoryDsc.Common
            Get-ADCommonParameters        | ActiveDirectoryDsc.Common
            Get-ADObjectParentDN          | ActiveDirectoryDsc.Common
            New-InvalidOperationException | ActiveDirectoryDsc.Common
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
        $GroupName,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [Parameter()]
        [ValidateSet('SamAccountName', 'DistinguishedName', 'SID', 'ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName'
    )

    Assert-Module -ModuleName 'ActiveDirectory'

    $commonParameters = Get-ADCommonParameters @PSBoundParameters

    Write-Verbose -Message ($script:localizedData.RetrievingADGroup -f $GroupName, $DomainName)

    $getADGroupProperties = ('Name', 'GroupScope', 'GroupCategory', 'DistinguishedName', 'Description', 'DisplayName',
        'ManagedBy', 'Info')

    try
    {
        $adGroup = Get-ADGroup @commonParameters -Properties $getADGroupProperties
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message ($script:localizedData.ADUserNotPresent -f $GroupName, $DomainName)

        $adGroup = $null
    }
    catch
    {
        $errorMessage = $script:localizedData.RetrievingADGroupError -f $GroupName, $DomainName
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }

    if ($adGroup)
    {
        Write-Verbose -Message ($script:localizedData.ADGroupIsPresent -f $GroupName, $DomainName)
        Write-Verbose -Message ($script:localizedData.RetrievingGroupMembers -f $MembershipAttribute)

        try
        {
            [System.Array] $adGroupMembers = (Get-ADGroupMember @commonParameters).$MembershipAttribute
        }
        catch
        {
            # This FullyQualifiedErrorId is indicative of a failure to retrieve members with Get-ADGroupMember
            # for a one-way trust
            $oneWayTrustFullyQualifiedErrorId = `
                'ActiveDirectoryServer:0,Microsoft.ActiveDirectory.Management.Commands.GetADGroupMember'

            if ($_.FullyQualifiedErrorId -eq $oneWayTrustFullyQualifiedErrorId)
            {
                # Get-ADGroupMember returns property name 'SID' while Get-ADObject returns property name 'ObjectSID'
                if ($MembershipAttribute -eq 'SID')
                {
                    $selectProperty = 'ObjectSID'
                }
                else
                {
                    $selectProperty = $MembershipAttribute
                }

                # Use the same results from Get-ADCommonParameters but remove the Identity
                # for usage with Get-ADObject
                $getADObjectParameters = $commonParameters.Clone()
                $getADObjectParameters.Remove('Identity')

                # Retrieve the current list of members, returning the specified membership attribute
                [System.Array] $adGroupMembers = $adGroup.Members | ForEach-Object -Process {
                    # Adding a Filter and additional Properties for the AD object retrieval
                    $getADObjectParameters['Filter'] = "DistinguishedName -eq '$($_)'"
                    $getADObjectParameters['Properties'] = @(
                        'SamAccountName',
                        'ObjectSID'
                    )

                    $adObject = Get-ADObject @getADObjectParameters

                    # Perform SID translation to a readable name as the SamAccountName if the member is
                    # of objectClass "foreignSecurityPrincipal"
                    $classMatchForResolve = $adObject.objectClass -eq 'foreignSecurityPrincipal'
                    $attributeMatchForResolve = $MembershipAttribute -eq 'SamAccountName'

                    if ($classMatchForResolve -and $attributeMatchForResolve)
                    {
                        Resolve-SamAccountName -ObjectSid $adObject.objectSid
                    }
                    else
                    {
                        $adObject.$selectProperty
                    }
                }
            }
            else
            {
                $errorMessage = $script:localizedData.RetrievingGroupMembersError -f $GroupName
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }
        }

        $targetResource = @{
            Ensure              = 'Present'
            GroupName           = $adGroup.Name
            GroupScope          = $adGroup.GroupScope
            Category            = $adGroup.GroupCategory
            DistinguishedName   = $adGroup.DistinguishedName
            Path                = Get-ADObjectParentDN -DN $adGroup.DistinguishedName
            Description         = $adGroup.Description
            DisplayName         = $adGroup.DisplayName
            Members             = $adGroupMembers
            MembersToInclude    = $null
            MembersToExclude    = $null
            MembershipAttribute = $MembershipAttribute
            ManagedBy           = $adGroup.ManagedBy
            Notes               = $adGroup.Info
        }
    }
    else
    {
        $targetResource = @{
            Ensure              = 'Absent'
            GroupName           = $GroupName
            GroupScope          = $null
            Category            = $null
            DistinguishedName   = $null
            Path                = $null
            Description         = $null
            DisplayName         = $null
            Members             = @()
            MembersToInclude    = $null
            MembersToExclude    = $null
            MembershipAttribute = $MembershipAttribute
            ManagedBy           = $null
            Notes               = $null
        }
    }

    return $targetResource
}

<#
    .SYNOPSIS
        Determines if the Active Directory group is in the desired state.

    .PARAMETER GroupName
         Name of the Active Directory group.

    .PARAMETER GroupScope
        Active Directory group scope. Default value is 'Global'.

    .PARAMETER Category
        Active Directory group category. Default value is 'Security'.

    .PARAMETER Path
        Location of the group within Active Directory expressed as a Distinguished Name.

    .PARAMETER Ensure
        Specifies if this Active Directory group should be present or absent.
        Default value is 'Present'.

    .PARAMETER Description
        Description of the Active Directory group.

    .PARAMETER DisplayName
        Display name of the Active Directory group.

    .PARAMETER Credential
        Credentials used to enact the change upon.

    .PARAMETER DomainController
        Active Directory domain controller to enact the change upon.

    .PARAMETER Members
        Active Directory group membership should match membership exactly.

    .PARAMETER MembersToInclude
        Active Directory group should include these members.

    .PARAMETER MembersToExclude
        Active Directory group should NOT include these members.

    .PARAMETER MembershipAttribute
        Active Directory attribute used to perform membership operations.
        Default value is 'SamAccountName'.

    .PARAMETER ManagedBy
        Active Directory managed by attribute specified as a DistinguishedName.

    .PARAMETER Notes
        Active Directory group notes field.

    .PARAMETER RestoreFromRecycleBin
        Try to restore the group from the recycle bin before creating a new one.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GroupName,

        [Parameter()]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [System.String]
        $GroupScope = 'Global',

        [Parameter()]
        [ValidateSet('Security', 'Distribution')]
        [System.String]
        $Category = 'Security',

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
        $DomainController,

        [Parameter()]
        [System.String[]]
        $Members,

        [Parameter()]
        [System.String[]]
        $MembersToInclude,

        [Parameter()]
        [System.String[]]
        $MembersToExclude,

        [Parameter()]
        [ValidateSet('SamAccountName', 'DistinguishedName', 'SID', 'ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

        # This must be the user's DN
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ManagedBy,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Notes,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin
    )

    # Validate parameters before we even attempt to retrieve anything
    $assertMemberParameters = @{ }

    # Members parameter should always be tested to enforce an empty group (issue #189)
    if ($PSBoundParameters.ContainsKey('Members'))
    {
        $assertMemberParameters['Members'] = $Members
    }

    if ($PSBoundParameters.ContainsKey('MembersToInclude') -and -not [System.String]::IsNullOrEmpty($MembersToInclude))
    {
        $assertMemberParameters['MembersToInclude'] = $MembersToInclude
    }

    if ($PSBoundParameters.ContainsKey('MembersToExclude') -and -not [System.String]::IsNullOrEmpty($MembersToExclude))
    {
        $assertMemberParameters['MembersToExclude'] = $MembersToExclude
    }

    Assert-MemberParameters @assertMemberParameters

    [HashTable] $parameters = $PSBoundParameters
    $parameters['MembershipAttribute'] = $MembershipAttribute

    $getTargetResourceParameters = @{
        GroupName           = $GroupName
        AccountType         = $AccountType
        DomainController    = $DomainController
        MembershipAttribute = $MembershipAttribute
    }

    @($getTargetResourceParameters.Keys) |
        ForEach-Object {
            if (-not $parameters.ContainsKey($_))
            {
                $getTargetResourceParameters.Remove($_)
            }
        }

    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

    if ($getTargetResourceResult.Ensure -eq 'Present')
    {
        # Resource exists
        if ($Ensure -eq 'Present')
        {
            # Resource should exist

            # Test group members match passed membership parameters
            if (-not (Test-Members @assertMemberParameters -ExistingMembers $targetResource.Members))
            {
                Write-Verbose -Message $script:localizedData.GroupMembershipNotDesiredState
                $membersInDesiredState = $false
            }
            else
            {
                $membersInDesiredState = $true
            }

            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $getTargetResourceResult -DesiredValues $parameters `
                    -IgnoreProperties 'DomainController', 'Credential' | Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState -or $membersInDesiredState -eq $false)
            {
                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $GroupName)
                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should not exist
            Write-Verbose -Message ($script:localizedData.ResourceExistsButShouldNotMessage -f $GroupName)
            $inDesiredState = $false
        }
    }
    else
    {
        # Resource does not exist
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            Write-Verbose -Message ($script:localizedData.ResourceDoesNotExistButShouldMessage -f $GroupName)
            $inDesiredState = $false
        }
        else
        {
            # Resource should not exist
            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $GroupName)
            $inDesiredState = $true
        }
    }

    return $inDesiredState
}

<#
    .SYNOPSIS
        Sets the state of an Active Directory group.

    .PARAMETER GroupName
         Name of the Active Directory group.

    .PARAMETER GroupScope
        Active Directory group scope. Default value is 'Global'.

    .PARAMETER Category
        Active Directory group category. Default value is 'Security'.

    .PARAMETER Path
        Location of the group within Active Directory expressed as a Distinguished Name.

    .PARAMETER Ensure
        Specifies if this Active Directory group should be present or absent.
        Default value is 'Present'.

    .PARAMETER Description
        Description of the Active Directory group.

    .PARAMETER DisplayName
        Display name of the Active Directory group.

    .PARAMETER Credential
        Credentials used to enact the change upon.

    .PARAMETER DomainController
        Active Directory domain controller to enact the change upon.

    .PARAMETER Members
        Active Directory group membership should match membership exactly.

    .PARAMETER MembersToInclude
        Active Directory group should include these members.

    .PARAMETER MembersToExclude
        Active Directory group should NOT include these members.

    .PARAMETER MembershipAttribute
        Active Directory attribute used to perform membership operations.
        Default value is 'SamAccountName'.

    .PARAMETER ManagedBy
        Active Directory managed by attribute specified as a DistinguishedName.

    .PARAMETER Notes
        Active Directory group notes field.

    .PARAMETER RestoreFromRecycleBin
        Try to restore the group from the recycle bin before creating a new one.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GroupName,

        [Parameter()]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [System.String]
        $GroupScope = 'Global',

        [Parameter()]
        [ValidateSet('Security', 'Distribution')]
        [System.String]
        $Category = 'Security',

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
        $DomainController,

        [Parameter()]
        [System.String[]]
        $Members,

        [Parameter()]
        [System.String[]]
        $MembersToInclude,

        [Parameter()]
        [System.String[]]
        $MembersToExclude,

        [Parameter()]
        [ValidateSet('SamAccountName', 'DistinguishedName', 'SID', 'ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

        # This must be the user's DN
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ManagedBy,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Notes,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin

    )

    $assertMemberParameters = @{ }

    # Members parameter should always be added to enforce an empty group (issue #189)
    if ($PSBoundParameters.ContainsKey('Members'))
    {
        $assertMemberParameters['Members'] = $Members
    }

    if ($PSBoundParameters.ContainsKey('MembersToInclude') -and -not [System.String]::IsNullOrEmpty($MembersToInclude))
    {
        $assertMemberParameters['MembersToInclude'] = $MembersToInclude
    }

    if ($PSBoundParameters.ContainsKey('MembersToExclude') -and -not [System.String]::IsNullOrEmpty($MembersToExclude))
    {
        $assertMemberParameters['MembersToExclude'] = $MembersToExclude
    }

    Assert-MemberParameters @assertMemberParameters

    if ($MembershipAttribute -eq 'DistinguishedName')
    {
        $allMembers = $Members + $MembersToInclude + $MembersToExclude

        $groupMemberDomains = @()

        foreach ($member in $allMembers)
        {
            $groupMemberDomains += Get-ADDomainNameFromDistinguishedName -DistinguishedName $member
        }

        $uniqueGroupMemberDomainCount = $groupMemberDomains |
            Select-Object -Unique

        $GroupMemberDomainCount = $uniqueGroupMemberDomainCount.count

        if ($GroupMemberDomainCount -gt 1 -or ($groupMemberDomains -ine (Get-DomainName)).Count -gt 0)
        {
            Write-Verbose -Message ($script:localizedData.GroupMembershipMultipleDomains -f $GroupMemberDomainCount)
        }
    }

    $getTargetResourceParameters = @{
        GroupName           = $GroupName
        AccountType         = $AccountType
        DomainController    = $DomainController
        MembershipAttribute = $MembershipAttribute
    }

    @($getTargetResourceParameters.Keys) |
        ForEach-Object {
            if (-not $parameters.ContainsKey($_))
            {
                $getTargetResourceParameters.Remove($_)
            }
        }

    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

    if ($Ensure -eq 'Present')
    {
        # Resource should be present
        if ($getTargetResourceResult.Ensure -eq 'Present')
        {
            # Resource is present
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $getTargetResourceResult -DesiredValues $parameters `
                    -IgnoreProperties 'DomainController', 'Credential' | Where-Object -Property InDesiredState -eq $false)
            if ($propertiesNotInDesiredState)
            {
                $setADGroupParams = $commonParameters.Clone()
                $setADGroupParams['Identity'] = $getTargetResourceResult.DistinguishedName
                $SetAdGroupRequired = $false
                $moveAdGroupRequired = $false

                foreach ($property in $propertiesNotInDesiredState)
                {
                    if ($property.ParameterName -eq 'Path')
                    {
                        # The path has changed, so the account needs moving, but not until after any other changes
                        $moveAdGroupRequired = $true
                    }
                    elseif ($property.ParameterName -eq 'GroupScope')
                    {
                        #  Cannot change DomainLocal <-> Global directly, so need to change to a Universal group first
                        Set-ADGroup -Identity $getTargetResourceResult.DistinguishedName -GroupScope 'Universal' `
                            -ErrorAction 'Stop'

                        Write-Verbose -Message ($script:localizedData.UpdatingResourceProperty -f
                            $GroupName, $property.ParameterName, $property.Expected)

                        $SetAdGroupParameters.Add($property.ParameterName, $property.Expected)
                    }
                    else
                    {
                        $setAdGroupRequired = $true

                        Write-Verbose -Message ($script:localizedData.UpdatingResourcePropertyMessage -f
                            $GroupName, $property.ParameterName, ($property.Expected -join ', '))

                        $SetAdGroupParameters.Add($property.ParameterName, $property.Expected)
                    }
                }

                if ($setAdGroupRequired)
                {
                    try
                    {
                        Set-ADGroup @setADGroupParameters
                    }
                    catch
                    {
                        $errorMessage = ($script:localizedData.SettingResourceError -f $GroupName)
                        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                    }
                }
            }

            if ($assertMemberParameters.Count -gt 0)
            {
                Write-Verbose -Message ($script:localizedData.RetrievingGroupMembers -f $MembershipAttribute)

                try
                {
                    $adGroupMembers = (Get-ADGroupMember @commonParameters).$MembershipAttribute
                }
                catch
                {
                    # This FullyQualifiedErrorId is indicative of a failure to retrieve members with Get-ADGroupMember
                    # for a one-way trust
                    $oneWayTrustFullyQualifiedErrorId = `
                        'ActiveDirectoryServer:0,Microsoft.ActiveDirectory.Management.Commands.GetADGroupMember'

                    if ($_.FullyQualifiedErrorId -eq $oneWayTrustFullyQualifiedErrorId)
                    {
                        # Get-ADGroupMember returns property name 'SID' while Get-ADObject
                        # returns property name 'ObjectSID'
                        if ($MembershipAttribute -eq 'SID')
                        {
                            $selectProperty = 'ObjectSID'
                        }
                        else
                        {
                            $selectProperty = $MembershipAttribute
                        }

                        # Use the same results from Get-ADCommonParameters but remove the Identity
                        # for usage with Get-ADObject
                        $getADObjectParameters = $commonParameters.Clone()
                        $getADObjectParameters.Remove('Identity')

                        $adGroupMemberDNs = (Get-ADGroup @commonParameters -Properties Members).Members

                        # Retrieve the current list of members, returning the specified membership attribute
                        $adGroupMembers = $adGroupMemberDNs | ForEach-Object -Process {
                            # Adding a Filter and additional Properties for the AD object retrieval
                            $getADObjectParameters['Filter'] = "DistinguishedName -eq '$($_)'"
                            $getADObjectParameters['Properties'] = @(
                                'SamAccountName',
                                'ObjectSID'
                            )

                            $adObject = Get-ADObject @getADObjectParameters

                            # Perform SID translation to a readable name as the SamAccountName if the member is
                            # of objectClass "foreignSecurityPrincipal"
                            $classMatchForResolve = $adObject.objectClass -eq 'foreignSecurityPrincipal'
                            $attributeMatchForResolve = $MembershipAttribute -eq 'SamAccountName'

                            if ($classMatchForResolve -and $attributeMatchForResolve)
                            {
                                Resolve-SamAccountName -ObjectSid $adObject.objectSid
                            }
                            else
                            {
                                $adObject.$selectProperty
                            }
                        }
                    }
                    else
                    {
                        $errorMessage = $script:localizedData.RetrievingGroupMembersError -f $GroupName
                        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                    }
                }

                $assertMemberParameters['ExistingMembers'] = $adGroupMembers

                # Return $false if the members mismatch.
                if (-not (Test-Members @assertMemberParameters))
                {
                    # Members parameter should always be enforce if it is bound (issue #189)
                    if ($PSBoundParameters.ContainsKey('Members'))
                    {
                        # Remove all existing first and add explicit members
                        $Members = Remove-DuplicateMembers -Members $Members

                        # We can only remove members if there are members already in the group!
                        if ($adGroupMembers.Count -gt 0)
                        {
                            Write-Verbose -Message ($script:localizedData.RemovingGroupMembers -f
                                $adGroupMembers.Count, $GroupName)

                            $setADCommonGroupMemberParms = @{
                                Members             = $adGroupMembers
                                MembershipAttribute = $MembershipAttribute
                                Parameters          = $commonParameters
                                Action              = 'Remove'
                            }
                            Set-ADCommonGroupMember @setADCommonGroupMemberParms
                        }

                        Write-Verbose -Message ($script:localizedData.AddingGroupMembers -f
                            $Members.Count, $GroupName)

                        $setADCommonGroupMemberParms = @{
                            Members             = $Members
                            MembershipAttribute = $MembershipAttribute
                            Parameters          = $commonParameters
                            Action              = 'Add'
                        }
                        Set-ADCommonGroupMember @setADCommonGroupMemberParms
                    }

                    if ($PSBoundParameters.ContainsKey('MembersToInclude') -and
                        -not [System.String]::IsNullOrEmpty($MembersToInclude))
                    {
                        $MembersToInclude = Remove-DuplicateMembers -Members $MembersToInclude

                        Write-Verbose -Message ($script:localizedData.AddingGroupMembers -f
                            $MembersToInclude.Count, $GroupName)

                        $setADCommonGroupMemberParms = @{
                            Members             = $MembersToInclude
                            MembershipAttribute = $MembershipAttribute
                            Parameters          = $commonParameters
                            Action              = 'Add'
                        }
                        Set-ADCommonGroupMember @setADCommonGroupMemberParms
                    }

                    if ($PSBoundParameters.ContainsKey('MembersToExclude') -and
                        -not [System.String]::IsNullOrEmpty($MembersToExclude))
                    {
                        $MembersToExclude = Remove-DuplicateMembers -Members $MembersToExclude

                        Write-Verbose -Message ($script:localizedData.RemovingGroupMembers -f
                            $MembersToExclude.Count, $GroupName)

                        $setADCommonGroupMemberParms = @{
                            Members             = $MembersToExclude
                            MembershipAttribute = $MembershipAttribute
                            Parameters          = $commonParameters
                            Action              = 'Remove'
                        }
                        Set-ADCommonGroupMember @setADCommonGroupMemberParms
                    }
                }
            }

            if ($moveAdGroupRequired)
            {
                Write-Verbose -Message ($script:localizedData.MovingGroup -f $GroupName, $Path)

                $moveADObjectParams = $commonParameters.Clone()
                $moveADObjectParams['Identity'] = $getTargetResourceResult.DistinguishedName

                try
                {
                    Move-ADObject @moveADObjectParams -TargetPath $Path
                }
                catch
                {
                    $errorMessage = ($script:localizedData.MovingResourceError -f
                        $GroupName, $getTargetResourceResult.Path, $Path)
                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
        else
        {
            # Resource is absent
            $commonParametersUsingName = Get-ADCommonParameters @PSBoundParameters -UseNameParameter

            $newAdGroupParameters = $commonParametersUsingName.Clone()
            $newAdGroupParameters['GroupCategory'] = $Category
            $newAdGroupParameters['GroupScope'] = $GroupScope

            if ($PSBoundParameters.ContainsKey('Description'))
            {
                $newAdGroupParameters['Description'] = $Description
            }

            if ($PSBoundParameters.ContainsKey('DisplayName'))
            {
                $newAdGroupParameters['DisplayName'] = $DisplayName
            }

            if ($PSBoundParameters.ContainsKey('ManagedBy'))
            {
                $newAdGroupParameters['ManagedBy'] = $ManagedBy
            }

            if ($PSBoundParameters.ContainsKey('Path'))
            {
                $newAdGroupParameters['Path'] = $Path
            }

            if ($PSBoundParameters.ContainsKey('Notes'))
            {
                $newAdGroupParameters['OtherAttributes'] = @{
                    Notes = $Notes
                }
            }

            $adGroup = $null

            # Create group. Try to restore account first if it exists.
            if ($RestoreFromRecycleBin)
            {
                Write-Verbose -Message ($script:localizedData.RestoringGroup -f $GroupName)

                $restoreParams = Get-ADCommonParameters @PSBoundParameters

                $adGroup = Restore-ADCommonObject @restoreParams -ObjectClass 'Group'
            }

            # Check if the Active Directory group was restored, if not create the group.
            if (-not $adGroup)
            {
                Write-Verbose -Message ($script:localizedData.AddingGroup -f $GroupName)

                try
                {
                    $adGroup = New-ADGroup @newAdGroupParameters -PassThru -ErrorAction 'Stop'
                }
                catch
                {
                    $errorMessage = ($script:localizedData.AddingResourceError -f $GroupName)
                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }

            # Add the required members
            if ($PSBoundParameters.ContainsKey('Members') -and -not [System.String]::IsNullOrEmpty($Members))
            {
                $Members = Remove-DuplicateMembers -Members $Members

                Write-Verbose -Message ($script:localizedData.AddingGroupMembers -f $Members.Count, $GroupName)

                $setADCommonGroupMemberParms = @{
                    Members             = $Members
                    MembershipAttribute = $MembershipAttribute
                    Parameters          = $commonParameters
                    Action              = 'Add'
                }
                Set-ADCommonGroupMember @setADCommonGroupMemberParms
            }
            elseif ($PSBoundParameters.ContainsKey('MembersToInclude') -and
                -not [System.String]::IsNullOrEmpty($MembersToInclude))
            {
                $MembersToInclude = Remove-DuplicateMembers -Members $MembersToInclude

                Write-Verbose -Message ($script:localizedData.AddingGroupMembers -f
                    $MembersToInclude.Count, $GroupName)

                $setADCommonGroupMemberParms = @{
                    Members             = $MembersToInclude
                    MembershipAttribute = $MembershipAttribute
                    Parameters          = $commonParameters
                    Action              = 'Add'
                }
                Set-ADCommonGroupMember @setADCommonGroupMemberParms
            }
        }
    }
    else
    {
        # Resource should be absent
        if ($getTargetResourceResult.Ensure -eq 'Present')
        {
            # Resource is present
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $GroupName)

            try
            {
                Remove-ADGroup @commonParameters -Confirm:$false
            }
            catch
            {
                $errorMessage = ($script:localizedData.RemovingResourceError -f $GroupName)
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }
        }
        else
        {
            # Resource is absent
            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $GroupName)
        }
    }
}

Export-ModuleMember -Function *-TargetResource
