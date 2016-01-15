# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
RoleNotFoundError              = Please ensure that the PowerShell module for role '{0}' is installed
MembersAndIncludeExcludeError  = The '{0}' and '{1}' and/or '{2}' parameters conflict. The '{0}' parameter should not be used in any combination with the '{1}' and '{2}' parameters.
MembersIsNullError             = The Members parameter value is null. The '{0}' parameter must be provided if neither '{1}' nor '{2}' is provided.
MembersIsEmptyError            = The Members parameter is empty.  At least one group member must be provided.
IncludeAndExcludeConflictError = The principal '{0}' is included in both '{1}' and '{2}' parameter values. The same principal must not be included in both '{1}' and '{2}' parameter values.
IncludeAndExcludeAreEmptyError = The '{0}' and '{1}' parameters are either both null or empty.  At least one member must be specified in one of these parameters.
                               
RetrievingGroupMembers         = Retrieving group membership based on '{0}' property.
RemovingDuplicateGroupMember   = Removing duplicate group member '{0}' definition.
CheckingGroupMembers           = Checking for '{0}' group members.
GroupMemberNotInDesiredState   = Group member '{0}' is not in the desired state.
GroupMembershipInDesiredState  = Group membership is in the desired state.
GroupMembershipNotDesiredState = Group membership is NOT in the desired state. 
GroupMembershipCountMismatch   = Group membership count is not correct. Expected '{0}' members, actual '{1}' members.
AddingGroupMembers             = Adding '{0}' member(s) to AD group '{1}'.
RemovingGroupMembers           = Removing '{0}' member(s) from AD group '{1}'.
AddingGroup                    = Adding AD Group '{0}'
UpdatingGroup                  = Updating AD Group '{0}'
RemovingGroup                  = Removing AD Group '{0}'
MovingGroup                    = Moving AD Group '{0}' to '{1}'
GroupNotFound                  = AD Group '{0}' was not found
NotDesiredPropertyState        = AD Group '{0}' is not correct. Expected '{1}', actual '{2}'
UpdatingGroupProperty          = Updating AD Group property '{0}' to '{1}'
'@
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GroupName,

        [ValidateSet('DomainLocal','Global','Universal')]
        [System.String]
        $GroupScope = 'Global',

        [ValidateSet('Security','Distribution')]
        [System.String]
        $Category = 'Security',

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = "Present",

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Members,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToInclude,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToExclude,

        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

        ## This must be the user's DN
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ManagedBy,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Notes
    )
    Assert-Module -ModuleName 'ActiveDirectory';
    $adGroupParams = Get-ADCommonParameters @PSBoundParameters;
    try {
        $adGroup = Get-ADGroup @adGroupParams -Property Name,GroupScope,GroupCategory,DistinguishedName,Description,DisplayName,ManagedBy,Info;
        Write-Verbose -Message ($LocalizedData.RetrievingGroupMembers -f $MembershipAttribute);
        ## Retrieve the current list of members using the specified proper
        $adGroupMembers = (Get-ADGroupMember -Identity $adGroup.DistinguishedName).$MembershipAttribute; 
        $targetResource = @{
            GroupName = $adGroup.Name;
            GroupScope = $adGroup.GroupScope;
            Category = $adGroup.GroupCategory;
            Path = Get-ADObjectParentDN -DN $adGroup.DistinguishedName;
            Description = $adGroup.Description;
            DisplayName = $adGroup.DisplayName;
            Members = $adGroupMembers;
            MembersToInclude = $MembersToInclude;
            MembersToExclude = $MembersToExclude;
            MembershipAttribute = $MembershipAttribute;
            ManagedBy = $adGroup.ManagedBy;
            Notes = $adGroup.Info;
            Ensure = 'Absent';
        }
        if ($adGroup)
        {
            $targetResource['Ensure'] = 'Present';
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose ($LocalizedData.GroupNotFound -f $GroupName);
        $targetResource = @{
            GroupName = $GroupName;
            GroupScope = $GroupScope;
            Category = $Category;
            Path = $Path;
            Description = $Description;
            DisplayName = $DisplayName;
            Members = @();
            MembersToInclude = $MembersToInclude;
            MembersToExclude = $MembersToExclude;
            MembershipAttribute = $MembershipAttribute;
            ManagedBy = $ManagedBy;
            Notes = $Notes;
            Ensure = 'Absent';
        }
    }
    return $targetResource;
} #end function Get-TargetResource

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GroupName,

        [ValidateSet('DomainLocal','Global','Universal')]
        [System.String]
        $GroupScope = 'Global',

        [ValidateSet('Security','Distribution')]
        [System.String]
        $Category = 'Security',

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = "Present",

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Members,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToInclude,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToExclude,

        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

        ## This must be the user's DN
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ManagedBy,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Notes
    )
    ## Validate parameters before we even attempt to retrieve anything
    $validateMemberParametersParams = @{};
    if ($PSBoundParameters.ContainsKey('Members'))
    {
        $validateMemberParametersParams['Members'] = $Members;
    }
    if ($PSBoundParameters.ContainsKey('MembersToInclude'))
    {
        $validateMemberParametersParams['MembersToInclude'] = $MembersToInclude;
    }
    if ($PSBoundParameters.ContainsKey('MembersToExclude'))
    {
        $validateMemberParametersParams['MembersToExclude'] = $MembersToExclude;
    }
    ValidateMemberParameters @validateMemberParametersParams -ErrorAction Stop;
    
    $targetResource = Get-TargetResource @PSBoundParameters;
    $targetResourceInCompliance = $true;
    if ($targetResource.GroupScope -ne $GroupScope)
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'GroupScope', $GroupScope, $targetResource.GroupScope);
        $targetResourceInCompliance = $false;
    }
    if ($targetResource.Category -ne $Category)
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Category', $Category, $targetResource.Category);
        $targetResourceInCompliance = $false;
    }
    if ($Path -and ($targetResource.Path -ne $Path))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Path', $Path, $targetResource.Path);
        $targetResourceInCompliance = $false;
    }
    if ($Description -and ($targetResource.Description -ne $Description))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Description', $Description, $targetResource.Description);
        $targetResourceInCompliance = $false;
    }
    if ($DisplayName -and ($targetResource.DisplayName -ne $DisplayName))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'DisplayName', $DisplayName, $targetResource.DisplayName);
        $targetResourceInCompliance = $false;
    }
    if ($ManagedBy -and ($targetResource.ManagedBy -ne $ManagedBy))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'ManagedBy', $ManagedBy, $targetResource.ManagedBy);
        $targetResourceInCompliance = $false;
    }
    if ($Notes -and ($targetResource.Notes -ne $Notes))
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Notes', $Notes, $targetResource.Notes);
        $targetResourceInCompliance = $false;
    }
    $testGroupMembershipParams = @{
        GroupMembers = $targetResource.Members;
        Members = $Members;
        MembersToInclude=  $MembersToInclude;
        MembersToExclude = $MembersToExclude;
    }
    if (-not (TestGroupMembership @testGroupMembershipParams))
    {
        Write-Verbose -Message $LocalizedData.GroupMembershipNotDesiredState;
        $targetResourceInCompliance = $false;
    }
    if ($targetResource.Ensure -ne $Ensure)
    {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Ensure', $Ensure, $targetResource.Ensure);
        $targetResourceInCompliance = $false;
    }
    return $targetResourceInCompliance;
} #end function Test-TargetResource

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GroupName,

        [ValidateSet('DomainLocal','Global','Universal')]
        [System.String]
        $GroupScope = 'Global',

        [ValidateSet('Security','Distribution')]
        [System.String]
        $Category = 'Security',

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = "Present",

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Members,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToInclude,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToExclude,

        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

        ## This must be the user's DN
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ManagedBy,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Notes

    )
    Assert-Module -ModuleName 'ActiveDirectory';
    $adGroupParams = Get-ADCommonParameters @PSBoundParameters;
    
    try {
        $adGroup = Get-ADGroup @adGroupParams -Property Name,GroupScope,GroupCategory,DistinguishedName,Description,DisplayName,Info;

        if ($Ensure -eq 'Present') {

            $setADGroupParams = @{};

            # Update existing group properties
            if ($Category -ne $adGroup.GroupCategory)
            {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Category', $Category);
                $setADGroupParams['GroupCategory'] = $Category;
            }
            if ($GroupScope -ne $adGroup.GroupScope)
            {
                ## Cannot change DomainLocal to Global or vice versa directly. Need to change them to a Universal group first!
                Set-ADGroup -Identity $adGroup.DistinguishedName -GroupScope Universal;
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'GroupScope', $GroupScope);
                $setADGroupParams['GroupScope'] = $GroupScope;
            }
            if ($Description -and ($Description -ne $adGroup.Description))
            {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Description', $Description);
                $setADGroupParams['Description'] = $Description;
            }
            if ($DisplayName -and ($DisplayName -ne $adGroup.DisplayName))
            {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'DisplayName', $DisplayName);
                $setADGroupParams['DisplayName'] = $DisplayName;
            }
            if ($ManagedBy -and ($ManagedBy -ne $adGroup.ManagedBy))
            {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'ManagedBy', $ManagedBy);
                $setADGroupParams['ManagedBy'] = $ManagedBy;
            }
            if ($Notes -and ($Notes -ne $adGroup.Info))
            {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Notes', $Notes);
                $setADGroupParams['Replace'] = @{ Info = $Notes };
            }
            Write-Verbose ($LocalizedData.UpdatingGroup -f $GroupName);
            Set-ADGroup -Identity $adGroup.DistinguishedName @setADGroupParams;

            # Move group if the path is not correct
            if ($Path -and ($Path -ne (Get-ADObjectParentDN -DN $adGroup.DistinguishedName))) {
                Write-Verbose ($LocalizedData.MovingGroup -f $GroupName, $Path);
                Move-ADObject -Identity $adGroup.DistinguishedName -TargetPath $Path;
            }

            Write-Verbose -Message ($LocalizedData.RetrievingGroupMembers -f $MembershipAttribute);
            $adGroupMembers = (Get-ADGroupMember @adGroupParams).$MembershipAttribute;
            if (-not (TestGroupMembership -GroupMembers $adGroupMembers -Members $Members -MembersToInclude $MembersToInclude -MembersToExclude $MembersToExclude))
            {
                ## The fact that we're in the Set method, there is no need to validate the parameter
                ## combination as this was performed in the Test method
                if ($PSBoundParameters.ContainsKey('Members'))
                {
                    # Remove all existing first and add explicit members
                    $Members = RemoveDuplicateMembers -Members $Members;
                    # We can only remove members if there are members already in the group!
                    if ($adGroupMembers.Count -gt 0)
                    {
                        Write-Verbose -Message ($LocalizedData.RemovingGroupMembers -f $adGroupMembers.Count, $GroupName);
                        Remove-ADGroupMember @adGroupParams -Members $adGroupMembers -Confirm:$false;
                    }
                    Write-Verbose -Message ($LocalizedData.AddingGroupMembers -f $Members.Count, $GroupName);
                    Add-ADGroupMember @adGroupParams -Members $Members;
                }
                if ($PSBoundParameters.ContainsKey('MembersToInclude'))
                {
                    $MembersToInclude = RemoveDuplicateMembers -Members $MembersToInclude;
                    Write-Verbose -Message ($LocalizedData.AddingGroupMembers -f $MembersToInclude.Count, $GroupName);
                    Add-ADGroupMember @adGroupParams -Members $MembersToInclude;
                }
                if ($PSBoundParameters.ContainsKey('MembersToExclude'))
                {
                    $MembersToExclude = RemoveDuplicateMembers -Members $MembersToExclude;
                    Write-Verbose -Message ($LocalizedData.RemovingGroupMembers -f $MembersToExclude.Count, $GroupName);
                    Remove-ADGroupMember @adGroupParams -Members $MembersToExclude -Confirm:$false;
                }
            }
        }
        elseif ($Ensure -eq 'Absent')
        {
            # Remove existing group
            Write-Verbose ($LocalizedData.RemovingGroup -f $GroupName);
            Remove-ADGroup @adGroupParams -Confirm:$false;
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        ## The AD group doesn't exist
        if ($Ensure -eq 'Present')
        {
      
            Write-Verbose ($LocalizedData.GroupNotFound -f $GroupName);
            Write-Verbose ($LocalizedData.AddingGroup -f $GroupName);
      
            $adGroupParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter;
            if ($Description)
            {
                $adGroupParams['Description'] = $Description;
            }
            if ($DisplayName)
            {
                $adGroupParams['DisplayName'] = $DisplayName;
            }
            if ($ManagedBy)
            {
                $adGroupParams['ManagedBy'] = $ManagedBy;
            }
            if ($Path)
            {
                $adGroupParams['Path'] = $Path;
            }
            ## Create group
            $adGroup = New-ADGroup @adGroupParams -GroupCategory $Category -GroupScope $GroupScope -PassThru;
      
            ## Only the New-ADGroup cmdlet takes a -Name parameter. Refresh
            ## the parameters with the -Identity parameter rather than -Name
            $adGroupParams = Get-ADCommonParameters @PSBoundParameters
      
            if ($Notes) {
                ## Can't set the Notes field when creating the group
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Notes', $Notes);
                Set-ADGroup -Identity $adGroup.DistinguishedName -Add @{ Info = $Notes };
            }
      
            ## Add the required members
            if ($PSBoundParameters.ContainsKey('Members'))
            {
                $Members = RemoveDuplicateMembers -Members $Members;
                Write-Verbose -Message ($LocalizedData.AddingGroupMembers -f $Members.Count, $GroupName);
                Add-ADGroupMember @adGroupParams -Members $Members;
            }
            elseif ($PSBoundParameters.ContainsKey('MembersToInclude'))
            {
                $MembersToInclude = RemoveDuplicateMembers -Members $MembersToInclude;
                Write-Verbose -Message ($LocalizedData.AddingGroupMembers -f $MembersToInclude.Count, $GroupName);
                Add-ADGroupMember @adGroupParams -Members $MembersToInclude;
            }
      
        }
    } #end catch
} #end function Set-TargetResource

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
        $errorMsg = $($LocalizedData.RoleNotFoundError) -f $moduleName;
        $exception = New-Object System.InvalidOperationException $errorMessage;
        $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null;
        throw $errorRecord;
    }
} #end function Assert-Module

# Internal function to get an Active Directory object's parent Distinguished Name
function Get-ADObjectParentDN {
    # https://www.uvm.edu/~gcd/2012/07/listing-parent-of-ad-object-in-powershell/
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.String]
        $DN
    )
    $distinguishedNameParts = $DN -split '(?<![\\]),';
    $distinguishedNameParts[1..$($distinguishedNameParts.Count-1)] -join ',';
} #end function Get-ADObjectParentDN

# Internal function to build common parameters for the Active Directory cmdlets
function Get-ADCommonParameters {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GroupName,

        [ValidateSet('DomainLocal','Global','Universal')]
        [System.String]
        $GroupScope = 'Global',

        [ValidateSet('Security','Distribution')]
        [System.String]
        $Category = 'Security',

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = "Present",

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Members,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToInclude,
        
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $MembersToExclude,

        [ValidateSet('SamAccountName','DistinguishedName','SID','ObjectGUID')]
        [System.String]
        $MembershipAttribute = 'SamAccountName',

        ## This must be the user's DN
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ManagedBy,

        [ValidateNotNullOrEmpty()]
        [System.String]
        $Notes,

        [System.Management.Automation.SwitchParameter]
        $UseNameParameter
    )
    ## The Get-ADGroup and Set-ADGroup cmdlets take an -Identity parameter, but the New-ADGroup cmdlet uses the -Name parameter
    if ($UseNameParameter)
    {
        $adGroupCommonParameters = @{ Name = $GroupName; }
    }
    else
    {
        $adGroupCommonParameters = @{ Identity = $GroupName; }
    }

    if ($Credential)
    {
        $adGroupCommonParameters['Credential'] = $Credential;
    }
    if ($DomainController)
    {
        $adGroupCommonParameters['Server'] = $DomainController;
    }
    return $adGroupCommonParameters;

} #end function Get-ADCommonParameters

# Internal function that validates the Members, MembersToInclude and MembersToExclude combination
# is valid. If the combination is invalid, an InvalidArgumentError is raised.
function ValidateMemberParameters
{
    [CmdletBinding()]
    param
    (
        [ValidateNotNull()]
        [System.String[]]
        $Members,
        
        [ValidateNotNull()]
        [System.String[]]
        $MembersToInclude,
        
        [ValidateNotNull()]
        [System.String[]]
        $MembersToExclude
    )

    if($PSBoundParameters.ContainsKey('Members'))
    {
        if($PSBoundParameters.ContainsKey('MembersToInclude') -or $PSBoundParameters.ContainsKey('MembersToExclude'))
        {
            # If Members are provided, Include and Exclude are not allowed.
            ThrowInvalidArgumentError -ErrorId 'xADGroup_MembersPlusIncludeOrExcludeConflict' -ErrorMessage ($LocalizedData.MembersAndIncludeExcludeError -f 'Members','MembersToInclude','MembersToExclude');
        }

        if ($Members.Length -eq 0) # )
        {
            ThrowInvalidArgumentError -ErrorId 'xADGroup_MembersIsNull' -ErrorMessage ($LocalizedData.MembersIsNullError -f 'Members','MembersToInclude','MembersToExclude');
        }
    }

    if ($PSBoundParameters.ContainsKey('MembersToInclude'))
    {
        $MembersToInclude = [System.String[]] @(RemoveDuplicateMembers -Members $MembersToInclude);
    }

    if ($PSBoundParameters.ContainsKey('MembersToExclude'))
    {
        $MembersToExclude = [System.String[]] @(RemoveDuplicateMembers -Members $MembersToExclude);
    }

    if (($PSBoundParameters.ContainsKey('MembersToInclude')) -and ($PSBoundParameters.ContainsKey('MembersToExclude')))
    {
        if (($MembersToInclude.Length -eq 0) -and ($MembersToExclude.Length -eq 0))
        {
            ThrowInvalidArgumentError -ErrorId 'xADGroup_EmptyIncludeAndExclude' -ErrorMessage ($LocalizedData.IncludeAndExcludeAreEmptyError -f 'MembersToInclude', 'MembersToExclude');
        }

        # Both MembersToInclude and MembersToExlude were provided. Check if they have common principals.
        foreach ($member in $MembersToInclude)
        {
            if ($member -in $MembersToExclude)
            {
                ThrowInvalidArgumentError -ErrorId 'xADGroup_IncludeAndExcludeConflict' -ErrorMessage ($LocalizedData.IncludeAndExcludeConflictError -f $member, 'MembersToInclude', 'MembersToExclude');
            }
        }
    }
        
} #end function ValidateMemberParameters

## Internal function to remove duplicate strings (members) from a string array
function RemoveDuplicateMembers
{
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [System.String[]] $Members
    )

    Set-StrictMode -Version Latest

    $destIndex = 0;
    for([int] $sourceIndex = 0 ; $sourceIndex -lt $Members.Count; $sourceIndex++)
    {
        $matchFound = $false;
        for([int] $matchIndex = 0; $matchIndex -lt $destIndex; $matchIndex++)
        {
            if($Members[$sourceIndex] -eq $Members[$matchIndex])
            {
                # A duplicate is found. Discard the duplicate.
                Write-Verbose -Message ($LocalizedData.RemovingDuplicateGroupMember -f $Members[$sourceIndex]);
                $matchFound = $true;
                continue;
            }
        }

        if(!$matchFound)
        {
            $Members[$destIndex++] = $Members[$sourceIndex].ToLowerInvariant();
        }
    }

    # Create the output array.
    $destination = New-Object -TypeName System.String[] -ArgumentList $destIndex;

    # Copy only distinct elements from the original array to the destination array.
    [System.Array]::Copy($Members, $destination, $destIndex);

    return $destination;

} #end function RemoveDuplicateMembers

# Internal function to test whether the existing group members match the defined explicit group
# members, the included members are present and the exlcuded members are not present.
function TestGroupMembership
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        ## Existing AD Group SamAccountNames
        #[Parameter(Mandatory)]
        [AllowNull()]
        [System.String[]]
        $GroupMembers,
        
        ## Explicit members
        [AllowNull()]
        [System.String[]]
        $Members ,
        
        ## Compulsory group members
        [AllowNull()]
        [System.String[]]
        $MembersToInclude,
        
        ## Excluded group members
        [AllowNull()]
        [System.String[]]
        $MembersToExclude
    )

    if ($Members.Count -gt 0)
    {
        Write-Verbose ($LocalizedData.CheckingGroupMembers -f 'Explicit');
        $Members = [System.String[]] @(RemoveDuplicateMembers -Members $Members);
        if ($GroupMembers.Count -ne $Members.Count)
        {
            Write-Verbose -Message ($LocalizedData.GroupMembershipCountMismatch -f $Members.Count, $GroupMembers.Count);
            return $false;
        }

        foreach ($member in $Members)
        {
            if ($member -notin $GroupMembers)
            {
                Write-Verbose -Message ($LocalizedData.GroupMemberNotInDesiredState -f $member);;
                return $false;
            }
        }
    } #end if $Members

    if ($MembersToInclude.Count -gt 0)
    {
        Write-Verbose -Message ($LocalizedData.CheckingGroupMembers -f 'Included');
        $MembersToInclude = [System.String[]] @(RemoveDuplicateMembers -Members $MembersToInclude);
        foreach ($member in $MembersToInclude)
        {
            if ($member -notin $GroupMembers)
            {
                Write-Verbose -Message ($LocalizedData.GroupMemberNotInDesiredState -f $member);
                return $false;
            }
        }
    } #end if $MembersToInclude

    if ($MembersToExclude.Count -gt 0)
    {
        Write-Verbose -Message ($LocalizedData.CheckingGroupMembers -f 'Excluded');
        $MembersToExclude = [System.String[]] @(RemoveDuplicateMembers -Members $MembersToExclude);
        foreach ($member in $MembersToExclude)
        {
            if ($member -in $GroupMembers)
            {
                Write-Verbose -Message ($LocalizedData.GroupMemberNotInDesiredState -f $member);
                return $false;
            }
        }
    } #end if $MembersToExclude

    Write-Verbose -Message $LocalizedData.GroupMembershipInDesiredState;
    return $true;

} #end function TestGroupMembership

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

    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument;
    $exception = New-Object -TypeName System.ArgumentException -ArgumentList $ErrorMessage;
    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $exception, $ErrorId, $errorCategory, $null;
    throw $errorRecord;

} #end function ThrowInvalidArgumentError

#Export-ModuleMember -Function *-TargetResource;
