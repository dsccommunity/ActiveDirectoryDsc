data localizedString
{
    # culture="en-US"
    ConvertFrom-StringData @'
        RoleNotFoundError              = Please ensure that the PowerShell module for role '{0}' is installed
        MembersAndIncludeExcludeError  = The '{0}' and '{1}' and/or '{2}' parameters conflict. The '{0}' parameter should not be used in any combination with the '{1}' and '{2}' parameters.
        MembersIsNullError             = The Members parameter value is null. The '{0}' parameter must be provided if neither '{1}' nor '{2}' is provided.
        MembersIsEmptyError            = The Members parameter is empty.  At least one group member must be provided.
        IncludeAndExcludeConflictError = The member '{0}' is included in both '{1}' and '{2}' parameter values. The same member must not be included in both '{1}' and '{2}' parameter values.
        IncludeAndExcludeAreEmptyError = The '{0}' and '{1}' parameters are either both null or empty.  At least one member must be specified in one of these parameters.
        
        CheckingMembers                = Checking for '{0}' members.
        MembershipCountMismatch        = Membership count is not correct. Expected '{0}' members, actual '{1}' members.
        MemberNotInDesiredState        = Member '{0}' is not in the desired state.
        RemovingDuplicateMember        = Removing duplicate member '{0}' definition.
        MembershipInDesiredState       = Membership is in the desired state.
        MembershipNotDesiredState      = Membership is NOT in the desired state.
        CheckingDomain                 = Checking for domain '{0}'.
'@
}

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
        $errorId = '{0}_ModuleNotFound' -f $ModuleName;
        $errorMessage = $localizedString.RoleNotFoundError -f $moduleName;
        ThrowInvalidOperationError -ErrorId $errorId -ErrorMessage $errorMessage;
    }
} #end function Assert-Module

# Internal function to test whether computer is a member of a domain
function Test-DomainMember {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ( )
     $isDomainMember = [System.Boolean] (Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$false).PartOfDomain;
    return $isDomainMember;
}

# Internal function to build domain FQDN
function Resolve-DomainFQDN {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [OutputType([System.String])]
        [System.String] $DomainName,
        
        [Parameter()] [AllowNull()]
        [System.String] $ParentDomainName
    )
    $domainFQDN = $DomainName
    if ($ParentDomainName)
    {
        $domainFQDN = '{0}.{1}' -f $DomainName, $ParentDomainName;
    }
    return $domainFQDN
}

## Internal function to test/ domain availability
function Test-ADDomain
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory)]
        [String] $DomainName,

        [Parameter()]
        [PSCredential] $Credential
    )
    Write-Verbose -Message ($localizedString.CheckingDomain -f $DomainName);
    $ldapDomain = 'LDAP://{0}' -f $DomainName;
    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        $domain = New-Object DirectoryServices.DirectoryEntry($ldapDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password);
    }
    else
    {
        $domain = New-Object DirectoryServices.DirectoryEntry($ldapDomain);
    }
    return ($null -ne $domain);
}

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
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory)]
        [System.String]
        $DN
    )
    
    # https://www.uvm.edu/~gcd/2012/07/listing-parent-of-ad-object-in-powershell/
    $distinguishedNameParts = $DN -split '(?<![\\]),';
    $distinguishedNameParts[1..$($distinguishedNameParts.Count-1)] -join ',';

} #end function GetADObjectParentDN

# Internal function that validates the Members, MembersToInclude and MembersToExclude combination
# is valid. If the combination is invalid, an InvalidArgumentError is raised.
function Validate-MemberParameters
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
        $MembersToExclude,
        
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleName = 'xActiveDirectory'
    )

    if($PSBoundParameters.ContainsKey('Members'))
    {
        if($PSBoundParameters.ContainsKey('MembersToInclude') -or $PSBoundParameters.ContainsKey('MembersToExclude'))
        {
            # If Members are provided, Include and Exclude are not allowed.
            $errorId = '{0}_MembersPlusIncludeOrExcludeConflict' -f $ModuleName;
            $errorMessage = $localizedString.MembersAndIncludeExcludeError -f 'Members','MembersToInclude','MembersToExclude';
            ThrowInvalidArgumentError -ErrorId $errorId -ErrorMessage $errorMessage;
        }

        if ($Members.Length -eq 0) # )
        {
            $errorId = '{0}_MembersIsNull' -f $ModuleName;
            $errorMessage = $localizedString.MembersIsNullError -f 'Members','MembersToInclude','MembersToExclude';
            ThrowInvalidArgumentError -ErrorId $errorId -ErrorMessage $errorMessage;
        }
    }

    if ($PSBoundParameters.ContainsKey('MembersToInclude'))
    {
        $MembersToInclude = [System.String[]] @(Remove-DuplicateMembers -Members $MembersToInclude);
    }

    if ($PSBoundParameters.ContainsKey('MembersToExclude'))
    {
        $MembersToExclude = [System.String[]] @(Remove-DuplicateMembers -Members $MembersToExclude);
    }

    if (($PSBoundParameters.ContainsKey('MembersToInclude')) -and ($PSBoundParameters.ContainsKey('MembersToExclude')))
    {
        if (($MembersToInclude.Length -eq 0) -and ($MembersToExclude.Length -eq 0))
        {
            $errorId = '{0}_EmptyIncludeAndExclude' -f $ModuleName;
            $errorMessage = $localizedString.IncludeAndExcludeAreEmptyError -f 'MembersToInclude', 'MembersToExclude';
            ThrowInvalidArgumentError -ErrorId $errorId -ErrorMessage $errorMessage;
        }

        # Both MembersToInclude and MembersToExlude were provided. Check if they have common principals.
        foreach ($member in $MembersToInclude)
        {
            if ($member -in $MembersToExclude)
            {
                $errorId = '{0}_IncludeAndExcludeConflict' -f $ModuleName;
                $errorMessage = $localizedString.IncludeAndExcludeConflictError -f $member, 'MembersToInclude', 'MembersToExclude';
                ThrowInvalidArgumentError -ErrorId $errorId -ErrorMessage $errorMessage;
            }
        }
    }
        
} #end function ValidateMemberParameters

## Internal function to remove duplicate strings (members) from a string array
function Remove-DuplicateMembers
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
                Write-Verbose -Message ($localizedString.RemovingDuplicateMember -f $Members[$sourceIndex]);
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

# Internal function to test whether the existing array members match the defined explicit array
# members, the included members are present and the exlcuded members are not present.
function Test-Members
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        ## Existing array members
        [AllowNull()]
        [System.String[]]
        $ExistingMembers,
        
        ## Explicit array members
        [AllowNull()]
        [System.String[]]
        $Members,
        
        ## Compulsory array members
        [AllowNull()]
        [System.String[]]
        $MembersToInclude,
        
        ## Excluded array members
        [AllowNull()]
        [System.String[]]
        $MembersToExclude
    )

    if ($Members.Count -gt 0)
    {
        Write-Verbose ($localizedString.CheckingMembers -f 'Explicit');
        $Members = [System.String[]] @(Remove-DuplicateMembers -Members $Members);
        if ($ExistingMembers.Count -ne $Members.Count)
        {
            Write-Verbose -Message ($localizedString.MembershipCountMismatch -f $Members.Count, $ExistingMembers.Count);
            return $false;
        }

        foreach ($member in $Members)
        {
            if ($member -notin $ExistingMembers)
            {
                Write-Verbose -Message ($Localizeda.MemberNotInDesiredState -f $member);;
                return $false;
            }
        }
    } #end if $Members

    if ($MembersToInclude.Count -gt 0)
    {
        Write-Verbose -Message ($localizedString.CheckingMembers -f 'Included');
        $MembersToInclude = [System.String[]] @(Remove-DuplicateMembers -Members $MembersToInclude);
        foreach ($member in $MembersToInclude)
        {
            if ($member -notin $ExistingMembers)
            {
                Write-Verbose -Message ($localizedString.MemberNotInDesiredState -f $member);
                return $false;
            }
        }
    } #end if $MembersToInclude

    if ($MembersToExclude.Count -gt 0)
    {
        Write-Verbose -Message ($localizedString.CheckingMembers -f 'Excluded');
        $MembersToExclude = [System.String[]] @(Remove-DuplicateMembers -Members $MembersToExclude);
        foreach ($member in $MembersToExclude)
        {
            if ($member -in $ExistingMembers)
            {
                Write-Verbose -Message ($localizedString.MemberNotInDesiredState -f $member);
                return $false;
            }
        }
    } #end if $MembersToExclude

    Write-Verbose -Message $localizedString.MembershipInDesiredState;
    return $true;

} #end function Test-Membership

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
