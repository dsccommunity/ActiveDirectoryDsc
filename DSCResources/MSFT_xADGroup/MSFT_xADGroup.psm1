# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
RoleNotFoundError       = Please ensure that the PowerShell module for role '{0}' is installed
AddingGroup             = Adding AD Group '{0}'
UpdatingGroup           = Updating AD Group '{0}'
RemovingGroup           = Removing AD Group '{0}'
MovingGroup             = Moving AD Group '{0}' to '{1}'
GroupNotFound           = AD Group '{0}' was not found
NotDesiredPropertyState = AD Group '{0}' is not correct. Expected '{1}', actual '{2}'
UpdatingGroupProperty   = Updating AD Group property '{0}' to '{1}'
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
        $Scope = 'Global',

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
        $DomainController
    )
    Assert-Module -ModuleName 'ActiveDirectory';
    $adGroupParams = Get-ADCommonParameters @PSBoundParameters;
    try {
        $adGroup = Get-ADGroup @adGroupParams -Property Name,GroupScope,GroupCategory,DistinguishedName,Description,DisplayName;
        $targetResource = @{
            GroupName = $adGroup.Name;
            Scope = $adGroup.GroupScope;
            Category = $adGroup.GroupCategory;
            Path = Get-ADObjectParentDN -DN $adGroup.DistinguishedName;
            Description = $adGroup.Description;
            DisplayName = $adGroup.DisplayName;
            Ensure = 'Present';
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose ($LocalizedData.GroupNotFound -f $GroupName);
        $targetResource = @{
            GroupName = $GroupName;
            Scope = $Scope;
            Category = $Category;
            Path = $Path;
            Description = $Description;
            DisplayName = $DisplayName;
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
        $Scope = 'Global',

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
        $DomainController
    )
    $adGroup = Get-TargetResource @PSBoundParameters;
    $targetResourceInCompliance = $true;
    if ($adGroup.Scope -ne $Scope) {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Scope', $Scope, $adGroup.Scope);
        $targetResourceInCompliance = $false;
    }
    elseif ($adGroup.Category -ne $Category) {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Category', $Category, $adGroup.Category);
        $targetResourceInCompliance = $false;
    }
    elseif ($Path -and ($adGroup.Path -ne $Path)) {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Path', $Path, $adGroup.Path);
        $targetResourceInCompliance = $false;
    }
    elseif ($Description -and ($adGroup.Description -ne $Description)) {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Description', $Description, $adGroup.Description);
        $targetResourceInCompliance = $false;
    }
    elseif ($DisplayName -and ($adGroup.DisplayName -ne $DisplayName)) {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'DisplayName', $DisplayName, $adGroup.DisplayName);
        $targetResourceInCompliance = $false;
    }
    elseif ($adGroup.Ensure -ne $Ensure) {
        Write-Verbose ($LocalizedData.NotDesiredPropertyState -f 'Ensure', $Ensure, $adGroup.Ensure);
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
        $Scope = 'Global',

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
        $DomainController
    )
    Assert-Module -ModuleName 'ActiveDirectory';
    $adGroupParams = Get-ADCommonParameters @PSBoundParameters;
    
    try {
        $adGroup = Get-ADGroup @adGroupParams -Property Name,GroupScope,GroupCategory,DistinguishedName,Description,DisplayName;

        if ($Ensure -eq 'Present') {

            $setADGroupParams = @{};

            # Update existing group properties
            if ($Category -ne $adGroup.GroupCategory) {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Category', $Category);
                $setADGroupParams['Category'] = $Categrory;
            }
            if ($Scope -ne $adGroup.GroupScope) {
                ## Cannot change DomainLocal to Global or vice versa. Need to change them to Universal groups first!
                Set-ADGroup -Identity $adGroup.DistinguishedName -GroupScope Universal;
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Scope', $Scope);
                $setADGroupParams['GroupScope'] = $Scope;
            }
            if ($Description -and ($Description -ne $adGroup.Description)) {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'Description', $Description);
                $setADGroupParams['Description'] = $Description;
            }
            if ($DisplayName -and ($DisplayName -ne $adGroup.DisplayName)) {
                Write-Verbose ($LocalizedData.UpdatingGroupProperty -f 'DisplayName', $DisplayName);
                $setADGroupParams['DisplayName'] = $DisplayName;
            }
            Write-Verbose ($LocalizedData.UpdatingGroup -f $GroupName);
            Set-ADGroup -Identity $adGroup.DistinguishedName @setADGroupParams;

            # Move group if the path is not correct
            if ($Path -and ($Path -ne (Get-ADObjectParentDN -DN $adGroup.DistinguishedName))) {
                Write-Verbose ($LocalizedData.MovingGroup -f $GroupName, $Path);
                Move-ADObject -Identity $adGroup.DistinguishedName -TargetPath $Path;
            }

        }
        elseif ($Ensure -eq 'Absent') {
            # Remove existing group
            Write-Verbose ($LocalizedData.RemovingGroup -f $GroupName);
            Remove-ADGroup @adGroupParams -Confirm:$false;
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        ## The AD group doesn't exist
        if ($Ensure -eq 'Present') {

            Write-Verbose ($LocalizedData.GroupNotFound -f $GroupName);
            Write-Verbose ($LocalizedData.AddingGroup -f $GroupName);

            $adGroupParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter;
            if ($Description) {
                $adGroupParams['Description'] = $Description;
            }
            if ($DisplayName) {
                $adGroupParams['DisplayName'] = $DisplayName;
            }
            if ($Path) {
                $adGroupParams['Path'] = $Path;
            }
            ## Create group
            New-ADGroup @adGroupParams -GroupCategory $Category -GroupScope $Scope;

        }
    } #end catch
} #end function Set-TargetResource

# Internal function to assert if the role specific module is installed or not
function Assert-Module
{
    [CmdletBinding()]
    param (
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
}

# Internal function to build common parameters for the Active Directory cmdlets
function Get-ADCommonParameters {
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
        $Scope = 'Global',

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

        [Switch]
        $UseNameParameter
    )
    ## The Get-ADGroup and Set-ADGroup parameters take an -Identity parameter, but the New-ADGroup cmdlet uses the -Name parameter
    if ($UseNameParameter) {
        $adGroupCommonParameters = @{ Name = $GroupName; }
    }
    else {
        $adGroupCommonParameters = @{ Identity = $GroupName; }
    }

    if ($Credential) {
        $adGroupCommonParameters['Credential'] = $Credential;
    }
    if ($DomainController) {
        $adGroupCommonParameters['Server'] = $DomainController;
    }
    return $adGroupCommonParameters;
} #end function Get-ADCommonParameters

Export-ModuleMember -Function *-TargetResource;
