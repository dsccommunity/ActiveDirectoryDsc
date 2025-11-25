$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Returns the current state of the read only domain controller account.

    .PARAMETER DomainControllerAccountName
        Provide the name of the Read Domain Controller Account which will be created.

    .PARAMETER DomainName
        Provide the FQDN of the domain the Read Domain Controller Account is being created in.

    .PARAMETER Credential
        Specifies the credential for the account used to add the read only domain controller account.

    .PARAMETER SiteName
        Provide the name of the site you want the Read Only Domain Controller Account to be added to.

    .PARAMETER InstallDns
        Specifies if the DNS Server service should be installed and configured on
        the read only domain controller. If this is not set the default value of the parameter
        InstallDns of the cmdlet Add-ADDSReadOnlyDomainControllerAccount is used.
        The parameter `InstallDns` is only used during the provisioning of a read only domain
        controller. The parameter cannot be used to install or uninstall the DNS
        server on an already provisioned read only domain controller.

        Not used in Get-TargetResource.

    .NOTES
        Used Functions:
            Name                                            | Module
            ------------------------------------------------|--------------------------
            Get-ADDomain                                    | ActiveDirectory
            Get-ADDomainControllerPasswordReplicationPolicy | ActiveDirectory
            Get-DomainControllerObject                      | ActiveDirectoryDsc.Common
            Assert-Module                                   | DscResource.Common
            New-ObjectNotFoundException                     | DscResource.Common
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainControllerAccountName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Boolean]
        $InstallDns
    )

    Assert-Module -ModuleName 'ActiveDirectory'

    Write-Verbose -Message ($script:localizedData.ResolveDomainName -f $DomainName)

    $Domain = Get-DomainObject -Identity $DomainName -Credential $Credential -ErrorOnUnexpectedExceptions -Verbose:$VerbosePreference

    if (-not $Domain)
    {
        $errorMessage = $script:localizedData.MissingDomain -f $DomainName
        New-ObjectNotFoundException -Message $errorMessage
    }

    Write-Verbose -Message ($script:localizedData.DomainPresent -f $DomainName)

    $domainControllerObject = Get-DomainControllerObject `
        -DomainName $DomainName -ComputerName $DomainControllerAccountName -Credential $Credential

    if ($domainControllerObject.IsReadOnly)
    {
        Write-Verbose -Message ($script:localizedData.IsReadOnlyDomainControllerAccount -f
            $domainControllerObject.Name, $domainControllerObject.Domain)

        # Retrieve any user or group that is a delegated administrator via the ManagedBy attribute
        $delegateAdministratorAccountName = $null
        $domainControllerComputerObject = $domainControllerObject.ComputerObjectDN |
            Get-ADComputer -Properties ManagedBy -Credential $Credential
        if ($domainControllerComputerObject.ManagedBy)
        {
            $domainControllerManagedByObject = $domainControllerComputerObject.ManagedBy |
                Get-ADObject -Properties objectSid -Credential $Credential

            $delegateAdministratorAccountName = Resolve-SamAccountName -ObjectSid $domainControllerManagedByObject.objectSid
        }

        $allowedPasswordReplicationAccountName = (
            Get-ADDomainControllerPasswordReplicationPolicy -Allowed -Identity $domainControllerObject |
            ForEach-Object -MemberName sAMAccountName)
        $deniedPasswordReplicationAccountName = (
            Get-ADDomainControllerPasswordReplicationPolicy -Denied -Identity $domainControllerObject |
            ForEach-Object -MemberName sAMAccountName)

        $targetResource = @{
            AllowPasswordReplicationAccountName = @($allowedPasswordReplicationAccountName)
            Credential                          = $Credential
            DelegatedAdministratorAccountName   = $delegateAdministratorAccountName
            DenyPasswordReplicationAccountName  = @($deniedPasswordReplicationAccountName)
            DomainControllerAccountName         = $domainControllerObject.Name
            DomainName                          = $domainControllerObject.Domain
            Ensure                              = $true
            InstallDns                          = $InstallDns
            IsGlobalCatalog                     = $domainControllerObject.IsGlobalCatalog
            SiteName                            = $domainControllerObject.Site
            Enabled                             = $domainControllerObject.Enabled
        }
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.NotReadOnlyDomainControllerAccount -f
            $domainControllerObject.Name, $domainControllerObject.Domain)

        $targetResource = @{
            AllowPasswordReplicationAccountName = $null
            Credential                          = $Credential
            DelegatedAdministratorAccountName   = $null
            DenyPasswordReplicationAccountName  = $null
            DomainControllerAccountName         = $DomainControllerAccountName
            DomainName                          = $DomainName
            Ensure                              = $false
            InstallDns                          = $false
            IsGlobalCatalog                     = $false
            SiteName                            = $null
            Enabled                             = $false
        }
    }

    return $targetResource
}

<#
    .SYNOPSIS
        Creates a read only domain controller account.

    .PARAMETER DomainControllerAccountName
        Provide the name of the Read Domain Controller Account which will be created.

    .PARAMETER DomainName
        Provide the FQDN of the domain the Read Domain Controller Account is being created in.

    .PARAMETER Credential
        Specifies the credential for the account used to add the read only domain controller account.

    .PARAMETER SiteName
        Provide the name of the site you want the Read Only Domain Controller Account to be added to.

    .PARAMETER IsGlobalCatalog
        Specifies if the read only domain controller will be a Global Catalog (GC).

    .PARAMETER DelegatedAdministratorAccountName
        Specifies the user or group that is the delegated administrator of this read only domain controller account.

    .PARAMETER AllowPasswordReplicationAccountName
        Provides a list of the users, computers, and groups to add to the password replication allowed list.

    .PARAMETER DenyPasswordReplicationAccountName
        Provides a list of the users, computers, and groups to add to the password replication denied list.

    .PARAMETER InstallDns
        Specifies if the DNS Server service should be installed and configured on
        the read only domain controller. If this is not set the default value of the parameter
        InstallDns of the cmdlet Add-ADDSReadOnlyDomainControllerAccount is used.
        The parameter `InstallDns` is only used during the provisioning of a read only domain
        controller. The parameter cannot be used to install or uninstall the DNS
        server on an already provisioned read only domain controller.

    .NOTES
        Used Functions:
            Name                                               | Module
            ---------------------------------------------------|--------------------------
            Add-ADDSReadOnlyDomainControllerAccount            | ActiveDirectory
            Set-ADObject                                       | ActiveDirectory
            Move-ADDirectoryServer                             | ActiveDirectory
            Remove-ADDomainControllerPasswordReplicationPolicy | ActiveDirectory
            Add-ADDomainControllerPasswordReplicationPolicy    | ActiveDirectory
            Get-DomainControllerObject                         | ActiveDirectoryDsc.Common
            Get-DomainObject                                   | ActiveDirectoryDsc.Common
            New-InvalidOperationException                      | DscResource.Common
#>
function Set-TargetResource
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
        Justification = 'Read-Only Domain Controller (RODC) Account Creation support(AllowPasswordReplicationAccountName and DenyPasswordReplicationAccountName)')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainControllerAccountName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Boolean]
        $IsGlobalCatalog,

        [Parameter()]
        [System.String]
        $DelegatedAdministratorAccountName,

        [Parameter()]
        [System.String[]]
        $AllowPasswordReplicationAccountName,

        [Parameter()]
        [System.String[]]
        $DenyPasswordReplicationAccountName,

        [Parameter()]
        [System.Boolean]
        $InstallDns
    )

    $getTargetResourceParameters = @{
        DomainControllerAccountName   = $DomainControllerAccountName
        DomainName                    = $DomainName
        Credential                    = $Credential
        SiteName                      = $SiteName
    }

    $targetResource = Get-TargetResource @getTargetResourceParameters

    if ($targetResource.Ensure -eq $false)
    {
        Write-Verbose -Message ($script:localizedData.Adding -f $DomainControllerAccountName, $DomainName)

        # Read only domain controller is not created so we add it.
        $addADDSReadOnlyDomainControllerAccountParameters = @{
            DomainControllerAccountName   = $DomainControllerAccountName
            DomainName                    = $DomainName
            Credential                    = $Credential
            SiteName                      = $SiteName
            Force                         = $true
        }

        if ($PSBoundParameters.ContainsKey('DelegatedAdministratorAccountName'))
        {
            $addADDSReadOnlyDomainControllerAccountParameters.Add('DelegatedAdministratorAccountName',
                $DelegatedAdministratorAccountName)
        }

        if ($PSBoundParameters.ContainsKey('AllowPasswordReplicationAccountName'))
        {
            $addADDSReadOnlyDomainControllerAccountParameters.Add('AllowPasswordReplicationAccountName',
                $AllowPasswordReplicationAccountName)
        }

        if ($PSBoundParameters.ContainsKey('DenyPasswordReplicationAccountName'))
        {
            $addADDSReadOnlyDomainControllerAccountParameters.Add('DenyPasswordReplicationAccountName',
                $DenyPasswordReplicationAccountName)
        }

        if ($PSBoundParameters.ContainsKey('IsGlobalCatalog') -and $IsGlobalCatalog -eq $false)
        {
            $addADDSReadOnlyDomainControllerAccountParameters.Add('NoGlobalCatalog', $true)
        }

        if ($PSBoundParameters.ContainsKey('InstallDns'))
        {
            $addADDSReadOnlyDomainControllerAccountParameters.Add('InstallDns', $InstallDns)
        }

        Add-ADDSReadOnlyDomainControllerAccount @addADDSReadOnlyDomainControllerAccountParameters

        Write-Verbose -Message ($script:localizedData.Added -f $DomainControllerAccountName, $DomainName)
    }
    elseif ($targetResource.Ensure)
    {
        # Read only domain controller account already created. We check if other properties are in desired state

        Write-Verbose -Message ($script:localizedData.IsReadOnlyDomainControllerAccount -f $DomainControllerAccountName, $DomainName)

        $domainControllerObject = Get-DomainControllerObject `
            -DomainName $DomainName -ComputerName $DomainControllerAccountName -Credential $Credential

        # Check if Node Global Catalog state is correct
        if ($PSBoundParameters.ContainsKey('IsGlobalCatalog') -and
            $targetResource.IsGlobalCatalog -ne $IsGlobalCatalog)
        {
            # RODC is not in the expected Global Catalog state
            if ($IsGlobalCatalog)
            {
                $globalCatalogOptionValue = 1

                Write-Verbose -Message $script:localizedData.AddGlobalCatalog
            }
            else
            {
                $globalCatalogOptionValue = 0

                Write-Verbose -Message $script:localizedData.RemoveGlobalCatalog
            }

            Set-ADObject -Identity $domainControllerObject.NTDSSettingsObjectDN -Replace @{
                options = $globalCatalogOptionValue
            }
        }

        if ($targetResource.SiteName -ne $SiteName)
        {
            # RODC is not in correct site. Move it.
            Write-Verbose -Message ($script:localizedData.MovingDomainController -f
                $targetResource.SiteName, $SiteName)

            Move-ADDirectoryServer -Identity $DomainControllerAccountName -Site $SiteName -Credential $Credential
        }

        if ($PSBoundParameters.ContainsKey('DelegatedAdministratorAccountName') -and
            $targetResource.DelegatedAdministratorAccountName -ne $DelegatedAdministratorAccountName)
        {
            # Set the delegated administrator via the ManagedBy attribute
            Write-Verbose -Message ($script:localizedData.UpdatingDelegatedAdministratorAccountName -f
            $targetResource.DelegatedAdministratorAccountName, $DelegatedAdministratorAccountName)

            $delegateAdministratorAccountSecurityIdentifier = Resolve-SecurityIdentifier -SamAccountName $DelegatedAdministratorAccountName

            Set-ADComputer -Identity $domainControllerObject.ComputerObjectDN `
                -ManagedBy $delegateAdministratorAccountSecurityIdentifier -Credential $Credential
        }

        if ($PSBoundParameters.ContainsKey('AllowPasswordReplicationAccountName'))
        {
            $testMembersParameters = @{
                ExistingMembers = $targetResource.AllowPasswordReplicationAccountName
                Members         = $AllowPasswordReplicationAccountName
            }

            if (-not (Test-Members @testMembersParameters))
            {
                Write-Verbose -Message (
                    $script:localizedData.AllowedSyncAccountsMismatch -f
                    ($targetResource.AllowPasswordReplicationAccountName -join ';'),
                    ($AllowPasswordReplicationAccountName -join ';')
                )

                $getMembersToAddAndRemoveParameters = @{
                    DesiredMembers = $AllowPasswordReplicationAccountName
                    CurrentMembers = $targetResource.AllowPasswordReplicationAccountName
                }

                $getMembersToAddAndRemoveResult = Get-MembersToAddAndRemove @getMembersToAddAndRemoveParameters

                $adPrincipalsToRemove = $getMembersToAddAndRemoveResult.MembersToRemove
                $adPrincipalsToAdd = $getMembersToAddAndRemoveResult.MembersToAdd

                if ($null -ne $adPrincipalsToRemove)
                {
                    $removeADPasswordReplicationPolicy = @{
                        Identity    = $domainControllerObject
                        AllowedList = $adPrincipalsToRemove
                    }

                    Remove-ADDomainControllerPasswordReplicationPolicy @removeADPasswordReplicationPolicy `
                        -Confirm:$false
                }

                if ($null -ne $adPrincipalsToAdd)
                {
                    $addADPasswordReplicationPolicy = @{
                        Identity    = $domainControllerObject
                        AllowedList = $adPrincipalsToAdd
                    }

                    Add-ADDomainControllerPasswordReplicationPolicy @addADPasswordReplicationPolicy
                }
            }
        }

        if ($PSBoundParameters.ContainsKey('DenyPasswordReplicationAccountName'))
        {
            $testMembersParameters = @{
                ExistingMembers = $targetResource.DenyPasswordReplicationAccountName
                Members         = $DenyPasswordReplicationAccountName;
            }

            if (-not (Test-Members @testMembersParameters))
            {
                Write-Verbose -Message (
                    $script:localizedData.DenySyncAccountsMismatch -f
                    ($targetResource.DenyPasswordReplicationAccountName -join ';'),
                    ($DenyPasswordReplicationAccountName -join ';')
                )

                $getMembersToAddAndRemoveParameters = @{
                    DesiredMembers = $DenyPasswordReplicationAccountName
                    CurrentMembers = $targetResource.DenyPasswordReplicationAccountName
                }

                $getMembersToAddAndRemoveResult = Get-MembersToAddAndRemove @getMembersToAddAndRemoveParameters

                $adPrincipalsToRemove = $getMembersToAddAndRemoveResult.MembersToRemove
                $adPrincipalsToAdd = $getMembersToAddAndRemoveResult.MembersToAdd

                if ($null -ne $adPrincipalsToRemove)
                {
                    $removeADPasswordReplicationPolicy = @{
                        Identity   = $domainControllerObject
                        DeniedList = $adPrincipalsToRemove
                    }

                    Remove-ADDomainControllerPasswordReplicationPolicy @removeADPasswordReplicationPolicy `
                        -Confirm:$false
                }

                if ($null -ne $adPrincipalsToAdd)
                {
                    $addADPasswordReplicationPolicy = @{
                        Identity   = $domainControllerObject
                        DeniedList = $adPrincipalsToAdd
                    }

                    Add-ADDomainControllerPasswordReplicationPolicy @addADPasswordReplicationPolicy
                }
            }
        }
    }
}

<#
    .SYNOPSIS
        Determines if the read only domain controller account is in desired state.

    .PARAMETER DomainControllerAccountName
        Provide the name of the Read Domain Controller Account which will be created.

    .PARAMETER DomainName
        Provide the FQDN of the domain the Read Domain Controller Account is being created in.

    .PARAMETER Credential
        Specifies the credential for the account used to add the read only domain controller account.

    .PARAMETER SiteName
        Provide the name of the site you want the Read Only Domain Controller Account to be added to.

    .PARAMETER IsGlobalCatalog
        Specifies if the read only domain controller will be a Global Catalog (GC).

    .PARAMETER DelegatedAdministratorAccountName
        Specifies the user or group that is the delegated administrator of this read only domain controller account.

    .PARAMETER AllowPasswordReplicationAccountName
        Provides a list of the users, computers, and groups to add to the password replication allowed list.

    .PARAMETER DenyPasswordReplicationAccountName
        Provides a list of the users, computers, and groups to add to the password replication denied list.

    .PARAMETER InstallDns
        Specifies if the DNS Server service should be installed and configured on
        the read only domain controller. If this is not set the default value of the parameter
        InstallDns of the cmdlet Add-ADDSReadOnlyDomainControllerAccount is used.
        The parameter `InstallDns` is only used during the provisioning of a read only domain
        controller. The parameter cannot be used to install or uninstall the DNS
        server on an already provisioned read only domain controller.

        Not used in Test-TargetResource.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Test-ADReplicationSite        | ActiveDirectoryDsc.Common
            Test-Members                  | ActiveDirectoryDsc.Common
            New-InvalidOperationException | DscResource.Common
            New-ObjectNotFoundException   | DscResource.Common
#>
function Test-TargetResource
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "",
        Justification = 'Read-Only Domain Controller (RODC) Account Creation support(AllowPasswordReplicationAccountName and DenyPasswordReplicationAccountName)')]
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainControllerAccountName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DomainName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SiteName,

        [Parameter()]
        [System.Boolean]
        $IsGlobalCatalog,

        [Parameter()]
        [System.String]
        $DelegatedAdministratorAccountName,

        [Parameter()]
        [System.String[]]
        $AllowPasswordReplicationAccountName,

        [Parameter()]
        [System.String[]]
        $DenyPasswordReplicationAccountName,

        [Parameter()]
        [System.Boolean]
        $InstallDns
    )

    Write-Verbose -Message ($script:localizedData.TestingConfiguration -f $DomainControllerAccountName, $DomainName)

    if (-not (Test-ADReplicationSite -SiteName $SiteName -DomainName $DomainName -Credential $Credential))
    {
        $errorMessage = $script:localizedData.FailedToFindSite -f $SiteName, $DomainName
        New-ObjectNotFoundException -Message $errorMessage
    }

    $getTargetResourceParameters = @{
        DomainControllerAccountName   = $DomainControllerAccountName
        DomainName                    = $DomainName
        Credential                    = $Credential
        SiteName                      = $SiteName
    }

    $existingResource = Get-TargetResource @getTargetResourceParameters

    $testTargetResourceReturnValue = $existingResource.Ensure

    if ($existingResource.SiteName -ne $SiteName)
    {
        Write-Verbose -Message ($script:localizedData.WrongSite -f $existingResource.SiteName, $SiteName)

        $testTargetResourceReturnValue = $false
    }

    # Check Global Catalog Config
    if ($PSBoundParameters.ContainsKey('IsGlobalCatalog') -and $existingResource.IsGlobalCatalog -ne $IsGlobalCatalog)
    {
        if ($IsGlobalCatalog)
        {
            Write-Verbose -Message ($script:localizedData.ExpectedGlobalCatalogEnabled)
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.ExpectedGlobalCatalogDisabled)
        }

        $testTargetResourceReturnValue = $false
    }

    if ($PSBoundParameters.ContainsKey('DelegatedAdministratorAccountName') -and $existingResource.DelegatedAdministratorAccountName -ne $DelegatedAdministratorAccountName)
    {
        Write-Verbose -Message ($script:localizedData.DelegatedAdministratorAccountNameMismatch -f $existingResource.DelegatedAdministratorAccountName, $DelegatedAdministratorAccountName)

        $testTargetResourceReturnValue = $false
    }

    if ($PSBoundParameters.ContainsKey('AllowPasswordReplicationAccountName') -and
        $null -ne $existingResource.AllowPasswordReplicationAccountName)
    {
        $testMembersParameters = @{
            ExistingMembers = $existingResource.AllowPasswordReplicationAccountName
            Members         = $AllowPasswordReplicationAccountName
        }

        if (-not (Test-Members @testMembersParameters))
        {
            Write-Verbose -Message (
                $script:localizedData.AllowedSyncAccountsMismatch -f
                ($existingResource.AllowPasswordReplicationAccountName -join ';'),
                ($AllowPasswordReplicationAccountName -join ';')
            )

            $testTargetResourceReturnValue = $false
        }
    }

    if ($PSBoundParameters.ContainsKey('DenyPasswordReplicationAccountName') -and
        $null -ne $existingResource.DenyPasswordReplicationAccountName)
    {
        $testMembersParameters = @{
            ExistingMembers = $existingResource.DenyPasswordReplicationAccountName
            Members         = $DenyPasswordReplicationAccountName;
        }

        if (-not (Test-Members @testMembersParameters))
        {
            Write-Verbose -Message (
                $script:localizedData.DenySyncAccountsMismatch -f
                ($existingResource.DenyPasswordReplicationAccountName -join ';'),
                ($DenyPasswordReplicationAccountName -join ';')
            )

            $testTargetResourceReturnValue = $false
        }
    }

    return $testTargetResourceReturnValue
}

<#
    .SYNOPSIS
        Return a hashtable with members that are not present in CurrentMembers,
        and members that are present add should not be present.

    .PARAMETER DesiredMembers
        Specifies the list of desired members in the hashtable.

    .PARAMETER CurrentMembers
        Specifies the list of current members in the hashtable.

    .OUTPUTS
        Returns a hashtable with two properties. The property MembersToAdd contains the
        members as ADPrincipal objects that are not members in the collection
        provided in $CurrentMembers. The property MembersToRemove contains the
        unwanted members as ADPrincipal objects in the collection provided
        in $CurrentMembers.
#>
function Get-MembersToAddAndRemove
{
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.String[]]
        $DesiredMembers,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.String[]]
        $CurrentMembers
    )

    $principalsToRemove = foreach ($memberName in $CurrentMembers)
    {
        if ($memberName -notin $DesiredMembers)
        {
            New-Object -TypeName Microsoft.ActiveDirectory.Management.ADPrincipal -ArgumentList $memberName
        }
    }

    $principalsToAdd = foreach ($memberName in $DesiredMembers)
    {
        if ($memberName -notin $CurrentMembers)
        {
            New-Object -TypeName Microsoft.ActiveDirectory.Management.ADPrincipal -ArgumentList $memberName
        }
    }

    return @{
        MembersToAdd    = [Microsoft.ActiveDirectory.Management.ADPrincipal[]] $principalsToAdd
        MembersToRemove = [Microsoft.ActiveDirectory.Management.ADPrincipal[]] $principalsToRemove
    }
}

Export-ModuleMember -Function *-TargetResource
