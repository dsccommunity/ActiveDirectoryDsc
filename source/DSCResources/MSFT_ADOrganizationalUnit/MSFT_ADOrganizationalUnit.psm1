$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Gets the Organizational Unit (OU) from Active Directory

    .PARAMETER Name
        Specifies the name of the Organizational Unit (OU).

    .PARAMETER Path
        Specifies the X.500 path of the OrganizationalUnit (OU) or container where the new object is created.

    .PARAMETER Credential
        The credential to be used to perform the operation on Active Directory.

    .PARAMETER DomainController
        Active Directory domain controller to enact the change upon.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Get-ADCommonParameters        | ActiveDirectoryDsc.Common
            Get-ADOrganizationalUnit      | ActiveDirectory
            Assert-Module                 | DscResource.Common
            New-InvalidOperationException | DscResource.Common
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DomainController
    )

    Assert-Module -ModuleName 'ActiveDirectory'

    $commonParameters = Get-ADCommonParameters @PSBoundParameters

    Write-Verbose -Message ($script:localizedData.RetrievingOU -f $Name, $Path)

    $getADOUProperties = ('Name', 'DistinguishedName', 'Description', 'ProtectedFromAccidentalDeletion')

    try
    {
        $getADOUParameters = $commonParameters.Clone()
        $getADOUParameters.Filter = ('Name -eq "{0}"' -f $Name)
        $getADOUParameters.SearchBase = $Path
        $getADOUParameters.SearchScope = 'OneLevel'
        $getADOUParameters.Properties = $getADOUProperties
        $getADOUParameters.Remove('Identity')
        $getADOUParameters.Remove('Name')
        $getADOUParameters.Remove('Path')
        $ou = Get-ADOrganizationalUnit @getADOUParameters
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message ($script:localizedData.OUPathIsAbsent -f $Path)
        $ou = $null
    }
    catch
    {
        $errorMessage = $script:localizedData.GetResourceError -f $Name
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }

    if ($ou)
    {
        Write-Verbose -Message ($script:localizedData.OUIsPresent -f $Name)

        $targetResource = @{
            Name                            = $Name
            Path                            = $Path
            ProtectedFromAccidentalDeletion = $ou.ProtectedFromAccidentalDeletion
            Description                     = $ou.Description
            DistinguishedName               = $ou.DistinguishedName
            Ensure                          = 'Present'
        }
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.OUIsAbsent -f $Name)

        $targetResource = @{
            Name                            = $Name
            Path                            = $Path
            ProtectedFromAccidentalDeletion = $null
            Description                     = $null
            DistinguishedName               = $null
            Ensure                          = 'Absent'
        }
    }

    return $targetResource
} # end function Get-TargetResource

<#
    .SYNOPSIS
        Tests the state of the specified Organizational Unit (OU).

    .PARAMETER Name
        Specifies the name of the Organizational Unit (OU).

    .PARAMETER Path
        Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created.

    .PARAMETER Ensure
        Specifies whether the Organizational Unit (OU) should be present or absent. Default value is 'Present'.

    .PARAMETER Credential
        The credential to be used to perform the operation on Active Directory.

    .PARAMETER DomainController
        Active Directory domain controller to enact the change upon.

    .PARAMETER ProtectedFromAccidentalDeletion
        Specifies if the Organizational Unit (OU) container should be protected from deletion. Default value is $true.

    .PARAMETER Description
        Specifies the description of the Organizational Unit (OU). Default value is empty ('').

    .PARAMETER RestoreFromRecycleBin
        Try to restore the Organizational Unit (OU) from the recycle bin before creating a new one.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Compare-ResourcePropertyState | ActiveDirectoryDsc.Common
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $ProtectedFromAccidentalDeletion = $true,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Description = '',

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController
    )

    $getTargetResourceParameters = @{
        Name             = $Name
        Path             = $Path
        Credential       = $Credential
        DomainController = $DomainController
    }

    # Remove parameters that have not been specified, unless in the IgnoreParameters array
    @($getTargetResourceParameters.Keys) |
        ForEach-Object {
            if (-not $PSBoundParameters.ContainsKey($_))
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
            $ignoreProperties = @('DomainController', 'Credential', 'RestoreFromRecycleBin')
            $propertiesNotInDesiredState = (Compare-ResourcePropertyState -CurrentValues $getTargetResourceResult `
                    -DesiredValues $PSBoundParameters -IgnoreProperties $ignoreProperties `
                    -Verbose:$VerbosePreference | Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.OUInDesiredState -f $Name)
                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should not exist
            Write-Verbose ($script:localizedData.OUExistsButShouldNot -f $Name)

            $inDesiredState = $false
        }
    }
    else
    {
        # Resource does not exist
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            Write-Verbose ($script:localizedData.OUDoesNotExistButShould -f $Name)

            $inDesiredState = $false
        }
        else
        {
            # Resource should not exist
            Write-Verbose ($script:localizedData.OUDoesNotExistAndShouldNot -f $Name)

            $inDesiredState = $true
        }
    }

    return $inDesiredState
} #end function Test-TargetResource

<#
    .SYNOPSIS
        Sets the state of the Organizational Unit (OU) in Active Directory.

    .PARAMETER Name
        Specifies the name of the Organizational Unit (OU).

    .PARAMETER Path
        Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created.

    .PARAMETER Ensure
        Specifies whether the Organizational Unit (OU) should be present or absent. Default value is 'Present'.

    .PARAMETER Credential
        The credential to be used to perform the operation on Active Directory.

    .PARAMETER DomainController
        Active Directory domain controller to enact the change upon.

    .PARAMETER ProtectedFromAccidentalDeletion
        Specifies if the Organizational Unit (OU) container should be protected from deletion. Default value is $true.

    .PARAMETER Description
        Specifies the description of the Organizational Unit (OU). Default value is empty ('').

    .PARAMETER RestoreFromRecycleBin
        Try to restore the Organizational Unit (OU) from the recycle bin before creating a new one.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            New-ADOrganizationalUnit      | ActiveDirectory
            Set-ADOrganizationalUnit      | ActiveDirectory
            Remove-ADOrganizationalUnit   | ActiveDirectory
            New-InvalidOperationException | DscResource.Common
            New-ObjectNotFoundException   | DscResource.Common
            Restore-ADCommonObject        | ActiveDirectoryDsc.Common
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

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
        [ValidateNotNull()]
        [System.Boolean]
        $ProtectedFromAccidentalDeletion = $true,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Description = '',

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin
    )

    $getTargetResourceParameters = @{
        Name             = $Name
        Path             = $Path
        Credential       = $Credential
        DomainController = $DomainController
    }

    # Remove parameters that have not been specified
    @($getTargetResourceParameters.Keys) |
        ForEach-Object {
            if (-not $PSBoundParameters.ContainsKey($_))
            {
                $getTargetResourceParameters.Remove($_)
            }
        }

    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

    if ($getTargetResourceResult.Ensure -eq 'Present')
    {
        if ($Ensure -eq 'Present')
        {
            Write-Verbose ($script:localizedData.UpdatingOU -f $Name)

            $setADOrganizationalUnitParams = @{
                Identity                        = $getTargetResourceResult.DistinguishedName
                Description                     = $Description
                ProtectedFromAccidentalDeletion = $ProtectedFromAccidentalDeletion
            }

            if ($Credential)
            {
                $setADOrganizationalUnitParams['Credential'] = $Credential
            }

            if ($DomainController)
            {
                $setADOrganizationalUnitParams['Server'] = $DomainController
            }

            try
            {
                Set-ADOrganizationalUnit @setADOrganizationalUnitParams
            }
            catch
            {
                $errorMessage = $script:localizedData.SetResourceError -f $Name
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }
        }
        else
        {
            Write-Verbose ($script:localizedData.DeletingOU -f $Name)

            # Disable 'ProtectedFromAccidentalDeletion' if it is set.
            if ($getTargetResourceResult.ProtectedFromAccidentalDeletion)
            {
                $setADOrganizationalUnitParams = @{
                    Identity                        = $getTargetResourceResult.DistinguishedName
                    ProtectedFromAccidentalDeletion = $false
                }

                if ($Credential)
                {
                    $setADOrganizationalUnitParams['Credential'] = $Credential
                }

                if ($DomainController)
                {
                    $setADOrganizationalUnitParams['Server'] = $DomainController
                }

                try
                {
                    Set-ADOrganizationalUnit @setADOrganizationalUnitParams
                }
                catch
                {
                    $errorMessage = $script:localizedData.SetResourceError -f $Name
                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }

            $removeADOrganizationalUnitParams = @{
                Identity = $getTargetResourceResult.DistinguishedName
            }

            if ($Credential)
            {
                $removeADOrganizationalUnitParams['Credential'] = $Credential
            }

            if ($DomainController)
            {
                $removeADOrganizationalUnitParams['Server'] = $DomainController
            }

            try
            {
                Remove-ADOrganizationalUnit @removeADOrganizationalUnitParams
            }
            catch
            {
                $errorMessage = $script:localizedData.RemoveResourceError -f $Name
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }
        }
    }
    else
    {
        if ($Ensure -eq 'Present')
        {
            if ($RestoreFromRecycleBin)
            {
                Write-Verbose -Message ($script:localizedData.RestoringOu -f $Name)

                $restoreParams = @{
                    Identity    = $Name
                    ObjectClass = 'OrganizationalUnit'
                    ErrorAction = 'Stop'
                }

                if ($Credential)
                {
                    $restoreParams['Credential'] = $Credential
                }

                if ($DomainController)
                {
                    $restoreParams['Server'] = $DomainController
                }

                $restoreSuccessful = Restore-ADCommonObject @restoreParams
            }

            if (-not $RestoreFromRecycleBin -or ($RestoreFromRecycleBin -and -not $restoreSuccessful))
            {
                Write-Verbose ($script:localizedData.CreatingOU -f $Name)

                $newADOrganizationalUnitParams = @{
                    Name                            = $Name
                    Path                            = $Path
                    Description                     = $Description
                    ProtectedFromAccidentalDeletion = $ProtectedFromAccidentalDeletion
                }

                if ($Credential)
                {
                    $newADOrganizationalUnitParams['Credential'] = $Credential
                }

                if ($DomainController)
                {
                    $newADOrganizationalUnitParams['Server'] = $DomainController
                }

                try
                {
                    New-ADOrganizationalUnit @newADOrganizationalUnitParams
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
                {
                    $errorMessage = $script:localizedData.PathNotFoundError -f $Path
                    New-ObjectNotFoundException -Message $errorMessage
                }
                catch
                {
                    $errorMessage = $script:localizedData.NewResourceError -f $Name
                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }
} #end function Set-TargetResource

Export-ModuleMember -Function *-TargetResource
