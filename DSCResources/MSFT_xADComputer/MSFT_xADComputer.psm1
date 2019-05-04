$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath 'DscResource.LocalizationHelper'
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath 'DscResource.LocalizationHelper.psm1')

$script:dscResourcePath = Split-Path -Path $PSScriptRoot -Parent
Import-Module -Name (Join-Path -Path $script:dscResourcePath -ChildPath '\MSFT_xADCommon\MSFT_xADCommon.psm1')

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xADComputer'

<#
    A property map that maps the resource parameters to the corresponding
    Active Directory computer account object attribute.
#>
$script:computerObjectPropertyMap = @(
    @{
        ParameterName = 'ComputerName'
        PropertyName  = 'CN'
    },
    @{
        ParameterName = 'Location'
    },
    @{
        ParameterName = 'DnsHostName'
    },
    @{
        ParameterName = 'ServicePrincipalNames'
    },
    @{
        ParameterName = 'UserPrincipalName'
    },
    @{
        ParameterName = 'DisplayName'
    },
    @{
        ParameterName = 'Path'
        PropertyName  = 'DistinguishedName'
    },
    @{
        ParameterName = 'Description'
    },
    @{
        ParameterName = 'Enabled'
    },
    @{
        ParameterName = 'Manager'
        PropertyName  = 'ManagedBy'
    },
    @{
        ParameterName = 'DistinguishedName'
        ParameterType = 'Read'
        PropertyName  = 'DistinguishedName'
    },
    @{
        ParameterName = 'SID'
        ParameterType = 'Read'
    }
)

<#
    .SYNOPSIS
        Returns the current state of the Active Directory computer account.

    .PARAMETER ComputerName
         Specifies the name of the Active Directory computer account to manage.
         You can identify a computer by its distinguished name, GUID, security
         identifier (SID) or Security Accounts Manager (SAM) account name.

    .PARAMETER RequestFile
        Specifies the full path to the Offline Domain Join Request file to create.

    .PARAMETER Enabled
        DEPRECATED - DO NOT USE.

        It is a parameter in Get-TargetResource to write the deprecated message.

    .PARAMETER EnabledOnCreation
        Specifies if the computer account is created enabled or disabled.
        By default the computer account will be created using the default
        value of the cmdlet New-ADComputer.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to connect to perform the task.

        Used by Get-ADCommonParameters and is returned as a common parameter.

    .PARAMETER DomainAdministratorCredential
        Specifies the user account credentials to use to perform the task.

        Used by Get-ADCommonParameters and is returned as a common parameter.

    .PARAMETER RestoreFromRecycleBin
        Indicates whether or not the computer object should first tried to be
        restored from the recycle bin before creating a new computer object.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ComputerName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $RequestFile,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DomainController,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $EnabledOnCreation
    )

    <#
        We have the deprecated message in Get-TargetResource so that it is
        shown when both Test- and Set-TargetResource calls Get-TargetResource.
    #>
    if ($PSBoundParameters.ContainsKey('Enabled'))
    {
        Write-Warning -Message $script:localizedData.EnabledDeprecatedMessage
    }

    Assert-Module -ModuleName 'ActiveDirectory' -ImportModule

    <#
        These are properties that have no corresponding property in a
        Computer account object.
    #>
    $getTargetResourceReturnValue = @{
        Ensure                        = 'Absent'
        ComputerName                  = $null
        Location                      = $null
        DnsHostName                   = $null
        ServicePrincipalNames         = $null
        UserPrincipalName             = $null
        DisplayName                   = $null
        Path                          = $null
        Description                   = $null
        Enabled                       = $false
        Manager                       = $null
        DomainController              = $DomainController
        DomainAdministratorCredential = $DomainAdministratorCredential
        RequestFile                   = $RequestFile
        RestoreFromRecycleBin         = $RestoreFromRecycleBin
        EnabledOnCreation             = $EnabledOnCreation
        DistinguishedName             = $null
        SID                           = $null
        SamAccountName                = $null
    }

    $getADComputerResult = $null

    try
    {
        $commonParameters = Get-ADCommonParameters @PSBoundParameters

        <#
            Create an array of the Active Directory Computer object property
            names to retrieve from the Computer object.
        #>
        $computerObjectProperties = Convert-PropertyMapToObjectProperties -PropertyMap $script:computerObjectPropertyMap

        Write-Verbose -Message ($script:localizedData.RetrievingComputerAccount -f $ComputerName)

        # If the computer account is not found Get-ADComputer will throw an error.
        $getADComputerResult = Get-ADComputer @commonParameters -Properties $computerObjectProperties

        Write-Verbose -Message ($script:localizedData.ComputerAccountIsPresent -f $ComputerName)

        $getTargetResourceReturnValue['Ensure'] = 'Present'
        $getTargetResourceReturnValue['ComputerName'] = $getADComputerResult.CN
        $getTargetResourceReturnValue['Location'] = $getADComputerResult.Location
        $getTargetResourceReturnValue['DnsHostName'] = $getADComputerResult.DnsHostName
        $getTargetResourceReturnValue['ServicePrincipalNames'] = [System.String[]] $getADComputerResult.ServicePrincipalNames
        $getTargetResourceReturnValue['UserPrincipalName'] = $getADComputerResult.UserPrincipalName
        $getTargetResourceReturnValue['DisplayName'] = $getADComputerResult.DisplayName
        $getTargetResourceReturnValue['Path'] = Get-ADObjectParentDN -DN $getADComputerResult.DistinguishedName
        $getTargetResourceReturnValue['Description'] = $getADComputerResult.Description
        $getTargetResourceReturnValue['Enabled'] = $getADComputerResult.Enabled
        $getTargetResourceReturnValue['Manager'] = $getADComputerResult.ManagedBy
        $getTargetResourceReturnValue['DomainController'] = $DomainController
        $getTargetResourceReturnValue['DomainAdministratorCredential'] = $DomainAdministratorCredential
        $getTargetResourceReturnValue['RequestFile'] = $RequestFile
        $getTargetResourceReturnValue['RestoreFromRecycleBin'] = $RestoreFromRecycleBin
        $getTargetResourceReturnValue['EnabledOnCreation'] = $EnabledOnCreation
        $getTargetResourceReturnValue['DistinguishedName'] = $getADComputerResult.DistinguishedName
        $getTargetResourceReturnValue['SID'] = $getADComputerResult.SID
        $getTargetResourceReturnValue['SamAccountName'] = $getADComputerResult.SamAccountName
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message ($script:localizedData.ComputerAccountIsAbsent -f $ComputerName)
    }
    catch
    {
        $errorMessage = $script:localizedData.FailedToRetrieveComputerAccount -f $ComputerName
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }

    return $getTargetResourceReturnValue
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        # Common Name
        [Parameter(Mandatory = $true)]
        [System.String]
        $ComputerName,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $UserPrincipalName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Location,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DnsHostName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String[]]
        $ServicePrincipalNames,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Description,

        # Computer's manager specified as a Distinguished Name (DN)
        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Manager,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $RequestFile,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DomainController,

        # Ideally this should just be called 'Credential' but is here for backwards compatibility
        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $EnabledOnCreation
    )

    $targetResource = Get-TargetResource @PSBoundParameters
    $isCompliant = $true

    if ($Ensure -eq 'Absent')
    {
        if ($targetResource.Ensure -eq 'Present')
        {
            Write-Verbose -Message ($script:localizedData.ADComputerNotDesiredPropertyState -f `
                    'Ensure', $PSBoundParameters.Ensure, $targetResource.Ensure)
            $isCompliant = $false
        }
    }
    else
    {
        # Add ensure as it may not be explicitly passed and we want to enumerate it.
        $PSBoundParameters['Ensure'] = $Ensure

        foreach ($parameter in $PSBoundParameters.Keys)
        {
            if ($targetResource.ContainsKey($parameter))
            {
                # This check is required to be able to explicitly remove values with an empty string, if required
                if (([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter)) -and
                    ([System.String]::IsNullOrEmpty($targetResource.$parameter)))
                {
                    # Both values are null/empty and therefore we are compliant
                }
                elseif ($parameter -eq 'ServicePrincipalNames')
                {
                    $testMembersParams = @{
                        ExistingMembers = $targetResource.ServicePrincipalNames -as [System.String[]]
                        Members         = $ServicePrincipalNames
                    }
                    if (-not (Test-Members @testMembersParams))
                    {
                        $existingSPNs = $testMembersParams['ExistingMembers'] -join ','
                        $desiredSPNs = $ServicePrincipalNames -join ','
                        Write-Verbose -Message ($script:localizedData.ADComputerNotDesiredPropertyState -f `
                                'ServicePrincipalNames', $desiredSPNs, $existingSPNs)
                        $isCompliant = $false
                    }
                }
                elseif ($PSBoundParameters.$parameter -ne $targetResource.$parameter)
                {
                    Write-Verbose -Message ($script:localizedData.ADComputerNotDesiredPropertyState -f `
                            $parameter, $PSBoundParameters.$parameter, $targetResource.$parameter)
                    $isCompliant = $false
                }
            }
        } #end foreach PSBoundParameter
    }

    if ($isCompliant)
    {
        Write-Verbose -Message ($script:localizedData.ADComputerInDesiredState -f $ComputerName)
        return $true
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ADComputerNotInDesiredState -f $ComputerName)
        return $false
    }

} #end function Test-TargetResource


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        # Common Name
        [Parameter(Mandatory = $true)]
        [System.String]
        $ComputerName,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $UserPrincipalName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Location,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DnsHostName,

        [Parameter()]
        [ValidateNotNull()]
        [System.String[]]
        $ServicePrincipalNames,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Description,

        # Computer's manager specified as a Distinguished Name (DN)
        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $Manager,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $RequestFile,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $Enabled,

        [Parameter()]
        [ValidateNotNull()]
        [System.String]
        $DomainController,

        # Ideally this should just be called 'Credential' but is here for backwards compatibility
        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $DomainAdministratorCredential,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $RestoreFromRecycleBin,

        [Parameter()]
        [ValidateNotNull()]
        [System.Boolean]
        $EnabledOnCreation
    )

    $targetResource = Get-TargetResource @PSBoundParameters

    ## Add ensure as they may not be explicitly passed and we want to enumerate them
    $PSBoundParameters['Ensure'] = $Ensure

    if ($Ensure -eq 'Present')
    {
        if ($targetResource.Ensure -eq 'Absent')
        {
            # Try to restore account if it exists
            if ($RestoreFromRecycleBin)
            {
                Write-Verbose -Message ($script:localizedData.RestoringADComputer -f $ComputerName)
                $restoreParams = Get-ADCommonParameters @PSBoundParameters
                $restorationSuccessful = Restore-ADCommonObject @restoreParams -ObjectClass Computer -ErrorAction Stop
            }

            <#
                Computer does not exist and needs creating
                or account not present in recycle bin
            #>
            if (-not $RestoreFromRecycleBin -or ($RestoreFromRecycleBin -and -not $restorationSuccessful))
            {
                if ($RequestFile)
                {
                    # Use DJOIN to create the computer account as well as the ODJ Request file.
                    Write-Verbose -Message ($script:localizedData.ODJRequestStartMessage -f `
                            $DomainName, $ComputerName, $RequestFile)

                    # This should only be performed on a Domain Member, so detect the Domain Name.
                    $DomainName = Get-DomainName
                    $DJoinParameters = @(
                        '/PROVISION'
                        '/DOMAIN', $DomainName
                        '/MACHINE', $ComputerName )
                    if ($PSBoundParameters.ContainsKey('Path'))
                    {
                        $DJoinParameters += @( '/MACHINEOU', $Path )
                    } # if

                    if ($PSBoundParameters.ContainsKey('DomainController'))
                    {
                        $DJoinParameters += @( '/DCNAME', $DomainController )
                    } # if

                    $DJoinParameters += @( '/SAVEFILE', $RequestFile )
                    $Result = & djoin.exe @DjoinParameters

                    if ($LASTEXITCODE -ne 0)
                    {
                        $errorId = 'ODJRequestError'
                        $errorMessage = $($script:localizedData.ODJRequestError `
                                -f $LASTEXITCODE, $Result)
                        ThrowInvalidOperationError -ErrorId $errorId -ErrorMessage $errorMessage
                    } # if

                    Write-Verbose -Message ($script:localizedData.ODJRequestCompleteMessage -f `
                            $DomainName, $ComputerName, $RequestFile)
                }
                else
                {
                    # Create the computer account using New-ADComputer
                    $newADComputerParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter
                    if ($PSBoundParameters.ContainsKey('Path'))
                    {
                        Write-Verbose -Message ($script:localizedData.UpdatingADComputerProperty -f 'Path', $Path)
                        $newADComputerParams['Path'] = $Path
                    }
                    Write-Verbose -Message ($script:localizedData.AddingADComputer -f $ComputerName)
                    New-ADComputer @newADComputerParams
                } # if
            }
            else
            {
                ## Create the computer account using New-ADComputer
                $newADComputerParams = Get-ADCommonParameters @PSBoundParameters -UseNameParameter
                if ($PSBoundParameters.ContainsKey('Path'))
                {
                    Write-Verbose -Message ($script:localizedData.UpdatingADComputerProperty -f 'Path', $Path)
                    $newADComputerParams['Path'] = $Path
                }

                <#
                    If CreateDisabled is set to $true, or Enabled is set to $false,
                    then create the computer account disabled.
                    If not then create the computer account enabled.
                #>
                if (
                    ($CreateDisabled -and -not $PSBoundParameters.ContainsKey('Enabled')) `
                        -or ($PSBoundParameters.ContainsKey('Enabled') -and -not $Enabled)
                )
                {
                    Write-Verbose -Message ($script:localizedData.AddingADComputerAsDisabled -f $ComputerName)
                    $newADComputerParams['Enabled'] = $false
                }
                else
                {
                    Write-Verbose -Message ($script:localizedData.AddingADComputer -f $ComputerName)
                    $newADComputerParams['Enabled'] = $true
                }

                New-ADComputer @newADComputerParams
            } # if
            ## Now retrieve the newly created computer
            $targetResource = Get-TargetResource @PSBoundParameters
        }

        $setADComputerParams = Get-ADCommonParameters @PSBoundParameters
        $replaceComputerProperties = @{ }
        $removeComputerProperties = @{ }
        foreach ($parameter in $PSBoundParameters.Keys)
        {
            # Only check/action properties specified/declared parameters that match one of the function's
            # parameters. This will ignore common parameters such as -Verbose etc.
            if ($targetResource.ContainsKey($parameter))
            {
                if ($parameter -eq 'Path' -and ($PSBoundParameters.Path -ne $targetResource.Path))
                {
                    # Cannot move computers by updating the DistinguishedName property
                    $commonParameters = Get-ADCommonParameters @PSBoundParameters
                    # Using the SamAccountName for identity with Move-ADObject does not work, use the DN instead
                    $commonParameters['Identity'] = $targetResource.DistinguishedName
                    Write-Verbose -Message ($script:localizedData.MovingADComputer -f `
                            $targetResource.Path, $PSBoundParameters.Path)
                    Move-ADObject @commonParameters -TargetPath $PSBoundParameters.Path
                }
                elseif ($parameter -eq 'ServicePrincipalNames')
                {
                    Write-Verbose -Message ($script:localizedData.UpdatingADComputerProperty -f `
                            'ServicePrincipalNames', ($ServicePrincipalNames -join ','))
                    $replaceComputerProperties['ServicePrincipalName'] = $ServicePrincipalNames
                }
                elseif ($parameter -eq 'Enabled' -and ($PSBoundParameters.$parameter -ne $targetResource.$parameter))
                {
                    Write-Verbose -Message ($script:localizedData.UpdatingADComputerProperty -f `
                            $parameter, $PSBoundParameters.$parameter)

                    <#
                        The Enabled property cannot be set as a hash table value in the
                        Remove or Replace parameter of the Set-ADComputer cmdlet. So
                        adding it as a parameter to the Set-ADComputer cmdlet.
                    #>
                    $setADComputerParams['Enabled'] = $PSBoundParameters.$parameter
                }
                elseif ($PSBoundParameters.$parameter -ne $targetResource.$parameter)
                {
                    # Find the associated AD property
                    $adProperty = $script:computerObjectPropertyMap | Where-Object { $_.Parameter -eq $parameter }

                    if ([System.String]::IsNullOrEmpty($adProperty))
                    {
                        # We can't do anything with an empty AD property!
                    }
                    elseif ([System.String]::IsNullOrEmpty($PSBoundParameters.$parameter))
                    {
                        # We are removing properties
                        # Only remove if the existing value in not null or empty
                        if (-not ([System.String]::IsNullOrEmpty($targetResource.$parameter)))
                        {
                            Write-Verbose -Message ($script:localizedData.RemovingADComputerProperty -f `
                                    $parameter, $PSBoundParameters.$parameter)
                            if ($adProperty.UseCmdletParameter -eq $true)
                            {
                                # We need to pass the parameter explicitly to Set-ADComputer, not via -Remove
                                $setADComputerParams[$adProperty.Parameter] = $PSBoundParameters.$parameter
                            }
                            elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty))
                            {
                                $removeComputerProperties[$adProperty.Parameter] = $targetResource.$parameter
                            }
                            else
                            {
                                $removeComputerProperties[$adProperty.ADProperty] = $targetResource.$parameter
                            }
                        }
                    } #end if remove existing value
                    else
                    {
                        # We are replacing the existing value
                        Write-Verbose -Message ($script:localizedData.UpdatingADComputerProperty -f `
                                $parameter, $PSBoundParameters.$parameter)
                        if ($adProperty.UseCmdletParameter -eq $true)
                        {
                            # We need to pass the parameter explicitly to Set-ADComputer, not via -Replace
                            $setADComputerParams[$adProperty.Parameter] = $PSBoundParameters.$parameter
                        }
                        elseif ([System.String]::IsNullOrEmpty($adProperty.ADProperty))
                        {
                            $replaceComputerProperties[$adProperty.Parameter] = $PSBoundParameters.$parameter
                        }
                        else
                        {
                            $replaceComputerProperties[$adProperty.ADProperty] = $PSBoundParameters.$parameter
                        }
                    } #end if replace existing value
                }

            } #end if TargetResource parameter
        } #end foreach PSBoundParameter

        <#
            Set-ADComputer is only called if we have something to change, or
            $setADComputerParams contains more than one value (ignoring parameter
            'Identity' by itself).
        #>
        if ($replaceComputerProperties.Count -gt 0 -or $removeComputerProperties.Count -gt 0 -or $setADComputerParams.Count -gt 1)
        {
            ## Only pass -Remove and/or -Replace if we have something to set/change
            if ($replaceComputerProperties.Count -gt 0)
            {
                $setADComputerParams['Replace'] = $replaceComputerProperties
            }
            if ($removeComputerProperties.Count -gt 0)
            {
                $setADComputerParams['Remove'] = $removeComputerProperties
            }

            Write-Verbose -Message ($script:localizedData.UpdatingADComputer -f $ComputerName)
            Set-DscADComputer -SetADComputerParameters $setADComputerParams
        }
    }
    elseif (($Ensure -eq 'Absent') -and ($targetResource.Ensure -eq 'Present'))
    {
        # User exists and needs removing
        Write-Verbose ($script:localizedData.RemovingADComputer -f $ComputerName)
        $commonParameters = Get-ADCommonParameters @PSBoundParameters
        [ref] $null = Remove-ADComputer @commonParameters -Confirm:$false
    }

} #end function Set-TargetResource

<#
    .SYNOPSIS
        This is a wrapper for Set-ADComputer. This is needed because of
        how Pester is unable to handle mocking this cmdlet.

    .PARAMETER SetADComputerParameters
        A hash table containing all parameters that will be pass trough to
        Set-ADComputer.
#>
function Set-DscADComputer
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $SetADComputerParameters
    )

    [ref] $null = Set-ADComputer @SetADComputerParameters
}

Export-ModuleMember -Function *-TargetResource
