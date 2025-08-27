$resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$modulesFolderPath = Join-Path -Path $resourceModulePath -ChildPath 'Modules'

$aDCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'ActiveDirectoryDsc.Common'
Import-Module -Name $aDCommonModulePath

$dscResourceCommonModulePath = Join-Path -Path $modulesFolderPath -ChildPath 'DscResource.Common'
Import-Module -Name $dscResourceCommonModulePath

$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

<#
    .SYNOPSIS
        Returns the current state of an Active Directory fine-grained password
        policy.

    .PARAMETER Name
        Specifies an Active Directory fine-grained password policy object name.

    .PARAMETER Precedence
        Specifies a value that defines the precedence of a fine-grained password policy among all fine-grained password
        policies.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to connect to.

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .NOTES
        Used Functions:
            Name                                   | Module
            ---------------------------------------|--------------------------
            Get-ADFineGrainedPasswordPolicy        | ActiveDirectory
            Get-ADFineGrainedPasswordPolicySubject | ActiveDirectory
            Assert-Module                          | DscResource.Common
            New-InvalidOperationException          | DscResource.Common
            Get-ADCommonParameters                 | ActiveDirectoryDsc.Common
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
        [System.UInt32]
        $Precedence,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    Assert-Module -ModuleName 'ActiveDirectory'

    [HashTable] $parameters = $PSBoundParameters

    $getADFineGrainedPasswordPolicyParameters = Get-ADCommonParameters @parameters
    $getADFineGrainedPasswordPolicyParameters['Properties'] = @(
        'ProtectedFromAccidentalDeletion'
        'DisplayName'
        'Description'
    )

    Write-Verbose -Message ($script:localizedData.QueryingPasswordPolicy -f $Name)

    try
    {
        $policy = Get-ADFineGrainedPasswordPolicy @getADFineGrainedPasswordPolicyParameters
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
    {
        Write-Verbose -Message ($script:localizedData.PasswordPolicyNotFound -f $Name)
        $policy = $null
    }
    catch
    {
        $errorMessage = $script:localizedData.RetrievePasswordPolicyError -f $Name
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }

    if ($policy)
    {
        $getADFineGrainedPasswordPolicySubjectParameters = Get-ADCommonParameters @parameters

        try
        {
            [String[]] $policySubjects = (Get-ADFineGrainedPasswordPolicySubject `
                    @getADFineGrainedPasswordPolicySubjectParameters).Name
        }
        catch
        {
            $errorMessage = $script:localizedData.RetrievePasswordPolicySubjectError -f $Name
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        $targetResource = @{
            Name                            = $Name
            DisplayName                     = $policy.DisplayName
            Description                     = $policy.Description
            ComplexityEnabled               = $policy.ComplexityEnabled
            LockoutDuration                 = $policy.LockoutDuration
            LockoutObservationWindow        = $policy.LockoutObservationWindow
            LockoutThreshold                = $policy.LockoutThreshold
            MinPasswordAge                  = $policy.MinPasswordAge
            MaxPasswordAge                  = $policy.MaxPasswordAge
            MinPasswordLength               = $policy.MinPasswordLength
            PasswordHistoryCount            = $policy.PasswordHistoryCount
            ReversibleEncryptionEnabled     = $policy.ReversibleEncryptionEnabled
            Precedence                      = $policy.Precedence
            ProtectedFromAccidentalDeletion = $policy.ProtectedFromAccidentalDeletion
            Ensure                          = 'Present'
            Subjects                        = $policySubjects
        }
    }
    else
    {
        $targetResource = @{
            Name                            = $Name
            DisplayName                     = $null
            Description                     = $null
            ComplexityEnabled               = $null
            LockoutDuration                 = $null
            LockoutObservationWindow        = $null
            LockoutThreshold                = $null
            MinPasswordAge                  = $null
            MaxPasswordAge                  = $null
            MinPasswordLength               = $null
            PasswordHistoryCount            = $null
            ReversibleEncryptionEnabled     = $null
            Precedence                      = $null
            ProtectedFromAccidentalDeletion = $null
            Ensure                          = 'Absent'
            Subjects                        = @()
        }
    }

    return $targetResource
} #end Get-TargetResource

<#
    .SYNOPSIS
        Determines if the Active Directory fine-grained password policy is in
        the desired state

    .PARAMETER Name
        Specifies an Active Directory fine-grained password policy object name.

    .PARAMETER Precedence
        Specifies a value that defines the precedence of a fine-grained password policy among all fine-grained password
        policies.

    .PARAMETER DisplayName
        Specifies the display name of the object.

    .PARAMETER Description
        Specifies the description of the object.

    .PARAMETER Subjects
        Specifies the ADPrincipal names the policy is to be applied to, overwrites all existing.

    .PARAMETER Ensure
        Specifies whether the fine grained password policy should be present or absent. Default value is 'Present'.

    .PARAMETER ComplexityEnabled
        Specifies whether password complexity is enabled for the password policy.

    .PARAMETER LockoutDuration
        Specifies the length of time that an account is locked after the number of failed login attempts exceeds the
        lockout threshold. The lockout duration must be greater than or equal to the lockout observation time for a
        password policy. The value must be a string representation of a TimeSpan value.

    .PARAMETER LockoutObservationWindow
        Specifies the maximum time interval between two unsuccessful login attempts before the number of unsuccessful
        login attempts is reset to 0. The lockout observation window must be smaller than or equal to the lockout
        duration for a password policy. The value must be a string representation of a TimeSpan value.

    .PARAMETER LockoutThreshold
        Specifies the number of unsuccessful login attempts that are permitted before an account is locked out.

    .PARAMETER MinPasswordAge
        Specifies the minimum length of time before you can change a password. The value must be a string
        representation of a TimeSpan value.

    .PARAMETER MaxPasswordAge
        Specifies the maximum length of time that you can have the same password. The value must be a string
        representation of a TimeSpan value.

    .PARAMETER MinPasswordLength
        Specifies the minimum number of characters that a password must contain.

    .PARAMETER PasswordHistoryCount
        Specifies the number of previous passwords to save.

    .PARAMETER ReversibleEncryptionEnabled
        Specifies whether the directory must store passwords using reversible encryption.

    .PARAMETER ProtectedFromAccidentalDeletion
        Specifies whether to prevent the object from being deleted.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to connect to.

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .NOTES
        Used Functions:
            Name                          | Module
            ------------------------------|--------------------------
            Compare-ResourcePropertyState | ActiveDirectoryDsc.Common
#>
function Test-TargetResource
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', MessageId = 'MinPasswordAge', Justification = 'Contains "Password" in name but is a TimeSpan string, not credential material.')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', MessageId = 'MaxPasswordAge', Justification = 'Contains "Password" in name but is a TimeSpan string, not credential material.')]
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.UInt32]
        $Precedence,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $Subjects,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [System.Boolean]
        $ComplexityEnabled,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $LockoutDuration,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $LockoutObservationWindow,

        [Parameter()]
        [System.UInt32]
        $LockoutThreshold,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $MinPasswordAge,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $MaxPasswordAge,

        [Parameter()]
        [System.UInt32]
        $MinPasswordLength,

        [Parameter()]
        [System.UInt32]
        $PasswordHistoryCount,

        [Parameter()]
        [System.Boolean]
        $ReversibleEncryptionEnabled,

        [Parameter()]
        [System.Boolean]
        $ProtectedFromAccidentalDeletion,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    [HashTable] $parameters = $PSBoundParameters

    # Build parameters needed to get resource properties
    $getTargetResourceParameters = @{
        Name             = $Name
        Precedence       = $Precedence
        DomainController = $DomainController
        Credential       = $Credential
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
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $getTargetResourceResult -DesiredValues $parameters `
                    -IgnoreProperties 'Name', 'Identity', 'Credential', 'DomainController' |
                    Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.PasswordPolicyInDesiredState -f $Name)
                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should not exist
            Write-Verbose -Message ($script:localizedData.PasswordPolicyExistsButShouldNot -f $Name)
            $inDesiredState = $false
        }
    }
    else
    {
        # Resource does not exist
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            Write-Verbose -Message ($script:localizedData.PasswordPolicyDoesNotExistButShould -f $Name)
            $inDesiredState = $false
        }
        else
        {
            # Resource should not exist
            $inDesiredState = $true
        }
    }

    if ($inDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.PasswordPolicyInDesiredState -f $Name)
        return $true
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.PasswordPolicyNotInDesiredState -f $Name)
        return $false
    }
} #end Test-TargetResource

<#
    .SYNOPSIS
        Modifies the Active Directory fine-grained password policy.

    .PARAMETER Name
        Specifies an Active Directory fine-grained password policy object name.

    .PARAMETER Precedence
        Specifies a value that defines the precedence of a fine-grained password policy among all fine-grained password
        policies.

    .PARAMETER DisplayName
        Specifies the display name of the object.

    .PARAMETER Description
        Specifies the description of the object.

    .PARAMETER Subjects
        Specifies the ADPrincipal names the policy is to be applied to, overwrites all existing.

    .PARAMETER Ensure
        Specifies whether the fine grained password policy should be present or absent. Default value is 'Present'.

    .PARAMETER ComplexityEnabled
        Specifies whether password complexity is enabled for the password policy.

    .PARAMETER LockoutDuration
        Specifies the length of time that an account is locked after the number of failed login attempts exceeds the
        lockout threshold. The lockout duration must be greater than or equal to the lockout observation time for a
        password policy. The value must be a string representation of a TimeSpan value.

    .PARAMETER LockoutObservationWindow
        Specifies the maximum time interval between two unsuccessful login attempts before the number of unsuccessful
        login attempts is reset to 0. The lockout observation window must be smaller than or equal to the lockout
        duration for a password policy. The value must be a string representation of a TimeSpan value.

    .PARAMETER LockoutThreshold
        Specifies the number of unsuccessful login attempts that are permitted before an account is locked out.

    .PARAMETER MinPasswordAge
        Specifies the minimum length of time before you can change a password. The value must be a string
        representation of a TimeSpan value.

    .PARAMETER MaxPasswordAge
        Specifies the maximum length of time that you can have the same password. The value must be a string
        representation of a TimeSpan value.

    .PARAMETER MinPasswordLength
        Specifies the minimum number of characters that a password must contain.

    .PARAMETER PasswordHistoryCount
        Specifies the number of previous passwords to save.

    .PARAMETER ReversibleEncryptionEnabled
        Specifies whether the directory must store passwords using reversible encryption.

    .PARAMETER ProtectedFromAccidentalDeletion
        Specifies whether to prevent the object from being deleted.

    .PARAMETER DomainController
        Specifies the Active Directory Domain Services instance to connect to.

    .PARAMETER Credential
        Specifies the user account credentials to use to perform this task.

    .NOTES
        Used Functions:
            Name                                      | Module
            ------------------------------------------|--------------------------
            New-ADFineGrainedPasswordPolicy           | ActiveDirectory
            Set-ADFineGrainedPasswordPolicy           | ActiveDirectory
            Remove-ADFineGrainedPasswordPolicy        | ActiveDirectory
            Add-ADFineGrainedPasswordPolicySubject    | ActiveDirectory
            Remove-ADFineGrainedPasswordPolicySubject | ActiveDirectory
            New-InvalidOperationException             | DscResource.Common
            Get-ADCommonParameters                    | ActiveDirectoryDsc.Common
            Compare-ResourcePropertyState             | ActiveDirectoryDsc.Common
#>
function Set-TargetResource
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', MessageId = 'MinPasswordAge', Justification = 'Contains "Password" in name but is a TimeSpan string, not credential material.')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', MessageId = 'MaxPasswordAge', Justification = 'Contains "Password" in name but is a TimeSpan string, not credential material.')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.UInt32]
        $Precedence,

        [Parameter()]
        [System.String]
        $DisplayName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $Subjects,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [System.Boolean]
        $ComplexityEnabled,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $LockoutDuration,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $LockoutObservationWindow,

        [Parameter()]
        [System.UInt32]
        $LockoutThreshold,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $MinPasswordAge,

        [Parameter()]
        [ValidateScript( {
                ([ValidateRange(0, 10675199)]$valueInDays = [TimeSpan]::Parse($_).TotalDays); $?
            })]
        [System.String]
        $MaxPasswordAge,

        [Parameter()]
        [System.UInt32]
        $MinPasswordLength,

        [Parameter()]
        [System.UInt32]
        $PasswordHistoryCount,

        [Parameter()]
        [System.Boolean]
        $ReversibleEncryptionEnabled,

        [Parameter()]
        [System.Boolean]
        $ProtectedFromAccidentalDeletion,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainController,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    [HashTable] $parameters = $PSBoundParameters
    $parameters.Remove('Ensure')

    $getTargetResourceParameters = @{
        Name             = $Name
        Precedence       = $Precedence
        DomainController = $DomainController
        Credential       = $Credential
    }

    @($getTargetResourceParameters.Keys) |
        ForEach-Object {
            if (-not $parameters.ContainsKey($_))
            {
                $getTargetResourceParameters.Remove($_)
            }
        }

    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

    $passwordPolicyParameters = Get-ADCommonParameters @parameters

    if ($Ensure -eq 'Present')
    {
        # Resource should be present and set correctly
        if ($getTargetResourceResult.Ensure -eq 'Present')
        {
            # Resource exists and should be in desired state
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $getTargetResourceResult -DesiredValues $parameters `
                    -IgnoreProperties 'Name', 'Identity', 'Credential', 'DomainController' |
                    Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                # Resource is present not in desired state
                $setPasswordPolicyParameters = $passwordPolicyParameters.Clone()
                $setPasswordPolicyRequired = $false

                Write-Verbose -Message ($script:localizedData.PasswordPolicyNotInDesiredState -f $Name)

                # Build parameters needed to set resource properties
                foreach ($property in $propertiesNotInDesiredState)
                {
                    if ($property.ParameterName -eq 'Subjects')
                    {
                        # Add/Remove required Policy Subjects
                        if (-not [System.String]::IsNullOrEmpty($property.Actual) -and
                            -not [System.String]::IsNullOrEmpty($property.Expected))
                        {
                            $compareResult = Compare-Object -ReferenceObject $property.Actual `
                                -DifferenceObject $property.Expected

                            $subjectsToAdd = ($compareResult |
                                    Where-Object -Property SideIndicator -eq '=>').InputObject
                            $subjectsToRemove = ($compareResult |
                                    Where-Object -Property SideIndicator -eq '<=').InputObject
                        }
                        elseif ([System.String]::IsNullOrEmpty($property.Expected))
                        {
                            $subjectsToRemove = $property.Actual
                            $subjectsToAdd = $null
                        }
                        else
                        {
                            $subjectsToAdd = $property.Expected
                            $subjectsToRemove = $null
                        }

                        if (-not [System.String]::IsNullOrEmpty($subjectsToAdd))
                        {
                            Write-Verbose -Message ($script:localizedData.AddingPasswordPolicySubjects -f
                                $Name, $($subjectsToAdd.Count))

                            try
                            {
                                Add-ADFineGrainedPasswordPolicySubject @passwordPolicyParameters `
                                    -Subjects $subjectsToAdd
                            }
                            catch
                            {
                                $errorMessage = $script:localizedData.AddingPasswordPolicySubjectsError -f $Name
                                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                            }
                        }

                        if (-not [System.String]::IsNullOrEmpty($subjectsToRemove))
                        {
                            Write-Verbose -Message ($script:localizedData.RemovingPasswordPolicySubjects -f
                                $Name, $($subjectsToRemove.Count))
                            try
                            {
                                Remove-ADFineGrainedPasswordPolicySubject @passwordPolicyParameters `
                                    -Subjects $subjectsToRemove -Confirm:$false
                            }
                            catch
                            {
                                $errorMessage = $script:localizedData.RemovingPasswordPolicySubjectsError -f $Name
                                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                            }
                        }
                    }
                    else
                    {
                        $setPasswordPolicyParameters[$property.ParameterName] = $property.Expected

                        Write-Verbose -Message ($script:localizedData.SettingPasswordPolicyValue -f
                            $Name, $property.ParameterName, $property.Expected)

                        $setPasswordPolicyRequired = $true
                    }
                }

                # Update the password policy if needed
                if ($setPasswordPolicyRequired)
                {
                    try
                    {
                        Set-ADFineGrainedPasswordPolicy @setPasswordPolicyParameters
                    }
                    catch
                    {
                        $errorMessage = $script:localizedData.SettingPasswordPolicyError -f $Name
                        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                    }
                }
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.PasswordPolicyInDesiredState -f $Name)
            }
        }
        else
        {
            # Resource should exist

            Write-Verbose -Message ($script:localizedData.PasswordPolicyDoesNotExistButShould -f $Name)

            Write-Verbose -Message ($script:localizedData.CreatingPasswordPolicy -f $Name)

            # Build parameters needed to create resource properties
            $createSubjectsRequired = $false
            $newPasswordPolicyParameters = $passwordPolicyParameters.Clone()
            $newPasswordPolicyParameters.Remove('Identity')

            foreach ($property in $parameters.keys)
            {
                if ($property -eq 'Subjects')
                {
                    $createSubjectsRequired = $true
                }
                else
                {
                    $newPasswordPolicyParameters[$property] = $parameters[$property]
                }
            }

            try
            {
                New-ADFineGrainedPasswordPolicy @newPasswordPolicyParameters
            }
            catch
            {
                $errorMessage = $script:localizedData.AddingPasswordPolicyError -f $Name
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }

            if ($createSubjectsRequired)
            {
                try
                {
                    Add-ADFineGrainedPasswordPolicySubject @passwordPolicyParameters  -Subjects $Subjects
                }
                catch
                {
                    $errorMessage = $script:localizedData.AddingPasswordPolicySubjectsError -f $Name
                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }
        }
    }
    else
    {
        # Resource should not exist

        if ($getTargetResourceResult.Ensure -eq 'Present')
        {
            # Resource exists but shouldn't

            Write-Verbose -Message ($script:localizedData.PasswordPolicyExistsButShouldNot -f $Name)

            if ($getTargetResourceResult.ProtectedFromAccidentalDeletion)
            {
                Write-Verbose -Message ($script:localizedData.RemoveDeletionProtection -f $Name)

                try
                {
                    Set-ADFineGrainedPasswordPolicy @passwordPolicyParameters  `
                        -ProtectedFromAccidentalDeletion $false
                }
                catch
                {
                    $errorMessage = $script:localizedData.RemovingDeletionProtectionError -f $Name
                    New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
                }
            }

            Write-Verbose -Message ($script:localizedData.RemovingPasswordPolicy -f $Name)

            try
            {
                Remove-ADFineGrainedPasswordPolicy @passwordPolicyParameters
            }
            catch
            {
                $errorMessage = $script:localizedData.RemovePasswordPolicyError -f $Name
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }
        }
        else
        {
            # Resource should not and does not exist

            Write-Verbose -Message ($script:localizedData.PasswordPolicyInDesiredState -f $Name)
        }
    }
} #end Set-TargetResource

Export-ModuleMember -Function *-TargetResource
