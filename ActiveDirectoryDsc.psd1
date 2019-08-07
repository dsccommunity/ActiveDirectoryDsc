@{
# Version number of this module.
moduleVersion = '4.0.0.0'

# ID used to uniquely identify this module
GUID = '9FECD4F6-8F02-4707-99B3-539E940E9FF5'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) 2019 Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = 'The ActiveDirectoryDsc module contains DSC resources for deployment and configuration of Active Directory.

These DSC resources allow you to configure new domains, child domains, and high availability domain controllers, establish cross-domain trusts and manage users, groups and OUs.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Nested modules to load when this module is imported.
NestedModules = 'Modules\ActiveDirectoryDsc.Common\ActiveDirectoryDsc.Common.psm1'

# Functions to export from this module
FunctionsToExport = @(
  # Exported so that WaitForADDomain can use this function in a separate scope.
  'Find-DomainController'
)

# Cmdlets to export from this module
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module
AliasesToExport = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('DesiredStateConfiguration', 'DSC', 'DSCResourceKit', 'DSCResource')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/PowerShell/ActiveDirectoryDsc/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/PowerShell/ActiveDirectoryDsc'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '- Changes to ActiveDirectoryDsc
  - BREAKING CHANGE: ADRecycleBin is replaced by the new resource ADOptionalFeature
    ([issue 162](https://github.com/PowerShell/ActiveDirectoryDsc/issues/162)).
  - New resource ADOptionalFeature ([issue 162](https://github.com/PowerShell/ActiveDirectoryDsc/issues/162)).
  - BREAKING CHANGE: Renamed the xActiveDirectory to ActiveDirectoryDsc
    and removed the "x" from all resource names ([issue 312](https://github.com/PowerShell/ActiveDirectoryDsc/issues/312)).
  - The helper function `Find-DomainController` is exported in the module
    manifest. When running `Import-Module -Name ActiveDirectoryDsc` the
    module will also import the nested module ActiveDirectoryDsc.Common.
    It is exported so that the resource WaitForADDomain can reuse code
    when running a background job to search for a domain controller.
  - Module manifest has been updated to optimize module auto-discovery
    according to the article [*PowerShell module authoring considerations*](https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/powershell/module-authoring-considerations)
    ([issue 463](https://github.com/PowerShell/ActiveDirectoryDsc/issues/463)).
  - Added a Requirements section to every DSC resource README with the
    bullet point stating "Target machine must be running Windows Server
    2008 R2 or later" ([issue 399](https://github.com/PowerShell/ActiveDirectoryDsc/issues/399)).
  - Added "about_\<DSCResource\>.help.txt" file to all resources
    ([issue 404](https://github.com/PowerShell/ActiveDirectoryDsc/issues/404)).
  - Fixed an issue that the helper function `Add-ADCommonGroupMember` was
    not outputting the correct group name in a verbose message and in an
    error message.
  - Style guideline cleanup.
    - Cleaned up some minor style violations in the code.
    - All localized strings in the resources now has a string ID suffix
      ([issue 419](https://github.com/PowerShell/ActiveDirectoryDsc/issues/419)).
    - All schema properties description now ends with full stop (.)
      ([issue 420](https://github.com/PowerShell/ActiveDirectoryDsc/issues/420)).
    - Updated all types in the resources schema to use PascalCase.
  - Updated all resource read-only parameters to start the description
    with "Returns..." so it is more clear that the property cannot be
    assigned a value.
  - The default value on resource parameters are now reflected in the parameter
    descriptions in the schema.mof (so that Wiki will be updated)
    ([issue 426](https://github.com/PowerShell/ActiveDirectoryDsc/issues/426)).
  - Removed unnecessary Script Analyzer rule overrides from tests.
  - Added new helper functions in xActiveDirectory.Common.
    - New-CimCredentialInstance
    - Add-TypeAssembly
    - New-ADDirectoryContext
  - Changes to ActiveDirectoryDsc.Common:
    - Removed unused parameter `ModuleName` from `Assert-MemberParameters`
      function.
    - Removed unused parameter `ModuleName` from `ConvertTo-DeploymentForestMode`
      function.
    - Removed unused parameter `ModuleName` from `ConvertTo-DeploymentDomainMode`
      function.
    - Added function help ([issue 321](https://github.com/PowerShell/ActiveDirectoryDsc/issues/321)).
    - Removed the helper function `ThrowInvalidOperationError` and
      `ThrowInvalidArgumentError` in favor of the
      [new helper functions for localization](https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.mdhelper-functions-for-localization)
      ([issue 316](https://github.com/PowerShell/ActiveDirectoryDsc/issues/316),
      [issue 317](https://github.com/PowerShell/ActiveDirectoryDsc/issues/317)).
    - Removed the alias `DomainAdministratorCredential` from the parameter
      `Credential` in the function `Restore-ADCommonObject`
    - Removed the alias `DomainAdministratorCredential` from the parameter
      `Credential` in the function `Get-ADCommonParameters`
    - Added function `Find-DomainController`.
    - Added function `Get-CurrentUser` (moved from the resource ADKDSKey).
    - Refactor `Remove-DuplicateMembers` and added more unit tests
      ([issue 443](https://github.com/PowerShell/ActiveDirectoryDsc/issues/443)).
    - Minor cleanup in `Test-Members` because of the improved `Remove-DuplicateMembers`.
    - Minor cleanup in `Assert-MemberParameters` because of the improved `Remove-DuplicateMembers`.
  - Updated all the examples files to be prefixed with the resource
    name so they are more easily discovered in PowerShell Gallery and
    Azure Automation ([issue 416](https://github.com/PowerShell/ActiveDirectoryDsc/issues/416)).
  - Fix examples that had duplicate guid that would have prevented them
    to be published.
  - Integration tests are now correctly evaluates the value from `Test-DscConfiguration`
    ([issue 434](https://github.com/PowerShell/ActiveDirectoryDsc/issues/434)).
  - Update all tests to use `| Should -BeTrue` and `| Should -BeFalse"`.
- Changes to ADManagedServiceAccount
  - Added a requirement to README stating "Group Managed Service Accounts
    need at least one Windows Server 2012 Domain Controller"
    ([issue 399](https://github.com/PowerShell/ActiveDirectoryDsc/issues/399)).
  - Using `$PSBoundParameters.Remove()` returns a `[System.Boolean]` to
    indicate of the removal was done or not. That returned value has been
    suppressed ([issue 466](https://github.com/PowerShell/ActiveDirectoryDsc/issues/466)).
- Changes to ADComputer
  - BREAKING CHANGE: The previously made obsolete parameter `Enabled` has
    been removed and is now a read-only property. See resource documentation
    how to enforce the `Enabled` property.
  - BREAKING CHANGE: Renamed the parameter `DomainAdministratorCredential`
    to `Credential` to better indicate that it is possible to impersonate
    any credential with enough permission to perform the task ([issue 269](https://github.com/PowerShell/ActiveDirectoryDsc/issues/269)).
  - Fixed the GUID in Example 3-AddComputerAccountSpecificPath_Config
    ([issue 410](https://github.com/PowerShell/ActiveDirectoryDsc/issues/410)).
  - Add example showing how to create cluster computer account ([issue 401](https://github.com/PowerShell/ActiveDirectoryDsc/issues/401)).
- Changes to ADOrganizationalUnit
  - Catch exception when the path property specifies a non-existing path
    ([issue 408](https://github.com/PowerShell/ActiveDirectoryDsc/issues/408)).
  - The unit tests are using the stub classes so the tests can be run locally.
  - Added comment-based help ([issue 339](https://github.com/PowerShell/ActiveDirectoryDsc/issues/339)).
- Changes to ADUser
  - BREAKING CHANGE: Renamed the parameter `DomainAdministratorCredential`
    to `Credential` to better indicate that it is possible to impersonate
    any credential with enough permission to perform the task ([issue 269](https://github.com/PowerShell/ActiveDirectoryDsc/issues/269)).
  - Fixes exception when creating a user with an empty string property
    ([issue 407](https://github.com/PowerShell/ActiveDirectoryDsc/issues/407)).
  - Fixes exception when updating `CommonName` and `Path` concurrently
    ([issue 402](https://github.com/PowerShell/ActiveDirectoryDsc/issues/402)).
  - Fixes ChangePasswordAtLogon Property to be only set to `true` at User
    Creation ([issue 414](https://github.com/PowerShell/ActiveDirectoryDsc/issues/414)).
  - Added comment-based help ([issue 340](https://github.com/PowerShell/ActiveDirectoryDsc/issues/340)).
  - Now it correctly tests passwords when parameter DomainName is set to
   distinguished name and parameter Credential is used ([issue 451](https://github.com/PowerShell/ActiveDirectoryDsc/issues/451)).
  - Added integration tests ([issue 359](https://github.com/PowerShell/ActiveDirectoryDsc/issues/359)).
  - Update the logic for setting the default value for the parameter
    `CommonName`. This is due to an how LCM handles parameters when a
    default value is derived from another parameter ([issue 427](https://github.com/PowerShell/ActiveDirectoryDsc/issues/427)).
  - Now uses the helper function `Add-TypeAssembly` which have some benefit
    instead of directly using `Add-Type`, like verbose logging ([issue 431](https://github.com/PowerShell/ActiveDirectoryDsc/issues/431)).
  - Add new property `ThumbnailPhoto` and read-only property `ThumbnailPhotoHash`
    ([issue 44](https://github.com/PowerShell/ActiveDirectoryDsc/issues/44)).
- Changes to ADDomain
  - BREAKING CHANGE: Renamed the parameter `DomainAdministratorCredential`
    to `Credential` to better indicate that it is possible to impersonate
    any credential with enough permission to perform the task ([issue 269](https://github.com/PowerShell/ActiveDirectoryDsc/issues/269)).
  - BREAKING CHANGE: A new parameter `AllowTrustRecreation` has been added
    that when set allows a trust to be recreated in scenarios where that
    is required. This way the user have to opt-in to such destructive
    action since since it can result in service interruption ([issue 421](https://github.com/PowerShell/ActiveDirectoryDsc/issues/421)).
  - Updated tests and replaced `Write-Error` with `throw`
    ([issue 332](https://github.com/PowerShell/ActiveDirectoryDsc/pull/332)).
  - Added comment-based help ([issue 335](https://github.com/PowerShell/ActiveDirectoryDsc/issues/335)).
  - Using `$PSBoundParameters.Remove()` returns a `[System.Boolean]` to
    indicate of the removal was done or not. That returned value has been
    suppressed ([issue 466](https://github.com/PowerShell/ActiveDirectoryDsc/issues/466)).
- Changes to ADServicePrincipalName
  - Minor change to the unit tests that did not correct assert the localized
    string when an account is not found.
- Changes to ADDomainTrust
  - BREAKING CHANGE: Renamed the parameter `TargetDomainAdministratorCredential`
    to `TargetCredential` to better indicate that it is possible to impersonate
    any credential with enough permission to perform the task ([issue 269](https://github.com/PowerShell/ActiveDirectoryDsc/issues/269)).
  - Refactored the resource to enable unit tests, and at the same time changed
    it to use the same code pattern as the resource xADObjectEnabledState.
  - Added unit tests ([issue 324](https://github.com/PowerShell/ActiveDirectoryDsc/issues/324)).
  - Added comment-based help ([issue 337](https://github.com/PowerShell/ActiveDirectoryDsc/issues/337)).
  - Added integration tests ([issue 348](https://github.com/PowerShell/ActiveDirectoryDsc/issues/348)).
- Changes to WaitForADDomain
  - BREAKING CHANGE: Refactored the resource to handle timeout better and
    more correctly wait for a specific amount of time, and at the same time
    make the resource more intuitive to use. This change has replaced
    parameters in the resource ([issue 343](https://github.com/PowerShell/ActiveDirectoryDsc/issues/343)).
  - Now the resource can use built-in `PsDscRunAsCredential` instead of
    specifying the `Credential` parameter ([issue 367](https://github.com/PowerShell/ActiveDirectoryDsc/issues/367)).
  - New parameter `SiteName` can be used to wait for a domain controller
    in a specific site in the domain.
  - Added comment-based help ([issue 341](https://github.com/PowerShell/ActiveDirectoryDsc/issues/341)).
- Changes to ADDomainController
  - BREAKING CHANGE: Renamed the parameter `DomainAdministratorCredential`
    to `Credential` to better indicate that it is possible to impersonate
    any credential with enough permission to perform the task ([issue 269](https://github.com/PowerShell/ActiveDirectoryDsc/issues/269)).
  - Add support for creating Read-Only Domain Controller (RODC)
    ([issue 40](https://github.com/PowerShell/ActiveDirectoryDsc/issues/40)).
    [Svilen @SSvilen](https://github.com/SSvilen)
  - Refactored unit tests for Test-TargetResource.
  - Added new parameter `FlexibleSingleMasterOperationRole` to able to move
    Flexible Single Master Operation (FSMO) roles to the current node.
    It does not allow seizing of roles, only allows a move when both
    domain controllers are available ([issue 55](https://github.com/PowerShell/ActiveDirectoryDsc/issues/55)).
- Changes to ADObjectPermissionEntry
  - Remove remnants of the `SupportsShouldProcess` ([issue 329](https://github.com/PowerShell/ActiveDirectoryDsc/issues/329)).
- Changes to ADGroup
  - Added comment-based help ([issue 338](https://github.com/PowerShell/ActiveDirectoryDsc/issues/338)).
  - Update the documentation with the correct default value for the parameter
    GroupScope.
- Changes to ADDomainDefaultPasswordPolicy
  - Added comment-based help ([issue 336](https://github.com/PowerShell/ActiveDirectoryDsc/issues/336)).

'

    } # End of PSData hashtable

} # End of PrivateData hashtable
}


















