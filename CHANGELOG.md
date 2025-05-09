# Changelog for ActiveDirectoryDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For older change log history see the [historic changelog](HISTORIC_CHANGELOG.md).

## [Unreleased]

### Added
- ADDomain
  - Support for Windows Server 2025 Forest and Domain functional modes.
    ([issue #721](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/721)).
- ADDomainFunctionalLevel
  - Support for Windows Server 2025 Domain functional mode.
    ([issue #721](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/721)).
- ADForestFunctionalLevel
  - Support for Windows Server 2025 Forest functional mode.
    ([issue #721](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/721)).
- ADUser
  - Support for AdminDescription, PhoneticDisplayName, PreferredLanguage and
    SimpleDisplayName attributes.

## [6.6.2] - 2025-03-17

### Fixed
 - ADObjectPermissionEntry
   - Fixed regression in 6.6.1 when using Join-Path.
   ([issue #727](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/727)).

## [6.6.1] - 2025-03-15

### Fixed
- ADmanagedServiceAccount
  - Set properties KeberosEncryptionType and TrustedForDelegation properly on account creation.
    Both properties were not considered previously when the account was created.
    ([issue #650](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/650)).
- ADObjectPermissionEntry
  - Fixed regression where resource cannot run on Windows Server 2016
    ([issue #724](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/724)).

## [6.6.0] - 2024-09-29

### Added
- ADManagedServiceAccount
  - New parameter TrustedForDelegation for Kerberos Delegation
    ([issue #717](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/717)).
  - New parameter TrustedForDelegation for Service Principal Name
    ([issue #717](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/717)).
- ADDomainController
  - New parameter UseExistingAccount for attaching a server to an existing RODC account.
    ([issue #711](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/711)).
- ADReadOnlyDomainControllerAccount
  - New resource for pre-creating Read Only Domain Controller accounts.
    ([issue #40](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/40))
    ([issue #711](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/711)).

### Fixed

- ActiveDirectoryDsc.Common
  - Fixed Get-DomainControllerObject to allow checking non-local domain controller accounts.
- ADObjectPermissionEntry
  - Fixed 'The object name has a bad syntax' error when using path that requires escaping.
    ([issue #675](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/675)).
- Update build process to pin GitVersion to 5.* to resolve errors
  (https://github.com/gaelcolas/Sampler/issues/477).

## [6.5.0] - 2024-05-17

### Added

- ADDomainController
  - Added support for specifying an RODC delegated administrator account using DelegatedAdministratorAccountName.

### Changed

- ADDomainController
  - Do not allow use of AllowPasswordReplicationAccountName or DenyPasswordReplicationAccountName
    unless ReadOnlyReplica is also set.
- ADServicePrincipalName
  - Add check to Set function to cover if `Invoke-DscResource -Method Set` is run and no changes are required.
    ([issue #520](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/520))
- VS Code
  - Add recommended extensions ([issue #622](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/622))

## [6.4.0] - 2024-02-14

### Added

- ADDomain
  - Added support for creating a Tree domain via the DomainType field
    ([issue #689](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/689))
    ([issue #692](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/692)).

### Fixed

- Move test pipeline to Windows PowerShell. The hosted agent was updated
  to PowerShell 7.4.1. That broke the ASKDSKey unit tests that has a helper
  function (`Copy-ArrayObjects`) that serializes objects.
- ADSRootKey
  -  Resolved 'String was not recognized as a valid DateTime' in non-US cultures ([issue #702](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/702)).

## [6.3.0] - 2023-08-24

### Removed

- ActiveDirectoryDsc
  - There was a 'build.ps1' file under the source folder than are no longer
    required for ModuleBuilder to work.

### Changed

- ActiveDirectoryDsc
  - Move CI/CD build step to using build worker image `windows-latest`.
- ActiveDirectoryDsc.Common
  - Created Get-DomainObject to wrap Get-ADDomain with common retry logic.
- ADDomainController
  - Refactored to use Get-DomainObject ([issue #673](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/673)).
  - Refactored Unit Tests.
- ADDomain
  - Refactored to use Get-DomainObject.
  - Refactored Unit Tests.
- ADOrganizationalUnit
  - Added DomainController Parameter.

### Fixed

- ADReplicationSiteLink
  - Allow OptionChangeNotification, OptionTwoWaySync and OptionDisableCompression to be updated even if
    ReplicationFrequencyInMinutes is not set ([issue #637](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/637)).

## [6.2.0] - 2022-05-01

### Changed

- ActiveDirectoryDsc
  - Updated Pipeline to Ubuntu 18.04 from Ubuntu 16.04
    ([issue #667](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/667))
  - Update pipeline files to latest Sampler ([issue #680](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/680)).
- ADGroup
  - Refactored Module.
  - Refactored Unit and Integration Tests.

### Added

- ADManagedServiceAccount
  - Added support for setting a common name to a Managed Service Account for a longer more friendly name than
    the SAM account name which has a 15 character limit.
    ([issue #644](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/644)).
- ADGroup
  - Added support for managing AD group membership of Foreign Security Principals. This involved completely
    refactoring group membership management to utilize the `Set-ADGroup` cmdlet and referencing SID values.
    ([issue #619](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/619)).
- ADFineGrainedPasswordPolicy
  - New resource for creating and updating Fine Grained Password Policies for AD principal subjects.
    ([issue #584](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/584)).

### Changed

- ActiveDirectoryDsc
  - Renamed `master` branch to `main` ([issue #641](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/641)).
  - Migrated to DscResource.Common Module.
  - Fixed the pipeline paths trigger.
  - Migrated HQRM and Unit Tests to use PowerShell 7 in the CI pipeline.
  - Changed CI pipeline to use PublishPipelineArtifact & DownloadPipelineArtifact.
  - Removed redundant common functions `Resolve-DomainFQDN` and `Set-DscADComputer`.
  - Added ActiveDirectoryDsc.Common Module markdown help.
  - Updated the `DscResource.Common` module to `v0.9.0`.
- ADDomainTrust
  - Move `Get-ActiveDirectoryDomain` and `Get-ActiveDirectoryForest` functions
    into the `ActiveDirectoryDsc.Common` module.
- ADReplicationSiteLink
  - Refactor Test-TargetResource Function.

### Fixed

- ActiveDirectoryDsc
  - The component `gitversion` that is used in the pipeline was wrongly configured
    when the repository moved to the new default branch `main`. It no longer throws
    an error when using newer versions of GitVersion.
  - Fixed the CI pipeline by pinning the `Pester` module to `v4.10.1`
  - Restored importing the `DscResource.Common` module import in the `ActiveDirectoryDsc.Common` module that was
    incorrectly disabled.
    ([issue #612](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/612)).
- ADDomainController
  - Fixed `Test-TargetResource` error when the `ReadOnlyReplica` property is set to `true`
    ([issue #611](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/611)).
- ADGroup
  - Fixed issue with retrieving group members using `Get-ADGroupMember` when members are from another domain
    by adding and using the 'Members' property from `Get-ADGroup` and sending the resulting DistinguishedName to
    `Get-ADObject` when `Get-ADGroupMember` throws a specific error.
    ([issue #616](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/616)).
- ADOrganizationalUnit
  - Removed Credential and RestoreFromRecycleBin from the list of desired values to compare when passed
    ([issue #624](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/624)).
  - Allows use of apostrophe or single quote in Name attribute
    ([issue #674](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/674)).
- ADReplicationSiteLink
  - Fixed setting options after the resource is initially created
    ([issue #605](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/605)).
- ADKDSKey
  - The resource did not work due to a non-working date conversion.
    ([issue #648](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/648)).

## [6.1.0] - 2020-12-09

### Changed

- Retracted release.

## [6.0.1] - 2020-04-16

### Fixed

- ActiveDirectoryDsc
  - The regular expression for `minor-version-bump-message` in the file
    `GitVersion.yml` was changed to only raise minor version when the
    commit message contain the word `add`, `adds`, `minor`, `feature`,
    or `features` ([issue #588](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/588)).
  - Rename folder 'Tests' to folder 'tests' (lower-case).
  - Moved oldest changelog details to historic changelog.
- ADDomain
  - Added additional Get-ADDomain retry exceptions
    ([issue #581](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/581)).
- ADUser
  - Fixed PasswordAuthentication parameter handling
  ([issue #582](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/582)).
- ADReplicationSiteLink
  - Fix Test-TargetResource when Ensure is Absent and other attributes are set
    ([issue #593](https://github.com/PowerShell/ActiveDirectoryDsc/issues/593)).

### Fixed

### Changed

- ActiveDirectoryDsc
  - Only run CI pipeline on branch `master` when there are changes to files
    inside the `source` folder.

## [6.0.0] - 2020-03-12

### Added

- ActiveDirectoryDsc
  - Added [Codecov.io](https://codecov.io) support.
  - Fixed miscellaneous spelling errors.
  - Added Strict-Mode v1.0 to all unit tests.
- ADDomain
  - Added integration tests
    ([issue #345](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/345)).
- ADGroup
  - Added support for Managed Service Accounts
    ([issue #532](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/532)).
- ADForestProperties
  - Added TombstoneLifetime property
    ([issue #302](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/302)).
  - Added Integration tests
    ([issue #349](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/349)).

### Fixed

- ADForestProperties
  - Fixed ability to clear `ServicePrincipalNameSuffix` and `UserPrincipalNameSuffix`
    ([issue #548](https://github.com/PowerShell/ActiveDirectoryDsc/issues/548)).
- WaitForADDomain
  - Fixed `Find-DomainController` to correctly handle an exception thrown when a domain controller is not ready
    ([issue #530](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/530)).
- ADObjectPermissionEntry
  - Fixed issue where Get-DscConfiguration / Test-DscConfiguration throw an exception when target object path does not
    yet exist
    ([issue #552](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/552)).
  - Fixed issue where Get-TargetResource throw an exception, `Cannot find drive. A drive with the name 'AD' does not
    exist`, when running soon after domain controller restart
    ([issue #547](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/547)).
- ADOrganizationalUnit
  - Fixed issue where Get-DscConfiguration/Test-DscConfiguration throws an exception when parent path does not yet exist
    ([issue #553](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/553)).
- ADReplicationSiteLink
  - Fixed issue creating a Site Link with options specified
    ([issue #571](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/571)).
- ADDomain
  - Added additional Get-ADDomain retry exceptions
    ([issue #574](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/574)).

### Changed

- ActiveDirectoryDsc
  - BREAKING CHANGE: Required PowerShell version increased from v4.0 to v5.0
  - Updated Azure Pipeline Windows image
    ([issue #551](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/551)).
  - Updated license copyright
    ([issue #550](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/550)).
- ADDomain
  - Changed Domain Install Tracking File to use NetLogon Registry Test.
    ([issue #560](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/560)).
  - Updated the Get-TargetResource function with the following:
    - Removed unused parameters.
    - Removed unnecessary domain membership check.
    - Removed unneeded catch exception blocks.
    - Changed Get-ADDomain and Get-ADForest to use localhost as the server.
    - Improved Try/Catch blocks to only cover cmdlet calls.
    - Simplified retry timing loop.
  - Refactored unit tests.
  - Updated NewChildDomain example to clarify the contents of the credential parameter and use Windows 2016 rather than
    2012 R2.
- ADDomainController
  - Updated the Get-TargetResource function with the following:
    - Removed unused parameters.
    - Added IsDnsServer read-only property
      ([issue #490](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/490)).
- ADForestProperties
  - Refactored unit tests.
- ADReplicationSiteLink
  - Refactored the `Set-TargetResource` function so that properties are only set if they have been changed.
  - Refactored the resource unit tests.
  - Added quotes to all the variables in the localised string data.
- ADOrganizationalUnit
  - Replaced throws with `New-InvalidOperationException`.
  - Refactored `Get-TargetResource` to not reference properties of a `$null` object
  - Fixed organization references to organizational.
  - Refactored `Test-TargetResource` to use `Compare-ResourcePropertyState` common function.
  - Reformatted code to keep line lengths to less than 120 characters.
  - Removed redundant `Assert-Module` and `Get-ADOrganizationalUnit` function calls from `Set-TargetResource`.
  - Wrapped `Set-ADOrganizationalUnit` and `Remove-ADOrganizationalUnit` with try/catch blocks and used common exception
    function.
  - Added `DistinguishedName` read-only property.
  - Refactored unit tests.
- ADUser
  - Improve Try/Catch blocks to only cover cmdlet calls.
  - Move the Test-Password function to the ActiveDirectoryDsc.Common module and add unit tests.
  - Reformat code to keep line lengths to less than 120 characters.
  - Fix Password parameter processing when PasswordNeverResets is $true.
  - Remove unnecessary Enabled parameter check.
  - Remove unnecessary Clear explicit parameter check.
  - Add check to only call Set-ADUser if there are properties to change.
  - Refactored Unit Tests - ([issue #467](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/467))

## [5.0.0] - 2020-01-14

### Added

- ADServicePrincipalName
  - Added Integration tests
    ([issue #358](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/358)).
- ADManagedServiceAccount
  - Added Integration tests.
- ADKDSKey
  - Added Integration tests
    ([issue #351](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/351)).

### Changed

- ADManagedServiceAccount
  - KerberosEncryptionType property added.
    ([issue #511](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/511)).
  - BREAKING CHANGE: AccountType parameter ValidateSet changed from ('Group', 'Single') to ('Group', 'Standalone') -
    Standalone is the correct terminology.
    Ref: [Service Accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts).
    ([issue #515](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/515)).
  - BREAKING CHANGE: AccountType parameter default of Single removed. - Enforce positive choice of account type.
  - BREAKING CHANGE: MembershipAttribute parameter ValidateSet member SID changed to ObjectSid to match result property
    of Get-AdObject. Previous code does not work if SID is specified.
  - BREAKING CHANGE: AccountTypeForce parameter removed - unnecessary complication.
  - BREAKING CHANGE: Members parameter renamed to ManagedPasswordPrincipals - to closer match Get-AdServiceAccount result
    property PrincipalsAllowedToRetrieveManagedPassword. This is so that a DelegateToAccountPrincipals parameter can be
    added later.
  - Common Compare-ResourcePropertyState function used to replace function specific Compare-TargetResourceState and code
    refactored.
    ([issue #512](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/512)).
  - Resource unit tests refactored to use nested contexts and follow the logic of the module.
- ActiveDirectoryDsc
  - Updated PowerShell help files.
  - Updated Wiki link in README.md.
  - Remove verbose parameters from unit tests.
  - Fix PowerShell script file formatting and culture string alignment.
  - Add the `pipelineIndentationStyle` setting to the Visual Studio Code settings file.
  - Remove unused common function Test-DscParameterState
    ([issue #522](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/522)).

### Fixed

- ActiveDirectoryDsc
  - Fix tests ErrorAction on DscResource.Test Import-Module.
- ADObjectPermissionEntry
  - Updated Assert-ADPSDrive with PSProvider Checks
    ([issue #527](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/527)).
- ADReplicationSite
  - Fixed incorrect evaluation of site configuration state when no description is defined
    ([issue #534](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/534)).
- ADReplicationSiteLink
  - Fix RemovingSites verbose message
    ([issue #518](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/518)).
- ADComputer
  - Fixed the SamAcountName property description
    ([issue #529](https://github.com/dsccommunity/ActiveDirectoryDsc/issues/529)).
