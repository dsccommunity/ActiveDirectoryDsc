@{
# Version number of this module.
moduleVersion = '4.1.0.0'

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
  - New resource ADDomainControllerProperties ([issue 301](https://github.com/PowerShell/ActiveDirectoryDsc/issues/301)).
  - New resource ADForestFunctionalLevel ([issue 200](https://github.com/PowerShell/ActiveDirectoryDsc/issues/200)).
  - New resource ADDomainFunctionalLevel ([issue 200](https://github.com/PowerShell/ActiveDirectoryDsc/issues/200)).
  - Split the meta tests and the unit and integration tests in different
    AppVeyor jobs ([issue 437](https://github.com/PowerShell/ActiveDirectoryDsc/issues/437)).
  - Fixed all stub cmdlets and unit tests so the unit test can be run locally
    without having the ActiveDirectory module installed on the computer.
    This will also be reflected in the AppVeyor build worker where there
    will no longer be an ActiveDirectory module installed. This is
    to make sure that if the unit tests work locally they should also work
    in the CI pipeline.
  - Added new stubs for the cmdlets and classes to be used with unit tests.
    The new stubs are based on the modules ActiveDirectory and ADDSDeployment
    in Windows Server 2019. The stubs are generated using the PowerShell
    module *Indented.StubCommand*. Instructions how to generate stubs
    (for example for a new operating system) has been added to the README.md
    in the `Tests/Unit/Stubs` folder ([issue 245](https://github.com/PowerShell/ActiveDirectoryDsc/issues/245)).
  - Update all unit tests removing all local stub functions in favor of
    the new stub modules.
  - Enable PSSCriptAnalyzer default rules ([issue 491](https://github.com/PowerShell/ActiveDirectoryDsc/issues/491)).
- Changes to ActiveDirectoryDsc.Common
  - Updated common helper function `Find-DomainController` with the
    optional parameter `WaitForValidCredentials` which will ignore
    authentication exceptions when the credentials cannot be authenticated.
  - Updated the function `Test-ADReplicationSite` to make the parameter
    `Credential` mandatory.
  - Update helper function `Add-ADCommonGroupMember` to reduce duplicated
    code, and add an evaluation if `Members` is empty.
  - Updated helper function `Restore-ADCommonObject` to write out a verbose
    message when no object was found in the recycle bin.
  - Updated helper function `Assert-MemberParameters` to not throw an error
    if the parameter `Members` is en empty array.
- Changes to WaitForADDomain
  - Correct grammar issues in example descriptions.
  - An optional parameter `WaitForValidCredentials` can be set to $true
    to tell the resource to ignore authentication errors ([issue 478](https://github.com/PowerShell/ActiveDirectoryDsc/issues/478)).
- Changes to ADDomain
  - The property `DomainName` will now always return the same value as
    was passed in as the parameter. For the fully qualified domain name
    (FQDN) of the domain see the new read-only property `DnsRoot`.
  - If the domain should exist, the resource correctly waits only 5 times
    when calling `Get-TargetResource` if the tracking file was previously
    created ([issue 181](https://github.com/PowerShell/ActiveDirectoryDsc/issues/181)).
  - The resource now throws if either one of the cmdlets `Install-ADDSForest`
    or `Install-ADDSDomain` fails, and will not create the tracking file
    ([issue 181](https://github.com/PowerShell/ActiveDirectoryDsc/issues/181)).
  - The resource now outputs the properties from `Get-TargetResource`
    when a domain cannot be found.
  - Minor casing corrections on the parameter and variable names.
  - Improved the parameter descriptions of the parameters `DomainName`
    and `Credential`.
  - If the tracking file is missing and the domain is found a warning
    message is now written asking the consumer to recreate the file.
  - Correctly outputs the time in seconds in the verbose message how long
    the resource waits between ech retry when looking for the domain
    (when a tracking file exist and the domain is not yet responding).
  - If the `Set-TargetResource` is called directly it will not try to
    create the domain if it already exist.
  - Added read-only property `DnsRoot` that will return the fully qualified
    domain name (FQDN) of the domain or child domain.
  - Added read-only property `Forest` that will return the fully qualified
    domain name (FQDN) of the forest that the domain belongs to.
  - Added read-only property `DomainExist` that will return `$true` if
    the domain was found, or `$false` if it was not.
- Changes to ADUser
  - Remove unused non-mandatory parameters from the Get-TargetResource ([issue 293](https://github.com/PowerShell/ActiveDirectoryDsc/issues/293)).
  - Added a note to the resource README.md that `RestoreFromRecycleBin`
    needs the feature Recycle Bin enabled.
- Changes to ADDomainController
  - Add InstallDns parameter to enable promotion without installing local
    DNS Server Service ([issue 87](https://github.com/PowerShell/xActiveDirectory/issues/87)).
- Changes to ADGroup
  - Now Get-TargetResource returns correct value when the group does not
    exist.
  - Added integration tests ([issue 350](https://github.com/PowerShell/ActiveDirectoryDsc/issues/350)).
  - Added a read-only property `DistinguishedName`.
  - Refactor the function `Set-TargetResource` to use the function
    `Get-TargetResource` so that `Set-TargetResource` can correctly throw
    an error when something goes wrong ([issue 151](https://github.com/PowerShell/ActiveDirectoryDsc/issues/151),
    [issue 166](https://github.com/PowerShell/ActiveDirectoryDsc/issues/166),
    [issue 493](https://github.com/PowerShell/ActiveDirectoryDsc/issues/493)).
  - It is now possible to enforce a group with no members by using
    `Members = @()` in a configuration ([issue 189](https://github.com/PowerShell/xActiveDirectory/issues/189)).
  - Added a note to the resource README.md that `RestoreFromRecycleBin`
    needs the feature Recycle Bin enabled ([issue 496](https://github.com/PowerShell/xActiveDirectory/issues/496)).
- Changes to ADOrganizationalUnit
  - Added a note to the resource README.md that `RestoreFromRecycleBin`
    needs the feature Recycle Bin enabled.
- Changes to ADComputer
  - Added a note to the resource README.md that `RestoreFromRecycleBin`
    needs the feature Recycle Bin enabled ([issue 498](https://github.com/PowerShell/xActiveDirectory/issues/498)).
  - Updated integration test to be able to catch when a computer account
    cannot be restored.

    } # End of PSData hashtable

} # End of PrivateData hashtable
}



















