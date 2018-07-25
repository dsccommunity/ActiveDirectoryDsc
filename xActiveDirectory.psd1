@{
# Version number of this module.
moduleVersion = '2.20.0.0'

# ID used to uniquely identify this module
GUID = '9FECD4F6-8F02-4707-99B3-539E940E9FF5'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) 2014 Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = 'The xActiveDirectory module is originally part of the Windows PowerShell Desired State Configuration (DSC) Resource Kit. This version has been modified for use in Azure. This module contains the xADDomain, xADDomainController, xADUser, and xWaitForDomain resources. These DSC Resources allow you to configure and manage Active Directory.

All of the resources in the DSC Resource Kit are provided AS IS, and are not supported through any Microsoft standard support program or service.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('DesiredStateConfiguration', 'DSC', 'DSCResourceKit', 'DSCResource')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/PowerShell/xActiveDirectory/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/PowerShell/xActiveDirectory'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '* Changes to xActiveDirectory
  * Changed MSFT_xADUser.schema.mof version to "1.0.0.0" to match other resources ([issue 190](https://github.com/PowerShell/xActiveDirectory/issues/190)). [thequietman44 (@thequietman44)](https://github.com/thequietman44)
  * Removed duplicated code from examples in README.md ([issue 198](https://github.com/PowerShell/xActiveDirectory/issues/198)). [thequietman44 (@thequietman44)](https://github.com/thequietman44)
  * xADDomain is now capable of setting the forest and domain functional level ([issue 187](https://github.com/PowerShell/xActiveDirectory/issues/187)). [Jan-Hendrik Peters (@nyanhp)](https://github.com/nyanhp)

'

    } # End of PSData hashtable

} # End of PrivateData hashtable
}










