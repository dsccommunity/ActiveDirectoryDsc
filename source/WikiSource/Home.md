# Welcome to the ActiveDirectoryDsc wiki

<sup>*ActiveDirectoryDsc v#.#.#*</sup>

Here you will find all the information you need to make use of the ActiveDirectoryDsc
DSC resources in the latest release (the code that is part of the master branch). This includes details of the resources that are available, current capabilities and known issues, and information to help plan a DSC based implementation of ActiveDirectoryDsc.

Please leave comments, feature requests, and bug reports in then
[issues section](../issues) for this module.

_This wiki is currently updated manually by a maintainer, so there can be some delay before this wiki is updated for the latest release._

## Getting started

To get started either:

- Install from the PowerShell Gallery using PowerShellGet by running the following command:

```powershell
Install-Module -Name ActiveDirectoryDsc -Repository PSGallery
```

- Download ActiveDirectoryDsc from the [PowerShell Gallery](http://www.powershellgallery.com/packages/ActiveDirectoryDsc/)
and then unzip it to one of your PowerShell modules folders
(such as $env:ProgramFiles\WindowsPowerShell\Modules).

To confirm installation, run the below command and ensure you see the ActiveDirectoryDsc
DSC resources available:

```powershell
Get-DscResource -Module ActiveDirectoryDsc
```

## Prerequisites

The ActiveDirectoryDsc module requires PowerShell v5.x and the Active Directory PowerShell module to be installed. For Windows Server the Active Directory PowerShell module can be installed using the following command:

```powershell
 Install-WindowsFeature -Name 'RSAT-AD-PowerShell'
 ```

For Windows 10, the Active Directory PowerShell module can be installed using the following command:

```script
DISM /Online /add-capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```
