# Description

This resource changes the domain functional level. For further details, see [Forest and Domain Functional Levels](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels).

**WARNING: This action might be irreversible!** Make sure you understand
the consequences of changing the domain functional level.

Read more about raising function levels and potential roll back
scenarios in the Active Directory documentation. For example: [Upgrade Domain Controllers to Windows Server 2016](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/upgrade-domain-controllers).

## Requirements

* Target machine must be running Windows Server 2008 R2 or later.
* Target machine must be running the minimum required operating system
  version for the domain functional level to set.
