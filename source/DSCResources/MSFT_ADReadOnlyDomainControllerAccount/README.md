# Description

The ADReadOnlyDomainControllerAccount DSC resource will pre-create a read only domain
controller account in Active Directory. This allows the account actually installing
the read only domain controller to use delegated administrative credentials supplied in
DelegatedAdministratorAccountName rather than requiring Domain Admins permissions.

> The resource does not support removing pre-created Read Only Domain Controller accounts.

## Requirements

* Target machine must be running Windows Server 2008 R2 or later.
