
# ActiveDirectoryDsc.Common Module
## Description
The ActiveDirectoryDsc.Common module is a PowerShell module that contains a set of functions that are common across the ActiveDirectoryDsc Module

## ActiveDirectoryDsc.Common Cmdlets
### [Add-TypeAssembly](docs/Add-TypeAssembly.md)
Adds the assembly to the PowerShell session.

### [Assert-ADPSDrive](docs/Assert-ADPSDrive.md)
Asserts if the AD PS Drive has been created, and creates one if not.

### [Assert-MemberParameters](docs/Assert-MemberParameters.md)
Assert the Members, MembersToInclude and MembersToExclude combination is valid.

### [Compare-ResourcePropertyState](docs/Compare-ResourcePropertyState.md)
Compares current and desired values for any DSC resource.

### [Convert-PropertyMapToObjectProperties](docs/Convert-PropertyMapToObjectProperties.md)
Converts a hashtable containing the parameter to property mappings to an array of properties.

### [ConvertFrom-TimeSpan](docs/ConvertFrom-TimeSpan.md)
Converts a TimeSpan object into the number of seconds, minutes, hours or days.

### [ConvertTo-DeploymentDomainMode](docs/ConvertTo-DeploymentDomainMode.md)
Converts a ModeId or ADDomainMode object to a DomainMode object.

### [ConvertTo-DeploymentForestMode](docs/ConvertTo-DeploymentForestMode.md)
Converts a ModeId or ADForestMode object to a ForestMode object.

### [ConvertTo-TimeSpan](docs/ConvertTo-TimeSpan.md)
Converts a specified time period into a TimeSpan object.

### [Find-DomainController](docs/Find-DomainController.md)
Finds an Active Directory domain controller.

### [Get-ActiveDirectoryDomain](docs/Get-ActiveDirectoryDomain.md)
Gets a Domain object for the specified context.

### [Get-ActiveDirectoryForest](docs/Get-ActiveDirectoryForest.md)
Gets a Forest object for the specified context.

### [Get-ADCommonParameters](docs/Get-ADCommonParameters.md)
Gets a common AD cmdlet connection parameter for splatting.

### [Get-ADDirectoryContext](docs/Get-ADDirectoryContext.md)
Gets an Active Directory DirectoryContext object.

### [Get-ADDomainNameFromDistinguishedName](docs/Get-ADDomainNameFromDistinguishedName.md)
Converts an Active Directory distinguished name into a fully qualified domain name.

### [Get-ADObjectParentDN](docs/Get-ADObjectParentDN.md)
Get an Active Directory object's parent distinguished name.

### [Get-ByteContent](docs/Get-ByteContent.md)
Gets the contents of a file as a byte array.

### [Get-CurrentUser](docs/Get-CurrentUser.md)
Gets the current user identity.

### [Get-DomainObject](docs/Get-DomainObject.md)
Gets the domain object with retries.

### [Get-DomainControllerObject](docs/Get-DomainControllerObject.md)
Gets an Active Directory domain controller object.

### [Get-DomainName](docs/Get-DomainName.md)
Gets the domain name of this computer.

### [New-CimCredentialInstance](docs/New-CimCredentialInstance.md)
Creates a new MSFT_Credential CIM instance credential object.

### [Remove-DuplicateMembers](docs/Remove-DuplicateMembers.md)
Removes duplicate members from a string array.

### [Resolve-MembersSecurityIdentifier](docs/Resolve-MembersSecurityIdentifier.md)
Resolves the Security Identifier (docs/SID) of a list of Members of the same type defined by the MembershipAttribute.

### [Resolve-SamAccountName](docs/Resolve-SamAccountName.md)
Resolves the SamAccountName of an Active Directory object based on a supplied ObjectSid.

### [Resolve-SecurityIdentifier](docs/Resolve-SecurityIdentifier.md)
Resolves the Security Identifier (docs/SID) of an Active Directory object based on a supplied SamAccountName.

### [Restore-ADCommonObject](docs/Restore-ADCommonObject.md)
Restores an AD object from the AD recyle bin.

### [Set-ADCommonGroupMember](docs/Set-ADCommonGroupMember.md)
Sets a member of an AD group by adding or removing its membership.

### [Start-ProcessWithTimeout](docs/Start-ProcessWithTimeout.md)
Starts a process with a timeout.

### [Test-ADReplicationSite](docs/Test-ADReplicationSite.md)
Tests Active Directory replication site availablity.

### [Test-DomainMember](docs/Test-DomainMember.md)
Tests whether this computer is a member of a domain.

### [Test-IsDomainController](docs/Test-IsDomainController.md)
Tests if the computer is a domain controller.

### [Test-Members](docs/Test-Members.md)
Tests Members of an array.

### [Test-Password](docs/Test-Password.md)
Tests the validity of a user's password.
