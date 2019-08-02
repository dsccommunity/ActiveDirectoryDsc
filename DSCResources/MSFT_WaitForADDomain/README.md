# Description

The WaitForADDomain resource is used to wait for Active Directory domain
controller to become available in the domain, or available in
a specific site in the domain.

>Running the resource as *NT AUTHORITY\SYSTEM*, only work when
>evaluating the domain on the current node, for example on a
>node that should be a domain controller (which might require a
>restart of the node once the node becomes a domain controller).
>In all other scenarios use either the built-in parameter
>`PsDscRunAsCredential`, or the parameter `Credential`.

## Requirements

* Target machine must be running Windows Server 2008 R2 or later.
