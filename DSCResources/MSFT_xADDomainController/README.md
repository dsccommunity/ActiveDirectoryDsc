# Description

The xADDomainController DSC resource will install and configure domain
controllers in Active Directory.

>**Note:** If the account used for the parameter `DomainAdministratorCredential`
>cannot connect to another domain controller, for example using a credential
>without the domain name, then the cmdlet `Install-ADDSDomainController` will
>seemingly halt (without reporting an error) when trying to replicate
>information from another domain controller.
>Make sure to use a correct domain account with the correct permission as
>the account for the parameter `DomainAdministratorCredential`.
