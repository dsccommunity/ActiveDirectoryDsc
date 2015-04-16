[![Build status](https://ci.appveyor.com/api/projects/status/p4jejr60jrgb8ity/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/xactivedirectory/branch/master)

#xActiveDirectory

The** xActiveDirectory** module is a part of the Windows PowerShell Desired State Configuration (DSC) Resource Kit, which is a collection of DSC Resources produced by the PowerShell Team.
This module contains the **xADDomain, xADDomainController, xADUser, xWaitForDomain, and xADDomainTrust** resources.
These DSC Resources allow you to configure and manage Active Directory.
Note: these resources do not presently install the RSAT tools.


**All of the resources in the DSC Resource Kit are provided AS IS, and are not supported through any Microsoft standard support program or service.
The "x" in xActiveDirectory stands for experimental**, which means that these resources will be **fix forward** and monitored by the module owner(s).


Please leave comments, feature requests, and bug reports in the Q &amp;amp; A tab for this module.

If you would like to modify **xActiveDirectory** module, feel free.
When modifying, please update the module name, resource friendly name, and MOF class name (instructions below).
As specified in the license, you may copy or modify this resource as long as they are used on the Windows Platform.


For more information about Windows PowerShell Desired State Configuration, check out the blog posts on the [PowerShell Blog](http://blogs.msdn.com/b/powershell/) ([this](http://blogs.msdn.com/b/powershell/archive/2013/11/01/configuration-in-a-devops-world-windows-powershell-desired-state-configuration.aspx) is a good starting point).
There are also great community resources, such as [ PowerShell.org ](http://powershell.org/wp/tag/dsc/), or [ PowerShell Magazine ](http://www.powershellmagazine.com/tag/dsc/).
For more information on the DSC Resource Kit, check out [this blog post](http://go.microsoft.com/fwlink/?LinkID=389546).

## Contributing
Please check out common DSC Resources [contributing guidelines](https://github.com/PowerShell/xDscResources/blob/master/CONTRIBUTING.md).

## Installation

To install **xActiveDirectory** module

*   Unzip the content under $env:ProgramFiles\WindowsPowerShell\Modules folder

To confirm installation:

*   Run **Get-DSCResource** to see that **xADDomain, xADDomainController, xADUser, xWaitForDomain, and xADDomainTrust** are among the DSC Resources listed 


## Requirements

This module requires the latest version of PowerShell (v4.0, which ships in Windows 8.1 or Windows Server 2012R2).
To easily use PowerShell 4.0 on older operating systems, [install WMF 4.0](http://www.microsoft.com/en-us/download/details.aspx?id=40855).
Please read the installation instructions that are present on both the download page and the release notes for WMF 4.0.


## Description

The **xActiveDirectory **module contains the **xADDomain, xADDomainController, xADUser, xWaitForDomain, and ADDomainTrust** DSC Resources.
These DSC Resources allow you to configure new domain, child domains,high availability domain controllers and establish cross-domain trusts.
The  **xADDomain** resource is responsible to create new Active directory forest configuration or new Active directory domain configuration.
The  **xADDomainController ** resource is responsible to install a domain controller in Active directory.
The  **xADUser** resource is responsible to modify or remove Active directory User.
The **xWaitForDomain** resource is responsible to wait for new domain to setup.
It's worth noting that the RSAT tools will not be installed when these resources are used to configure AD.
The **xADDomainTrust** resource is used to establish a cross-domain trust.
     

## Details

**xADDomain** resource has following properties:

*   **DomainName**: Name of the domain.
If no parent name is specified, this is the fully qualified domain name for first domain in the forest.

*   **ParentDomainName**: Name of the parent domain.

*   **DomainAdministratorCredential**: Credentials used to query for domain existence.
Note: These are not used during domain creation.
( AD sets the localadmin credentials as new domain administrator credentials during setup ) 
*   **SafemodeAdministratorPassword**:   Password for the administrator account when the computer is started in Safe Mode.
 
*   ** DnsDelegationCredential: **Credential used for creating DNS delegation 

**xADDomainController** resource has following properties:

*   **DomainName**: The fully qualified domain name for the domain where the domain controller will be present 
*   **DomainAdministratorCredential**: Specifies the credential for the account used to install the domain controller 
*   **SafemodeAdministratorPassword**: Password for the administrator account when the computer is started in Safe Mode.


**xADUser** resource has following properties:

*   **Ensure**: Specifies whether the given user is present or absent 
*   **DomainName**: Name of the domain to which the user will be added 
*   **UserName**: Name of the user 
*   **Password**: &amp;lt;span&amp;gt; Password value for the account  
*   **DomainAdministratorCredential: **User account credentials used to perform the task 

**xWaitForADDomain** resource has following properties:

*   **DomainName**: Name of the domain to wait for 
*   **RetryIntervalSec**: Interval to check for the domain's existance 
*   **RetryCount**: Maximum number of retries to check for the domain's existance 

**xADDomainTrust** resource has following properties:

*   **Ensure:** Specifies whether the domain trust is present or absent 
*   **TargetDomainAdministratorCredential: **Credentials to authenticate to the target domain 
*   **TargetDomainName:** Name of the AD domain that is being trusted 
*   **TrustType:** Type of trust 
*   **TrustDirection:** Direction of trust, the values for which may be Bidirectional,Inbound, or Outbound 
*   **SourceDomainName:** Name of the AD domain that is requesting the trust 

## Versions

### 1.0.0.0

*   Initial release with the following resources:
    *   xADDomain, xADDomainController, xADUser, and xWaitForDomain.

### 2.0.0.0

*   Updated release, which added the resource:
    *   xADDomainTrust.

### 2.1.0.0

*   Minor update: Get-TargetResource to use domain name instead of name.

### 2.2

*   Modified xAdDomain and xAdDomainController to support Ensure as Present / Absent, rather than True/False.
Note: this may cause issues for existing scripts.
Also corrected return value to be a hashtable in both resources.


## Examples

### Create a highly available Domain using multiple domain controllers
In the following example configuration, a highly available domain is created by adding a domain controller to an existing domain.
This example uses the xWaitForDomain resource to ensure that the domain is present before the second domain controller is added.

```powershell
# A configuration to Create High Availability Domain Controller 
Configuration AssertHADC
{
   param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory)]
        [pscredential]$DNSDelegationCred,
        [Parameter(Mandatory)]
        [pscredential]$NewADUserCred
    )
    Import-DscResource -ModuleName xActiveDirectory
    Node $AllNodes.Where{$_.Role -eq "Primary DC"}.Nodename
    {
        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }
        xADDomain FirstDS
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DnsDelegationCredential = $DNSDelegationCred
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
        xWaitForADDomain DscForestWait
        {
            DomainName = $Node.DomainName
            DomainUserCredential = $domainCred
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[xADDomain]FirstDS"
        }
        xADUser FirstUser
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            UserName = "dummy"
            Password = $NewADUserCred
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
    }
    Node $AllNodes.Where{$_.Role -eq "Replica DC"}.Nodename
    {
        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }
        xWaitForADDomain DscForestWait
        {
            DomainName = $Node.DomainName
            DomainUserCredential = $domainCred
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
        xADDomainController SecondDC
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DnsDelegationCredential = $DNSDelegationCred
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
    }
}
# Configuration Data for AD 
$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = "dsc-testNode1"
            Role = "Primary DC"
            DomainName = "dsc-test.contoso.com"
            CertificateFile = "C:\publicKeys\targetNode.cer"  
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8" 
            RetryCount = 20 
            RetryIntervalSec = 30 
        },
        @{
            Nodename = "dsc-testNode2"
            Role = "Replica DC"
            DomainName = "dsc-test.contoso.com"
            CertificateFile = "C:\publicKeys\targetNode.cer"  
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8" 
            RetryCount = 20 
            RetryIntervalSec = 30 
        }
    )
}
AssertHADC -configurationData $ConfigData `
-safemodeAdministratorCred (Get-Credential -Message "New Domain Safe Mode Admin Credentials") `
-domainCred (Get-Credential -Message "New Domain Admin Credentials") `
-DNSDelegationCred (Get-Credential -Message "Credentials to Setup DNS Delegation") `
-NewADUserCred (Get-Credential -Message "New AD User Credentials")
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode1" -Path $PSScriptRoot\AssertHADC `
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine")
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode2" -Path $PSScriptRoot\AssertHADC `
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine")
# A configuration to Create High Availability Domain Controller  
 
Configuration AssertHADC 
{ 
 
   param 
    ( 
        [Parameter(Mandatory)] 
        [pscredential]$safemodeAdministratorCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$domainCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$DNSDelegationCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$NewADUserCred 
    ) 
 
    Import-DscResource -ModuleName xActiveDirectory 
 
    Node $AllNodes.Where{$_.Role -eq "Primary DC"}.Nodename 
    { 
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services" 
        } 
 
        xADDomain FirstDS 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            DnsDelegationCredential = $DNSDelegationCred 
            DependsOn = "[WindowsFeature]ADDSInstall" 
        } 
 
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $Node.DomainName 
            DomainUserCredential = $domainCred 
            RetryCount = $Node.RetryCount 
            RetryIntervalSec = $Node.RetryIntervalSec 
            DependsOn = "[xADDomain]FirstDS" 
        } 
 
        xADUser FirstUser 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domainCred 
            UserName = "dummy" 
            Password = $NewADUserCred 
            Ensure = "Present" 
            DependsOn = "[xWaitForADDomain]DscForestWait" 
        } 
 
    } 
 
    Node $AllNodes.Where{$_.Role -eq "Replica DC"}.Nodename 
    { 
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services" 
        } 
 
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $Node.DomainName 
            DomainUserCredential = $domainCred 
            RetryCount = $Node.RetryCount 
            RetryIntervalSec = $Node.RetryIntervalSec 
            DependsOn = "[WindowsFeature]ADDSInstall" 
        } 
 
        xADDomainController SecondDC 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            DnsDelegationCredential = $DNSDelegationCred 
            DependsOn = "[xWaitForADDomain]DscForestWait" 
        } 
    } 
} 
 
# Configuration Data for AD  
 
$ConfigData = @{ 
    AllNodes = @( 
        @{ 
            Nodename = "dsc-testNode1" 
            Role = "Primary DC" 
            DomainName = "dsc-test.contoso.com" 
            CertificateFile = "C:\publicKeys\targetNode.cer"   
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"  
            RetryCount = 20  
            RetryIntervalSec = 30  
        }, 
 
        @{ 
            Nodename = "dsc-testNode2" 
            Role = "Replica DC" 
            DomainName = "dsc-test.contoso.com" 
            CertificateFile = "C:\publicKeys\targetNode.cer"   
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"  
            RetryCount = 20  
            RetryIntervalSec = 30  
        } 
    ) 
} 
 
AssertHADC -configurationData $ConfigData ` 
-safemodeAdministratorCred (Get-Credential -Message "New Domain Safe Mode Admin Credentials") ` 
-domainCred (Get-Credential -Message "New Domain Admin Credentials") ` 
-DNSDelegationCred (Get-Credential -Message "Credentials to Setup DNS Delegation") ` 
-NewADUserCred (Get-Credential -Message "New AD User Credentials") 
 
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode1" -Path $PSScriptRoot\AssertHADC ` 
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine") 
 
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode2" -Path $PSScriptRoot\AssertHADC ` 
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine") 
```

 
### Create a child domain under a parent domain

In this example, we create a domain, and then create a child domain on another node.

```powershell
# Configuration to Setup Parent Child Domains  
 
Configuration AssertParentChildDomains 
{ 
    param 
    ( 
        [Parameter(Mandatory)] 
        [pscredential]$safemodeAdministratorCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$domainCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$DNSDelegationCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$NewADUserCred 
    ) 
 
    Import-DscResource -ModuleName xActiveDirectory 
 
    Node $AllNodes.Where{$_.Role -eq "Parent DC"}.Nodename 
    { 
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services" 
        } 
 
        xADDomain FirstDS 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            DnsDelegationCredential = $DNSDelegationCred 
            DependsOn = "[WindowsFeature]ADDSInstall" 
        } 
 
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $Node.DomainName 
            DomainUserCredential = $domainCred 
            RetryCount = $Node.RetryCount 
            RetryIntervalSec = $Node.RetryIntervalSec 
            DependsOn = "[xADDomain]FirstDS" 
        } 
 
        xADUser FirstUser 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domaincred 
            UserName = "dummy" 
            Password = $NewADUserCred 
            Ensure = "Present" 
            DependsOn = "[xWaitForADDomain]DscForestWait" 
        } 
 
    } 
 
    Node $AllNodes.Where{$_.Role -eq "Child DC"}.Nodename 
    { 
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services" 
        } 
 
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $Node.ParentDomainName 
            DomainUserCredential = $domainCred 
            RetryCount = $Node.RetryCount 
            RetryIntervalSec = $Node.RetryIntervalSec 
            DependsOn = "[WindowsFeature]ADDSInstall" 
        } 
 
        xADDomain ChildDS 
        { 
            DomainName = $Node.DomainName 
            ParentDomainName = $Node.ParentDomainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            DependsOn = "[xWaitForADDomain]DscForestWait" 
        } 
    } 
} 
 
$ConfigData = @{ 
 
    AllNodes = @( 
        @{ 
            Nodename = "dsc-testNode1" 
            Role = "Parent DC" 
            DomainName = "dsc-test.contoso.com"         
            CertificateFile = "C:\publicKeys\targetNode.cer"   
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"  
            RetryCount = 50  
            RetryIntervalSec = 30  
        }, 
 
        @{ 
            Nodename = "dsc-testNode2" 
            Role = "Child DC" 
            DomainName = "dsc-child" 
            ParentDomainName = "dsc-test.contoso.com"              
            CertificateFile = "C:\publicKeys\targetNode.cer"   
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"  
            RetryCount = 50  
            RetryIntervalSec = 30         
        } 
    ) 
} 
 
AssertParentChildDomains -configurationData $ConfigData ` 
-safemodeAdministratorCred (Get-Credential -Message "New Domain Safe Mode Admin Credentials") ` 
-domainCred (Get-Credential -Message "New Domain Admin Credentials") ` 
-DNSDelegationCred (Get-Credential -Message "Credentials to Setup DNS Delegation") ` 
-NewADUserCred (Get-Credential -Message "New AD User Credentials") 
 
 
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode1" -Path $PSScriptRoot\AssertParentChildDomains ` 
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine") 
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode2" -Path $PSScriptRoot\AssertParentChildDomains ` 
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine") 
``` 
 
### Create a cross-domain trust
In this example, we setup one-way trust between two domains
 

```powershell
Configuration Sample_xADDomainTrust_OneWayTrust
{
    param
    (
        [Parameter(Mandatory)]
        [String]$SourceDomain,
        [Parameter(Mandatory)]
        [String]$TargetDomain,
        
        [Parameter(Mandatory)]
        [PSCredential]$TargetDomainAdminCred,
        [Parameter(Mandatory)]
        [String]$TrustDirection
    )
    Import-DscResource -module xActiveDirectory
    Node $AllNodes.Where{$_.Role -eq 'DomainController'}.NodeName
    {
        xADDomainTrust trust
        {
            Ensure                              = 'Present'
            SourceDomainName                    = $SourceDomain
            TargetDomainName                    = $TargetDomain
            TargetDomainAdministratorCredential = $TargetDomainAdminCred
            TrustDirection                      = $TrustDirection
            TrustType                           = 'External'
        }
    }
}
$config = @{
    AllNodes = @(
        @{
            NodeName      = 'localhost'
            Role          = 'DomainController'
            # Certificate Thumbprint that is used to encrypt/decrypt the credential
            CertificateID = 'B9192121495A307A492A19F6344E8752B51AC4A6'
        }
    )
}
Sample_xADDomainTrust_OneWayTrust -configurationdata $config `
                                  -SourceDomain safeharbor.contoso.com `
                                  -TargetDomain corporate.contoso.com `
                                  -TargetDomainAdminCred (get-credential) `
                                  -TrustDirection 'Inbound'
# Configuration to Setup Parent Child Domains  
 
configuration AssertParentChildDomains 
{ 
    param 
    ( 
        [Parameter(Mandatory)] 
        [pscredential]$safemodeAdministratorCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$domainCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$DNSDelegationCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$NewADUserCred 
    ) 
 
    Import-DscResource -ModuleName xActiveDirectory 
 
    Node $AllNodes.Where{$_.Role -eq "Parent DC"}.Nodename 
    { 
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services" 
        } 
 
        xADDomain FirstDS 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            DnsDelegationCredential = $DNSDelegationCred 
            DependsOn = "[WindowsFeature]ADDSInstall" 
        } 
 
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $Node.DomainName 
            DomainUserCredential = $domainCred 
            RetryCount = $Node.RetryCount 
            RetryIntervalSec = $Node.RetryIntervalSec 
            DependsOn = "[xADDomain]FirstDS" 
        } 
 
        xADUser FirstUser 
        { 
            DomainName = $Node.DomainName 
            DomainAdministratorCredential = $domaincred 
            UserName = "dummy" 
            Password = $NewADUserCred 
            Ensure = "Present" 
            DependsOn = "[xWaitForADDomain]DscForestWait" 
        } 
 
    } 
 
    Node $AllNodes.Where{$_.Role -eq "Child DC"}.Nodename 
    { 
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services" 
        } 
 
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $Node.ParentDomainName 
            DomainUserCredential = $domainCred 
            RetryCount = $Node.RetryCount 
            RetryIntervalSec = $Node.RetryIntervalSec 
            DependsOn = "[WindowsFeature]ADDSInstall" 
        } 
 
        xADDomain ChildDS 
        { 
            DomainName = $Node.DomainName 
            ParentDomainName = $Node.ParentDomainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            DependsOn = "[xWaitForADDomain]DscForestWait" 
        } 
    } 
} 
 
$ConfigData = @{ 
 
    AllNodes = @( 
        @{ 
            Nodename = "dsc-testNode1" 
            Role = "Parent DC" 
            DomainName = "dsc-test.contoso.com"         
            CertificateFile = "C:\publicKeys\targetNode.cer"   
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"  
            RetryCount = 50  
            RetryIntervalSec = 30  
        }, 
 
        @{ 
            Nodename = "dsc-testNode2" 
            Role = "Child DC" 
            DomainName = "dsc-child" 
            ParentDomainName = "dsc-test.contoso.com"              
            CertificateFile = "C:\publicKeys\targetNode.cer"   
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"  
            RetryCount = 50  
            RetryIntervalSec = 30         
        } 
    ) 
} 
 
AssertParentChildDomains -configurationData $ConfigData ` 
-safemodeAdministratorCred (Get-Credential -Message "New Domain Safe Mode Admin Credentials") ` 
-domainCred (Get-Credential -Message "New Domain Admin Credentials") ` 
-DNSDelegationCred (Get-Credential -Message "Credentials to Setup DNS Delegation") ` 
-NewADUserCred (Get-Credential -Message "New AD User Credentials") 
 
 
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode1" -Path $PSScriptRoot\AssertParentChildDomains ` 
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine") 
Start-DscConfiguration -Wait -Force -Verbose -ComputerName "dsc-testNode2" -Path $PSScriptRoot\AssertParentChildDomains ` 
-Credential (Get-Credential -Message "Local Admin Credentials on Remote Machine") 
 ```
