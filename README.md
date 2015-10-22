[![Build status](https://ci.appveyor.com/api/projects/status/p4jejr60jrgb8ity/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/xactivedirectory/branch/master)

# xActiveDirectory

The **xActiveDirectory** DSC resources allow you to configure and manage Active Directory.
Note: these resources do not presently install the RSAT tools.

## Contributing
Please check out common DSC Resource [contributing guidelines](https://github.com/PowerShell/xDscResources/blob/master/CONTRIBUTING.md).

## Description

The **xActiveDirectory** module contains the **xADDomain, xADDomainController, xADUser, xWaitForDomain, and ADDomainTrust** DSC Resources.
These DSC Resources allow you to configure new domains, child domains, and high availability domain controllers and establish cross-domain trusts.

## Resources

* **xADDomain** creates new Active Directory forest configurations and new Active Directory domain configurations.
* **xADDomainController** installs and configures domain controllers in Active Directory.
* **xADUser** modifies and removes Active Directory Users. 
* **xWaitForDomain** waits for new, remote domain to setup.
(Note: the RSAT tools will not be installed when these resources are used to configure AD.)
* **xADDomainTrust** establishes cross-domain trusts

### **xADDomain**

* **DomainName**: Name of the domain.
If no parent name is specified, this is the fully qualified domain name for the first domain in the forest.
* **ParentDomainName**: Name of the parent domain.
* **DomainAdministratorCredential**: Credentials used to query for domain existence.
Note: These are not used during domain creation.
(AD sets the localadmin credentials as new domain administrator credentials during setup.) 
* **SafemodeAdministratorPassword**: Password for the administrator account when the computer is started in Safe Mode.
* ** DnsDelegationCredential**: Credential used for creating DNS delegation.

### xADDomainController

* **DomainName**: The fully qualified domain name for the domain where the domain controller will be present.
* **DomainAdministratorCredential**: Specifies the credential for the account used to install the domain controller.
* **SafemodeAdministratorPassword**: Password for the administrator account when the computer is started in Safe Mode.

### xADUser

* **Ensure**: Specifies whether the given user is present or absent.
* **DomainName**: Name of the domain to which the user will be added.
* **UserName**: Name of the user.
* **Password**: Password value for the account.
* **DomainAdministratorCredential**: User account credentials used to perform the task.

### xWaitForADDomain

* **DomainName**: Name of the remote domain.
* **RetryIntervalSec**: Interval to check for the domain's existance.
* **RetryCount**: Maximum number of retries to check for the domain's existance.

### xADDomainTrust

* **Ensure**: Specifies whether the domain trust is present or absent 
* **TargetDomainAdministratorCredential**: Credentials to authenticate to the target domain 
* **TargetDomainName**: Name of the AD domain that is being trusted 
* **TrustType**: Type of trust 
* **TrustDirection**: Direction of trust, the values for which may be Bidirectional,Inbound, or Outbound 
* **SourceDomainName**: Name of the AD domain that is requesting the trust 

### xADRecycleBin
The xADRecycleBin DSC resource will enable the Active Directory Recycle Bin feature for the target forest. 
This resource first verifies that the forest mode is Windows Server 2008 R2 or greater.  If the forest mode 
is insufficient, then the resource will exit with an error message.  The change is executed against the  
Domain Naming Master FSMO of the forest. 
(Note: This resource is compatible with a Windows 2008 R2 or above target node. )
* **ForestFQDN**:  Fully qualified domain name of forest to enable Active Directory Recycle Bin. 
* **EnterpriseAdministratorCredential**:  Credential with Enterprise Administrator rights to the forest. 
* **RecycleBinEnabled**:  Read-only. Returned by Get. 
* **ForestMode**:  Read-only. Returned by Get. 

## Versions

### 2.7.0.0

* Added DNS flush in retry loop
* Bug fixes in xADDomain resource

### 2.6.0.0

* Removed xDscResourceDesigner tests (moved to common tests)

### 2.5.0.0

* Updated xADDomainTrust and xADRecycleBin tests

### 2.4.0.0

* Added xADRecycleBin resource
* Minor fixes for xADUser resource

### 2.3

* Added xADRecycleBin.
* Modified xADUser to include a write-verbose after user is removed when Absent.
* Corrected xADUser to successfully create a disabled user without a password.

### 2.2

* Modified xAdDomain and xAdDomainController to support Ensure as Present / Absent, rather than True/False.
Note: this may cause issues for existing scripts.
* Corrected return value to be a hashtable in both resources.

### 2.1.0.0

* Minor update: Get-TargetResource to use domain name instead of name.

### 2.0.0.0

* Updated release, which added the resource:
    * xADDomainTrust

### 1.0.0.0

* Initial release with the following resources:
    * xADDomain, xADDomainController, xADUser, and xWaitForDomain


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

In this example, we setup one-way trust between two domains.

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

### Enable the Active Directory Recycle Bin

In this example, we enable the Active Directory Recycle Bin.

```
Configuration Example_xADRecycleBin
{
Param(
    [parameter(Mandatory = $true)]
    [System.String]
    $ForestFQDN,

    [parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $EACredential 
)

    Import-DscResource -Module xActiveDirectory

    Node $AllNodes.NodeName
    {
        xADRecycleBin RecycleBin
        {
           EnterpriseAdministratorCredential = $EACredential
           ForestFQDN = $ForestFQDN
        }
    }
}

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = '2012r2-dc'
        }
    )
}

Example_xADRecycleBin -EACredential (Get-Credential contoso\administrator) -ForestFQDN 'contoso.com' -ConfigurationData $ConfigurationData

Start-DscConfiguration -Path .\Example_xADRecycleBin -Wait -Verbose
```
