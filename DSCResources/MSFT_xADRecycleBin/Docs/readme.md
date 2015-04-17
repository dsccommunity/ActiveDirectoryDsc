The xADRecycleBin DSC resource will enable the Active Directory Recycle Bin feature for the target forest.
This resource first verifies that the forest mode is Windows Server 2008 R2 or greater.  If the forest mode
is insufficient, then the resource will exit with an error message.  The change is executed against the 
Domain Naming Master FSMO of the forest.

Note: This resource is compatible with a Windows 2008 R2 or above target node.

xADRecycleBin resource has the following properties:
-	ForestFQDN:  Fully qualified domain name of forest to enable Active Directory Recycle Bin.
-	EnterpriseAdministratorCredential:  Credential with Enterprise Administrator rights to the forest.
-	RecycleBinEnabled:  Read-only. Returned by Get.
-	ForestMode:  Read-only. Returned by Get.

Example usage code is included in the resource subfolder:
[xActiveDirectory_xADRecycleBin.ps1](MSFT_xADRecycleBin\Examples\xActiveDirectory_xADRecycleBin.ps1)
