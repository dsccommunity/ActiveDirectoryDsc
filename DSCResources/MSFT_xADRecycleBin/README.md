# Description

The ADRecycleBin DSC resource will enable the Active Directory Recycle Bin feature for the target forest.
This resource first verifies that the forest mode is Windows Server 2008 R2 or greater.  If the forest mode
is insufficient, then the resource will exit with an error message.  The change is executed against the
Domain Naming Master FSMO of the forest.

## Requirements

* Target machine must be running Windows Server 2008 R2 or later.
