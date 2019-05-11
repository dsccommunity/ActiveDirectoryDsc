# Running tests

## Integration tests in Hyper-V

The below steps assumes the virtual machines does not have access to the
Internet.

This requires at least one working domain controller.

<!--
1. Install [`git`](https://git-scm.com/download/win) using the default
   configuration. _This is used later to clone the test framework._
1. NOT NECESSARY: Copy any dependent modules to Modules-folder.
// -->

1. Copy Pester to a path in `$env:PSModulePath`.
1. Copy PSDepend to a path in `$env:PSModulePath`.
1. Copy resource module code to a local folder, e.g. `C:\source\xActiveDirectory`.
   _**NOTE:** Do not copy the resource being tested to a path that exist_
   _in `$env:PSModulePath`, that will generate an error that multiple_
   _modules exist on the node._
1. Copy the repository [DscResource.Tests](https://github.com/PowerShell/DscResource.Tests)
   to the root of the folder where the resource module code was copied,
   e.g. `C:\source\xActiveDirectory`.
1. Start a PowerShell prompt with elevated permissions.
1. Run
   ```powershell
   cd 'c:\source\xActiveDirectory'
   .\Assert-TestEnvironment.ps1 -Confirm
   ```
1. **IMPORTANT!** Answer 'No' on the first two questions, and answer
   'Yes' on the third question.
   ```plaintext
   Processing dependency
   Process the dependency 'RemoveTestFramework'?
   [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): n

   Processing dependency
   Process the dependency 'CloneTestFramework'?
   [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): n

   Processing dependency
   Process the dependency 'LoadDscResourceKitTypes'?
   [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): y
   ```
1. Run
   ```powershell
   Invoke-Pester .\Tests\Integration\MSFT_xADComputer.Integration.Tests.ps1
   ```
