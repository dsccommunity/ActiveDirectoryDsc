# ActiveDirectoryDsc

This module contains DSC resources for the deployment and
configuration of Active Directory.

These DSC resources allow you to configure new domains, child domains, and high
availability domain controllers, establish cross-domain trusts and manage users,
groups and OUs.

[![Build Status](https://dev.azure.com/dsccommunity/ActiveDirectoryDsc/_apis/build/status/dsccommunity.ActiveDirectoryDsc?branchName=main)](https://dev.azure.com/dsccommunity/ActiveDirectoryDsc/_build/latest?definitionId=13&branchName=main)
![Azure DevOps coverage (branch)](https://img.shields.io/azure-devops/coverage/dsccommunity/ActiveDirectoryDsc/13/main)
[![codecov](https://codecov.io/gh/dsccommunity/ActiveDirectoryDsc/branch/main/graph/badge.svg)](https://codecov.io/gh/dsccommunity/ActiveDirectoryDsc)
[![Azure DevOps tests](https://img.shields.io/azure-devops/tests/dsccommunity/ActiveDirectoryDsc/13/main)](https://dsccommunity.visualstudio.com/ActiveDirectoryDsc/_test/analytics?definitionId=13&contextType=build)
[![PowerShell Gallery (with prereleases)](https://img.shields.io/powershellgallery/vpre/ActiveDirectoryDsc?label=ActiveDirectoryDsc%20Preview)](https://www.powershellgallery.com/packages/ActiveDirectoryDsc/)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ActiveDirectoryDsc?label=ActiveDirectoryDsc)](https://www.powershellgallery.com/packages/ActiveDirectoryDsc/)

## Code of Conduct

This project has adopted this [Code of Conduct](CODE_OF_CONDUCT.md).

## Releases

For each merge to the branch `main` a preview release will be
deployed to [PowerShell Gallery](https://www.powershellgallery.com/).
Periodically a release version tag will be pushed which will deploy a
full release to [PowerShell Gallery](https://www.powershellgallery.com/).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

## Documentation

The documentation can be found in the [ActiveDirectoryDsc Wiki](https://github.com/dsccommunity/ActiveDirectoryDsc/wiki).
The DSC resources schema files is used to automatically update the
documentation on each PR merge.

### Examples

You can review the [Examples](/source/Examples) directory in the ActiveDirectoryDsc module
for some general use scenarios for all of the resources that are in the module.

The resource examples are also available in the [ActiveDirectoryDsc Wiki](https://github.com/dsccommunity/ActiveDirectoryDsc/wiki).
