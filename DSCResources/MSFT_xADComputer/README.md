# Description

The xADComputer DSC resource will manage computer accounts within Active Directory.

>**Note:** An Offline Domain Join (ODJ) request file will only be created
>when a computer account is first created in the domain. Setting an Offline
>Domain Join (ODJ) Request file path for a configuration that updates a
>computer account that already exists, or restore it from the recycle bin
>will not cause the Offline Domain Join (ODJ) request file to be created.

## Requirements

* Target machine must be running Windows Server 2008 R2 or later.
