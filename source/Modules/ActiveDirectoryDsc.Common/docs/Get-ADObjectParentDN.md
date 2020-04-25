---
external help file: ActiveDirectoryDsc.Common-help.xml
Module Name: ActiveDirectoryDsc.Common
online version:
schema: 2.0.0
---

# Get-ADObjectParentDN

## SYNOPSIS
Gets an Active Directory object parent's distinguished name.

## SYNTAX

```
Get-ADObjectParentDN [-DN] <String> [<CommonParameters>]
```

## DESCRIPTION
The Get-ADObjectParentDN function is used to get an Active Directory object parent's distinguished name.

## EXAMPLES

### EXAMPLE 1
```
Get-ADObjectParentDN -DN CN=User1,CN=Users,DC=contoso,DC=com
```

Returns CN=Users,DC=contoso,DC=com

## PARAMETERS

### -DN
The distinguished name of the object to return the parent from.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.String
## NOTES

## RELATED LINKS
