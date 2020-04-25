---
external help file: ActiveDirectoryDsc.Common-help.xml
Module Name: ActiveDirectoryDsc.Common
online version:
schema: 2.0.0
---

# Assert-MemberParameters

## SYNOPSIS
Assert the Members, MembersToInclude and MembersToExclude combination is valid.

## SYNTAX

```
Assert-MemberParameters [[-Members] <String[]>] [[-MembersToInclude] <String[]>]
 [[-MembersToExclude] <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The Assert-MemberParameters function is used to assert the Members, MembersToInclude and MembersToExclude
combination is valid.
If the combination is invalid, an InvalidArgumentError is raised.

## EXAMPLES

### EXAMPLE 1
```
Assert-MemberParameters -Members fred, bill
```

## PARAMETERS

### -Members
The Members to validate.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MembersToExclude
The MembersToExclude to validate.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MembersToInclude
The MembersToInclude to validate.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### None
## NOTES

## RELATED LINKS
