
# Test-Members

## SYNOPSIS
Tests Members of an array.

## SYNTAX

```
Test-Members [[-ExistingMembers] <String[]>] [[-Members] <String[]>] [[-MembersToInclude] <String[]>]
 [[-MembersToExclude] <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The Test-Members function is used to test whether the existing array members match the defined explicit array
and include/exclude the specified members.
A boolean is returned that represents if the existing array members
match.

## EXAMPLES

### EXAMPLE 1
```
Test-Members -ExistingMembers fred, bill -Members fred, bill
```

## PARAMETERS

### -ExistingMembers
Specifies existing array members.

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

### -Members
Specifies explicit array members.

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

### -MembersToExclude
Specifies excluded array members.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MembersToInclude
Specifies compulsory array members.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Boolean
## NOTES

## RELATED LINKS
