
# Remove-DuplicateMembers

## SYNOPSIS
Removes duplicate members from a string array.

## SYNTAX

```
Remove-DuplicateMembers [[-Members] <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The Remove-DuplicateMembers function is used to remove duplicate members from a string array.
The comparison
is case insensitive.
A string array is returned containing the resultant members.

## EXAMPLES

### EXAMPLE 1
```
Remove-DuplicateMembers -Members fred, bill, bill
```

## PARAMETERS

### -Members
Specifies the array of members to remove duplicates from.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.String[]
## NOTES

## RELATED LINKS
