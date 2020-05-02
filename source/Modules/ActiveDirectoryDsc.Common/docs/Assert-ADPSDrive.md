
# Assert-ADPSDrive

## SYNOPSIS
Asserts if the AD PS Drive has been created, and creates one if not.

## SYNTAX

```
Assert-ADPSDrive [[-Root] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Assert-ADPSDrive function is used to assert if the AD PS Drive has been created, and creates one if not.

## EXAMPLES

### EXAMPLE 1
```
Assert-ADPSDrive
```

## PARAMETERS

### -Root
Specifies the AD path to which the drive is mapped.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: //RootDSE/
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
Throws an exception if the PS Drive cannot be created.

## RELATED LINKS
