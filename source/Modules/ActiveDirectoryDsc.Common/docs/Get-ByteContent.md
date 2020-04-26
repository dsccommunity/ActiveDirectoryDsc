
# Get-ByteContent

## SYNOPSIS
Gets the contents of a file as a byte array.

## SYNTAX

```
Get-ByteContent [-Path] <String> [<CommonParameters>]
```

## DESCRIPTION
The Get-ByteContent function is used to get the contents of a file as a byte array.

## EXAMPLES

### EXAMPLE 1
```
Get-ByteContent -Path $path
```

## PARAMETERS

### -Path
Specifies the path to an item.

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

### none
## OUTPUTS

### System.Byte[]
## NOTES

## RELATED LINKS
