
# Convert-PropertyMapToObjectProperties

## SYNOPSIS
Converts a hashtable containing the parameter to property mappings to an array of properties.

## SYNTAX

```
Convert-PropertyMapToObjectProperties [-PropertyMap] <Array> [<CommonParameters>]
```

## DESCRIPTION
The Convert-PropertyMapToObjectProperties function is used to convert a hashtable containing the parameter to
property mappings to an array of properties that can be used to call cmdlets that supports the parameter
Properties.

## EXAMPLES

### EXAMPLE 1
```
Convert-PropertyMapToObjectProperties -PropertyMap $computerObjectPropertyMap
```

## PARAMETERS

### -PropertyMap
Specifies the property map, as an array of hashtables, to convert to a properties array.

```yaml
Type: System.Array
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

### System.Array
## NOTES

## RELATED LINKS
