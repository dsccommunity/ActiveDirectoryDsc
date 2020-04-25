---
external help file: ActiveDirectoryDsc.Common-help.xml
Module Name: ActiveDirectoryDsc.Common
online version:
schema: 2.0.0
---

# Compare-ResourcePropertyState

## SYNOPSIS
Compares current and desired values for any DSC resource.

## SYNTAX

```
Compare-ResourcePropertyState [-CurrentValues] <Hashtable> [-DesiredValues] <Hashtable>
 [[-Properties] <String[]>] [[-IgnoreProperties] <String[]>] [<CommonParameters>]
```

## DESCRIPTION
The Compare-ResourcePropertyState function is used to compare current and desired values for any DSC resource,
and return a hashtable with the result of the comparison.
An array of hashtables is returned containing the
results of the comparison with the following properties:

- ParameterName - The name of the parameter
- Expected - The expected value of the parameter
- Actual - The actual value of the parameter

## EXAMPLES

### EXAMPLE 1
```
Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters
```

## PARAMETERS

### -CurrentValues
The current values that should be compared to to desired values.
Normally the values returned from
Get-TargetResource.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DesiredValues
The values set in the configuration and is provided in the call to the functions *-TargetResource, and that
will be compared against current values.
Normally set to $PSBoundParameters.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IgnoreProperties
{{ Fill IgnoreProperties Description }}

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

### -Properties
An array of property names, from the keys provided in DesiredValues, that will be compared.
If this parameter
is left out, all the keys in the DesiredValues will be compared.

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

### System.Collections.Hashtable[]
## NOTES

## RELATED LINKS
