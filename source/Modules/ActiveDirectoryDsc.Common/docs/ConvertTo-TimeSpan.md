
# ConvertTo-TimeSpan

## SYNOPSIS
Converts a specified time period into a TimeSpan object.

## SYNTAX

```
ConvertTo-TimeSpan [-TimeSpan] <UInt32> [-TimeSpanType] <String> [<CommonParameters>]
```

## DESCRIPTION
The ConvertTo-TimeSpan function is used to convert a specified time period in seconds, minutes, hours or days
into a TimeSpan object.

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-TimeSpan -TimeSpan 60 -TimeSpanType Minutes
```

## PARAMETERS

### -TimeSpan
Specifies the length of time to use for the time span.

```yaml
Type: System.UInt32
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeSpanType
Specifies the units of measure in the TimeSpan parameter.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
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

### System.TimeSpan
## NOTES

## RELATED LINKS
