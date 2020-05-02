
# ConvertFrom-TimeSpan

## SYNOPSIS
Converts a TimeSpan object into the number of seconds, minutes, hours or days.

## SYNTAX

```
ConvertFrom-TimeSpan [-TimeSpan] <TimeSpan> [-TimeSpanType] <String> [<CommonParameters>]
```

## DESCRIPTION
The ConvertFrom-TimeSpan function is used to Convert a TimeSpan object into an Integer containing the number of
seconds, minutes, hours or days within the timespan.

## EXAMPLES

### EXAMPLE 1
```
ConvertFrom-TimeSpan -TimeSpan (New-TimeSpan -Days 15) -TimeSpanType Seconds
```

Returns the number of seconds in 15 days.

## PARAMETERS

### -TimeSpan
Specifies the TimeSpan object to convert into an integer.

```yaml
Type: System.TimeSpan
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeSpanType
Specifies the unit of measure to be used in the conversion.

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

### System.Int32
## NOTES

## RELATED LINKS
