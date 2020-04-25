---
external help file: ActiveDirectoryDsc.Common-help.xml
Module Name: ActiveDirectoryDsc.Common
online version:
schema: 2.0.0
---

# Test-DscPropertyState

## SYNOPSIS
Compares the current and the desired value of a property.

## SYNTAX

```
Test-DscPropertyState [-Values] <Hashtable> [<CommonParameters>]
```

## DESCRIPTION
The Test-DscPropertyState function is used to compare the current and the desired value of a property.
A
boolean is returned the represent the result of the comparison.

## EXAMPLES

### EXAMPLE 1
```
Test-DscPropertyState -Values @{
```

CurrentValue = 'John'
    DesiredValue = 'Alice'
}

### EXAMPLE 2
```
Test-DscPropertyState -Values @{
```

CurrentValue = 1
    DesiredValue = 2
}

## PARAMETERS

### -Values
This is set to a hash table with the current value (the CurrentValue key) and desired value (the DesiredValue
key).

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Boolean
## NOTES

## RELATED LINKS
