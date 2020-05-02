
# Start-ProcessWithTimeout

## SYNOPSIS
Starts a process with a timeout.

## SYNTAX

```
Start-ProcessWithTimeout [-FilePath] <String> [[-ArgumentList] <String[]>] [-Timeout] <UInt32>
 [<CommonParameters>]
```

## DESCRIPTION
The Start-ProcessWithTimeout function is used to start a process with a timeout.
An Int32 object is returned
representing the exit code of the started process.

## EXAMPLES

### EXAMPLE 1
```
Start-ProcessWithTimeout -FilePath 'djoin.exe' -ArgumentList '/PROVISION /DOMAIN contoso.com /MACHINE SRV1' -Timeout 300
```

## PARAMETERS

### -ArgumentList
Specifies he arguments that should be passed to the executable.

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

### -FilePath
Specifies the path to the executable to start.

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

### -Timeout
Specifies the timeout in seconds to wait for the process to finish.

```yaml
Type: System.UInt32
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: 0
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
