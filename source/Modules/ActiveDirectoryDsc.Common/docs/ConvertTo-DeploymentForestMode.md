
# ConvertTo-DeploymentForestMode

## SYNOPSIS
Converts a ModeId or ADForestMode object to a ForestMode object.

## SYNTAX

### ById
```
ConvertTo-DeploymentForestMode -ModeId <UInt16> [<CommonParameters>]
```

### ByName
```
ConvertTo-DeploymentForestMode -Mode <ADForestMode> [<CommonParameters>]
```

## DESCRIPTION
The ConvertTo-DeploymentForestMode function is used to convert a
Microsoft.ActiveDirectory.Management.ADForestMode object or a ModeId to a
Microsoft.DirectoryServices.Deployment.Types.ForestMode object.

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-DeploymentForestMode -Mode $adForestMode
```

## PARAMETERS

### -Mode
Specifies the Microsoft.ActiveDirectory.Management.ADForestMode value to convert to a
Microsoft.DirectoryServices.Deployment.Types.ForestMode type.

```yaml
Type: System.Nullable`1[Microsoft.ActiveDirectory.Management.ADForestMode]
Parameter Sets: ByName
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ModeId
Specifies the ModeId value to convert to a Microsoft.DirectoryServices.Deployment.Types.ForestMode type.

```yaml
Type: System.UInt16
Parameter Sets: ById
Aliases:

Required: True
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### Microsoft.DirectoryServices.Deployment.Types.ForestMode
## NOTES

## RELATED LINKS
