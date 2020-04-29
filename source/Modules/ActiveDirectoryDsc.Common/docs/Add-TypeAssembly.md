
# Add-TypeAssembly

## SYNOPSIS
Adds the assembly to the PowerShell session.

## SYNTAX

```
Add-TypeAssembly [-AssemblyName] <String> [[-TypeName] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Add-TypeAssembly function is used to Add the assembly to the PowerShell session, optionally after a check
if the type is missing.

## EXAMPLES

### EXAMPLE 1
```
Add-TypeAssembly -AssemblyName 'System.DirectoryServices.AccountManagement' -TypeName 'System.DirectoryServices.AccountManagement.PrincipalContext'
```

## PARAMETERS

### -AssemblyName
Specifies the assembly to load into the PowerShell session.

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

### -TypeName
Specifies an optional parameter to check if the type exist, if it exist then the assembly is not loaded again.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
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

### None
## NOTES

## RELATED LINKS
