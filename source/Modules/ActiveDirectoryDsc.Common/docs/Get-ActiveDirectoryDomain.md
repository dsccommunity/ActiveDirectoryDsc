
# Get-ActiveDirectoryDomain

## SYNOPSIS
Gets a Domain object for the specified context.

## SYNTAX

```
Get-ActiveDirectoryDomain [-DirectoryContext] <DirectoryContext> [<CommonParameters>]
```

## DESCRIPTION
The Get-ActiveDirectoryDomain function is used to get a System.DirectoryServices.ActiveDirectory.Domain object
for the specified context, which is a class that represents an Active Directory Domain Services domain.

## EXAMPLES

### EXAMPLE 1
```
Get-ActiveDirectoryDomain -DirectoryContext $context
```

## PARAMETERS

### -DirectoryContext
Specifies the Active Directory context from which the domain object is returned.
Calling the
Get-ADDirectoryContext gets a value that can be provided in this parameter.

```yaml
Type: System.DirectoryServices.ActiveDirectory.DirectoryContext
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

### System.DirectoryServices.ActiveDirectory.Domain
## NOTES
This is a wrapper to allow test mocking of the calling function.
See issue https://github.com/PowerShell/ActiveDirectoryDsc/issues/324 for more information.

## RELATED LINKS
