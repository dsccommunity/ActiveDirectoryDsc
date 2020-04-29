
# Get-ADDirectoryContext

## SYNOPSIS
Gets an Active Directory DirectoryContext object.

## SYNTAX

```
Get-ADDirectoryContext [-DirectoryContextType] <String> [[-Name] <String>] [[-Credential] <PSCredential>]
 [<CommonParameters>]
```

## DESCRIPTION
The Get-ADDirectoryContext function is used to get an Active Directory DirectoryContext object that represents
the desired context.

## EXAMPLES

### EXAMPLE 1
```
Get-ADDirectoryContext -DirectoryContextType 'Forest' -Name contoso.com
```

## PARAMETERS

### -Credential
Specifies the credentials to use when accessing the domain, or use the current user if not specified.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DirectoryContextType
Specifies the context type of the object to return.
Valid values are 'Domain', 'Forest',
'ApplicationPartition', 'ConfigurationSet' or 'DirectoryServer'.

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

### -Name
An optional parameter for the target of the directory context.
For the correct format for this parameter
depending on context type, see the article
https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.directorycontext?view=netframework-4.8

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

### System.DirectoryServices.ActiveDirectory.DirectoryContext
## NOTES

## RELATED LINKS
