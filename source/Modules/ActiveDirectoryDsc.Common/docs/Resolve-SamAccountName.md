
# Resolve-SamAccountName

## SYNOPSIS
Resolves the SamAccountName of an Active Directory object based on a supplied ObjectSid.

## SYNTAX

```
Resolve-SamAccountName [-ObjectSid] <String> [<CommonParameters>]
```

## DESCRIPTION
The Resolve-SamAccountName function is used to get a System.String object representing the SamAccountName
translated from the specified ObjectSid.
If a System.Security.Principal.IdentityNotMappedException exception
is thrown, then we assume it is an orphaned ForeignSecurityPrincipal and the ObjectSid value is returned back.

## EXAMPLES

### EXAMPLE 1
```
Resolve-SamAccountName -ObjectSid $adObject.objectSid
```

## PARAMETERS

### -ObjectSid
Specifies the Active Directory object security identifier to use for translation to a SamAccountName.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.String
## NOTES
This is a wrapper to allow test mocking of the calling function.
See issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/616 for more information.

## RELATED LINKS
