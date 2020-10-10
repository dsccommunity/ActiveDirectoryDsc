
# Resolve-SecurityIdentifier

## SYNOPSIS
Resolves the Security Identifier (SID) of an Active Directory object based on a supplied SamAccountName.

## SYNTAX

```
Resolve-SecurityIdentifier [-SamAccountName] <String> [<CommonParameters>]
```

## DESCRIPTION
The Resolve-SecurityIdentifier function is used to get a System.String object representing the Security Identifier
(SID) translated from the specified SamAccountName.

## EXAMPLES

### EXAMPLE 1
```
Resolve-SecurityIdentifier -SamAccountName $adObject.SamAccountName
```

## PARAMETERS

### -SamAccountName
Specifies the Active Directory object SamAccountName to use for translation to a Security Identifier (SID).

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
See issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/619 for more information.

## RELATED LINKS
