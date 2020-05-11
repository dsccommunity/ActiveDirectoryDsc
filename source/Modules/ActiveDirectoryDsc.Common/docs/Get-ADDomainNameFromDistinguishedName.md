
# Get-ADDomainNameFromDistinguishedName

## SYNOPSIS
Converts an Active Directory distinguished name into a fully qualified domain name.

## SYNTAX

```
Get-ADDomainNameFromDistinguishedName [[-DistinguishedName] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Get-ADDomainNameFromDistinguishedName function is used to convert an Active Directory distinguished name
into a fully qualified domain name.

## EXAMPLES

### EXAMPLE 1
```
Get-ADDomainNameFromDistinguishedName -DistinguishedName 'CN=ExampleObject,OU=ExampleOU,DC=example,DC=com'
```

## PARAMETERS

### -DistinguishedName
Specifies the distinguished name to convert into the FQDN.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
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
Author: Robert D.
Biddle (https://github.com/RobBiddle)

## RELATED LINKS
