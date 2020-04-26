
# Resolve-DomainFQDN

## SYNOPSIS
Resolves a fully qualified domain name.

## SYNTAX

```
Resolve-DomainFQDN [-DomainName] <String> [[-ParentDomainName] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Resolve-DomainFQDN function is used to resolve a fully qualified domain name by appending the domain name
to the parent domain name.

## EXAMPLES

### EXAMPLE 1
```
Get-DomainName -DomainName 'child' -ParentDomainName 'contoso.com'
```

## PARAMETERS

### -DomainName
The domain name to append to the ParentDomainName.

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

### -ParentDomainName
The parent domain name.

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

### System.String
## NOTES

## RELATED LINKS
