
# Test-ADReplicationSite

## SYNOPSIS
Tests Active Directory replication site availablity.

## SYNTAX

```
Test-ADReplicationSite [-SiteName] <String> [-DomainName] <String> [-Credential] <PSCredential>
 [<CommonParameters>]
```

## DESCRIPTION
The Test-ADReplicationSite function is used to test Active Directory replication site availablity.
A boolean is
returned that represents the replication site availability.

## EXAMPLES

### EXAMPLE 1
```
Test-ADReplicationSite -SiteName Default -DomainName contoso.com
```

## PARAMETERS

### -Credential
Specifies the credentials to use when accessing the domain, or use the current user if not specified.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Specifies the domain name containing the replication site.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SiteName
Specifies the replication site name to test the availability of.

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

### System.Boolean
## NOTES

## RELATED LINKS
