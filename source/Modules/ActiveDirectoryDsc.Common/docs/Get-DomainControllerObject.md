
# Get-DomainControllerObject

## SYNOPSIS
Gets the domain controller object if the node is a domain controller.

## SYNTAX

```
Get-DomainControllerObject [-DomainName] <String> [[-ComputerName] <String>] [[-Credential] <PSCredential>]
 [<CommonParameters>]
```

## DESCRIPTION
The Get-DomainControllerObject function is used to get the domain controller object if the node is a domain
controller, otherwise it returns $null.

## EXAMPLES

### EXAMPLE 1
```
Get-DomainControllerObject -DomainName contoso.com
```

## PARAMETERS

### -ComputerName
Specifies the name of the node to return the domain controller object for.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: $env:COMPUTERNAME
Accept pipeline input: False
Accept wildcard characters: False
```

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

### -DomainName
Specifies the name of the domain that should contain the domain controller.

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

### Microsoft.ActiveDirectory.Management.ADDomainController
## NOTES
Throws an exception of Microsoft.ActiveDirectory.Management.ADServerDownException if the domain cannot be
contacted.

## RELATED LINKS
