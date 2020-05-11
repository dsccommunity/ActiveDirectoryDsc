
# Restore-ADCommonObject

## SYNOPSIS
Restores an AD object from the AD recyle bin.

## SYNTAX

```
Restore-ADCommonObject [-Identity] <String> [-ObjectClass] <String> [[-Credential] <PSCredential>]
 [[-Server] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Restore-ADCommonObject function is used to Restore an AD object from the AD recyle bin.
An ADObject is
returned that represents the restored object.

## EXAMPLES

### EXAMPLE 1
```
Restore-ADCommonObject -Identity User1 -ObjectClass User
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

### -Identity
Specifies the identity of the object to restore.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: UserName, GroupName, ComputerName, ServiceAccountName

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ObjectClass
Specifies the type of the AD object to restore.

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

### -Server
Specifies the name of the domain controller to use when accessing the domain.
If not specified, a domain
controller is discovered using the standard Active Directory discovery process.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: DomainController

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### Microsoft.ActiveDirectory.Management.ADObject
## NOTES

## RELATED LINKS
