
# Test-Password

## SYNOPSIS
Tests the validity of a user's password.

## SYNTAX

```
Test-Password [-DomainName] <String> [-UserName] <String> [-Password] <PSCredential>
 [[-Credential] <PSCredential>] [-PasswordAuthentication] <String> [<CommonParameters>]
```

## DESCRIPTION
The Test-Password funtion is used to test the validity of a user's password.
A boolean is returned that
represents the validity of the password.

## EXAMPLES

### EXAMPLE 1
```
Test-Password -DomainName contoso.com -UserName 'user1' -Password $cred
```

## PARAMETERS

### -Credential
Specifies the credentials to use when accessing the domain, or use the current user if not specified.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Specifies the name of the domain where the user account is located (only used if password is managed).

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

### -Password
Specifies a new password value for the account.

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

### -PasswordAuthentication
Specifies the authentication context type used when testing passwords.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserName
Specifies the Security Account Manager (SAM) account name of the user (ldapDisplayName 'sAMAccountName').

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Boolean
## NOTES

## RELATED LINKS
