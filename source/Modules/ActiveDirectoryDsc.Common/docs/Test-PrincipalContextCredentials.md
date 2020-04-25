---
external help file: ActiveDirectoryDsc.Common-help.xml
Module Name: ActiveDirectoryDsc.Common
online version:
schema: 2.0.0
---

# Test-PrincipalContextCredentials

## SYNOPSIS
Tests the validity of credentials using a PrincipalContext.

## SYNTAX

```
Test-PrincipalContextCredentials [-UserName] <String> [-Password] <PSCredential>
 [-PrincipalContext] <PrincipalContext> [-PasswordAuthentication] <String> [<CommonParameters>]
```

## DESCRIPTION
The Test-PrincipalContextCredentials function is used to test the validity of credentials using a
PrincipalContext.
A boolean is returned that represents the validity of the password.

## EXAMPLES

### EXAMPLE 1
```
Test-PrincipalContextCredentials -UserName 'user1' -Password $cred -PrincialContext $context
```

## PARAMETERS

### -Password
Specifies a new password value for the account.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PasswordAuthentication
Specifies the authentication context type to be used when testing the password.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PrincipalContext
Specifies the PrincipalContext object that the credential test will be performed using.

```yaml
Type: System.DirectoryServices.AccountManagement.PrincipalContext
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
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
This is a wrapper to allow test mocking of the calling function.

## RELATED LINKS
