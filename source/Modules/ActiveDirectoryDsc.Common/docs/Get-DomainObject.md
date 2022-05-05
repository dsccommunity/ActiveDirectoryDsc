
# Get-DomainObject

## SYNOPSIS
The Get-DomainObject function is used to get the domain object with retries, otherwise it returns $null.

## SYNTAX

```
Get-DomainObject [-Identity] <String> [[-Server] <String>] [[-Credential] <PSCredential>]
 [<CommonParameters>]
```

## DESCRIPTION
The Get-DomainObject function is used to get the domain object with retries, otherwise it returns $null.

## EXAMPLES

### EXAMPLE 1
```
Get-DomainObject -DomainName contoso.com
```

## PARAMETERS

### -Server
Specifies the Active Directory Domain Services instance to connect to, most commonly a Fully qualified domain name.

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

### -MaximumRetries
Specifies the maximum number of retries to attempt.

```yaml
Type: System.UInt32
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 15
Accept pipeline input: False
Accept wildcard characters: False
```

### -RetryIntervalInSeconds
Specifies the time to wait in seconds between retries attempts.

```yaml
Type: System.UInt32
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### -ErrorOnUnexpectedExceptions
Switch to indicate if the function should throw an exception on unexpected errors rather than returning null.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ErrorOnMaxRetries
Switch to indicate if the function should throw an exception when the maximum retries are exceeded.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Identity
Specifies an Active Directory domain object, most commonly a DNS domain name.

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

### System.DirectoryServices.ActiveDirectory.Domain
## NOTES
## RELATED LINKS
