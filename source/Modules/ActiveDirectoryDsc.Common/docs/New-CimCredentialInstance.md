
# New-CimCredentialInstance

## SYNOPSIS
Creates a new MSFT_Credential CIM instance credential object.

## SYNTAX

```
New-CimCredentialInstance [-Credential] <PSCredential> [<CommonParameters>]
```

## DESCRIPTION
The New-CimCredentialInstance function is used to create a new MSFT_Credential CIM instance credential object
to be used when returning credential objects from Get-TargetResource.
This creates a credential object without
the password.

## EXAMPLES

### EXAMPLE 1
```
New-CimCredentialInstance -Credential $Cred
```

## PARAMETERS

### -Credential
Specifies the PSCredential object to return as a MSFT_Credential CIM instance credential object.

```yaml
Type: System.Management.Automation.PSCredential
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

### Microsoft.Management.Infrastructure.CimInstance
## NOTES
When returning a PSCredential object from Get-TargetResource, the credential object does not contain the
username.
The object is empty.

| Password | UserName | PSComputerName |
| -------- | -------- | -------------- |
|          |          | localhost      |

When the MSFT_Credential CIM instance credential object is returned by the Get-TargetResource then the
credential object contains the values provided in the object.

| Password | UserName           | PSComputerName |
| -------- | ------------------ | -------------- |
|          |COMPANY\TestAccount | localhost      |

## RELATED LINKS
