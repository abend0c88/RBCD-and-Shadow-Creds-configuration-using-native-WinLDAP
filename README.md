# RBCD and Shadow Credentials Configuration Using Native WinLDAP

## Initial Situation

During a penetration test, I was running Responder on a network where LLMNR was actively used. A system administrator connected to a SQL Server instance using the `sa` account over a connection that did not enforce encryption. Responder captured the SQL authentication credentials, allowing me to access the instance with `sa` privileges.

See Microsoft's documentation on [configuring SQL Server encryption](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-sql-server-encryption).

What next? I enabled `xp_cmdshell` to identify the account under which commands were executed. It was `NT SERVICE\MSSQLSERVER`, the virtual service account used by the default SQL Server instance. How could I escalate from this service context to administrative control of the host?

One common approach is:

- Exploiting `SeImpersonatePrivilege` through a suitable Potato-style privilege escalation technique. Depending on the technique, this may involve RPC authentication coercion and named-pipe impersonation. Applicability depends on the Windows version, available services, and security controls.

On a domain-joined host, a virtual service account such as `NT SERVICE\MSSQLSERVER` normally uses the computer account for network authentication. This identity may therefore provide a path to configuring RBCD or Shadow Credentials on the computer object.

Possible options include:

- Triggering authentication to a WebDAV endpoint and relaying it to LDAP to configure RBCD. This depends on several prerequisites, including a running WebClient service and an LDAP endpoint that accepts the relayed authentication without enforcing the relevant protections.
- Using the TGT delegation trick, which requires adapting the referenced Beacon Object File into a standalone executable or using a compatible C2 environment.

Finally, could I use that context to modify the computer object's RBCD or Shadow Credentials attributes directly, provided that its permissions allowed it? Could I then use the resulting configuration against services on the same host, relying on native Windows APIs?

## SDSP — System.DirectoryServices.Protocols

This directory contains three scripts using the .NET `System.DirectoryServices.Protocols` library to:

- Read the RBCD attribute, `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Set the RBCD attribute. Some values are currently hardcoded and must be adapted before use.
- Delete the RBCD attribute.

Shadow Credentials support, involving the `msDS-KeyCredentialLink` attribute, TODO.

## wldap32.dll — Native WinLDAP API

An implementation using the native Windows LDAP API exposed by `wldap32.dll` TODO.

## S4U and Self-RBCD

The following PowerShell expression uses the `WindowsIdentity` constructor that accepts a user principal name (UPN):

```powershell
New-Object System.Security.Principal.WindowsIdentity($UserUpn)
```

On Windows, this constructor uses `LsaLogonUser` with `KERB_S4U_LOGON` to obtain a token for the specified identity through the Kerberos S4U logon mechanism. It does not, by itself, perform S4U2Proxy or apply impersonation to the current thread.

Using this mechanism with self-RBCD, where the computer account is allowed to delegate to services associated with that same account, remains to be investigated and implemented. Local impersonation and access to a service on the same host must be evaluated separately.

## References

- [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [TGT Delegation BOF by Connor McGarr](https://github.com/connormcgarr/tgtdelegation)
- [Configuring SQL Server Encryption](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-sql-server-encryption)
- [WindowsIdentity Constructors](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.-ctor)
- [KERB_S4U_LOGON](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_s4u_logon)
