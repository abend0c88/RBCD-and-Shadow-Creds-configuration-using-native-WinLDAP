# RBCD-and-Shadow-Creds-configuration-using-native-WinLDAP


## Initial situation
During a pentest I was running Responder and llmnr was activily used in the network. a sysadmin used the sa account of mssql which was running without encrytion (https://learn.microsoft.com/fr-fr/sql/database-engine/configure-windows/configure-sql-server-encryption). Result, the clear credentials poped up in responder allowing me to fully access the mssql service!

Then what? I enble xp_cmdshell to see under which service account it was running. it was a default generic account **nt service\mssqlserver**. So then how to fully compromise the server?

The basic technics kown are:

* Using the **SeImpersonatePrivilege** with one of the **Potatoes Privilege Escalation**, but mainly with MS-RPRN/EFS with named pipes, need av/edr bypass
* Adding a DNS name then leverage an enabled **WebDAV client** with xp_dirtree "\\monnomdns@80\random" to relay to a ldap with no-sining, a lot of if
* TGT Deleg trick, extracting TGS-REP with DELEGATE flag and Session key to rebuilt offline the TGT, seems good but still need a C2 or refactoring the existing beacon to exe.

Beyond all these possibilities, that making me painful was the generic accounts are using the domain machine account to authenticate in AD so can I directly set the RBCD or Shadow cred attirbutes? Can even using it locally? with the native Windows features? 

Having a quick research the answer was for sure!

## SDSP 
.NET lib

## wldap32.dll
Win API

## References

* https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
* https://github.com/connormcgarr/tgtdelegation