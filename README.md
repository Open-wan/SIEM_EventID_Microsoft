# SIEM_EventID_Microsoft

### Mise en oeuvre d'un SIEM - Evènnements Windows à surveiller

La bible : https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx

### Syntaxe GRAYLOG:
https://docs.graylog.org/en/4.0/pages/searching/query_language.html
* Messages that include the term ssh: ssh
* Messages that include the term ssh or login: ssh login
* Messages that include the exact phrase ssh login: "ssh login"
* Messages where the field type includes ssh: type:ssh
* Messages where the field type includes ssh or login: type:(ssh OR login)
* Messages that have the field type: _exists_:type
* Messages that do not have the field type: NOT _exists_:type
* Messages that match regular expression ethernet[0-9]+: /ethernet[0-9]+/
* Wildcards: Use ? to replace a single character or * to replace zero or more characters:
* Range queries: 
	* http_response_code:[500 TO 504]   http_response_code:{400 TO 404}
	* http_response_code:>400   http_response_code:>=400   http_response_code:(>=400 AND <500)
	* timestamp:["2019-07-23 09:53:08.175" TO "2019-07-23 09:53:08.575"]


Event ID  | Description
------- | -------------
1006	| MALWAREPROTECTION_MALWARE_DETECTED (Windows Defender)
1007	| MALWAREPROTECTION_MALWARE_ACTION_TAKEN
1008	| MALWAREPROTECTION_MALWARE_ACTION_FAILED
------- | -------------
1102	| The audit log was cleared 
------- | -------------
4624 	| An account was successfully logged on (NTLM)
        | RDP : (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:4624 AND winlogbeat_event_data_LogonType:10 AND NOT winlogbeat_event_data_IpAddress:10.32.1.*
	| template IP : ${source.winlogbeat_event_data_IpAddress}
	| template UserName : ${source.winlogbeat_event_data_TargetUserName}
4625 	| An account failed to log on (NTLM)
	| * si > 60 events en 1 mn : (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:4625
	|	* Search within 1 minutes Execute search every 1 minutes Create Events if count() > 60
		* template IP : ${source.winlogbeat_event_data_IpAddress}
		* template UserName : ${source.winlogbeat_event_data_TargetUserName}
	| * si user admin* : (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:(4625 OR 4771) AND winlogbeat_event_data_TargetUserName:admin*
	|	* template IP : ${source.winlogbeat_event_data_IpAddress}
		* template UserName : ${source.winlogbeat_event_data_TargetUserName}
4634 	| An account was logged off
4648	| Account Login with Explicit Credentials	(Run As)
	| * (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:4648 AND winlogbeat_event_data_TargetUserName:admin*
	|	* template IP : ${source.winlogbeat_event_data_IpAddress}
	|	* template UserName : ${source.winlogbeat_event_data_TargetUserName}
4663 	| An attempt was made to access an object
	| * source:SERV04 AND winlogbeat_event_id:4663	****FAIT****
	|	* Group by Field(s) winlogbeat_event_data_SubjectUserName
		* Execute search every 1 minutes Create Events if count() > 50
------- | -------------
4698	| A Scheduled Task Was Created
4696	| A primary token was assigned to process (Scheduled task)
------- | -------------
4720 	| A user account was created
4725 	| A user account was disabled
4726 	| A user account was deleted
4728 	| A member was added to a security-enabled global group
4732 	| A member was added to a security-enabled local group
------- | -------------
4742	| ANONYMOUS LOGON
------- | -------------
4768 	| A Kerberos authentication ticket (TGT) was requested
4769 	| A Kerberos service ticket was requested
	| * (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:4769 AND winlogbeat_event_data_TargetUserName:admin*
------- | -------------
4771 	| Kerberos pre-authentication failed
4772 	| A Kerberos authentication ticket request failed
4773 	| A Kerberos service ticket request failed
	| * (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:4773
------- | -------------
4776 	| The domain controller attempted to validate the credentials for an account
4777 	| The domain controller failed to validate the credentials for an account
------- | -------------
5829 (5805 + 5827-5831)	| ZeroLogon - connexions non sécurisées
			|* (source:PUSERV02 OR source:PUSERV01) AND winlogbeat_event_id:5805
			|	* Template ${source.message}
------- | -------------
7030 	| Service Creation Errors
7045 	| Service Creation

One of the useful information that Successful/Failed Logon event provide is how the user/process tried to logon  (Logon Type ) but Windows display this information as a number and here is a list of the logon type and their explanation
Logon Type | Explanation
---------- | ------------
2 	   | Logon via console
3 	   | Network Logon, A user or computer logged on to this computer from the network.
4 	   | Batch logon
5 	   | Windows Service Logon
7 	   | Credentials used to unlock screen
8 	   | Network logon sending credentials (cleartext)
9 	   | Different credentials used than logged on user
10 	   | Remote interactive logon (RDP)
11 	   | Cached credentials used to logon
12 	   | Cached remote interactive
13 	   | Cached unlock (Similar to logon type 7)
 
We can also add

Logon failure events
*    0xC0000064 User name does not exist
*    0xC000006A User name is correct but the password is wrong
*    0xC0000234 User is currently locked out
*    0xC0000072 Account is currently disabled
*    0xC000006F User tried to logon outside his day of week or time of day restrictions
*    0xC0000070 Workstation restriction
*    0xC00000193 Account expiration
*    0xC0000071 Expired password
*    0xC0000133 Clocks between DC and other computer too far out of sync
*    0xC0000224 User is required to change password at next logon
*    0xC0000225 Evidently a bug in Windows and not a risk
*    0xC000015b “The user has not been granted the requested logon”

Logon sessions
*    4647 user initiated logon
*    4800 Workstation Locked
*    4801 Workstation unlocked
*    4802 Screen saver loaded
*    4803 Screen saver dismissed
*    4778 RDP reconnected
*    4779 RDP disconnected

User account changes
*    4720 Created
*    4722 Enabled
*    4723 User changed own password
*    4724 Privileged User changed this user’s password
*    4725 Disabled
*    4726 Deleted
*    4738 Changed
*    4740 Locked out
*    4767 Unlocked
*    4781 Name change
