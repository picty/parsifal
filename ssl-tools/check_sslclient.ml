(* check_sslclient: TODO

Check the version proposed?

Record checks: same as check_sslserver

[...]

Check the different versions to write 0 in DHE
Check the client avoids DHE values in {-1;0;1}

Check how subject naming is handled
 - multiple CN
 - wildcard
 - empty subject
 - IP in SAN/IPAddress
 - IP in SAN/URL
 - IP in SAN/DNSName
 -  does SAN overrid CN?)

Check wether the presence of \x00 works in CN/SAN/etc.

*)
