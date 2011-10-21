let _ =
  print_endline (Common.hexdump (Crypto.md5sum ""));;
  print_endline (Common.hexdump (Crypto.sha1sum ""));;
