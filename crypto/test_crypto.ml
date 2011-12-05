let _ =
  print_endline (Common.hexdump (Crypto.md5sum ""));;
  print_endline (Common.hexdump (Crypto.sha1sum ""));;

  print_endline (Common.hexdump (Crypto.exp_mod "\x10\x20\x30" "\x01\x00\x01" "\x13\x21\x12"));;
