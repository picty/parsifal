let channels_of_socket server_addr port =
  let sockaddr = Unix.ADDR_INET(server_addr,port) in
  let domain = Unix.PF_INET in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  try
    Unix.connect sock sockaddr;
    (Unix.in_channel_of_descr sock , Unix.out_channel_of_descr sock)
  with exn -> Unix.close sock ; raise exn ;;

let _ =
  let i, o = channels_of_socket (Unix.inet_addr_of_string "209.85.148.99") 80 in
  output_string o "GET /\n";
  flush o;
  begin
    try
      while true do
	let line = input_line i in
	print_endline line
      done
    with End_of_file -> ()
  end
    
