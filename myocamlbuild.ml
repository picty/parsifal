open Ocamlbuild_plugin

;;

dispatch begin function
| After_rules ->
  dep  ["link"; "ocaml"; "use_socket"] ["libsocket.a"];
| _ -> ()
end
