open Ocamlbuild_plugin;;
open Command;;

dispatch begin function
  | After_rules ->
(*    flag ["link"; "native"; "ocaml"; "use_str"]
      (S[A"str.cmxa"]);

    flag ["link"; "byte"; "ocaml"; "program"; "use_str"]
      (S[A"str.cma"]); *)
()
  | _ -> ()
end
