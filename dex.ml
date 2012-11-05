open Parsifal

exception Pouet

let check_header_size = function
  | 0x70 -> ()
  | _ -> raise Pouet

(* TODO: Auto-generate little and big endian variants when asked *)
(* TODO: Add array to the expressiveness *)


struct file_content = {
  header_size : uint32;
  check_header_size : check of check_header_size (header_size);
  endian_tag : 
}

struct header_item [top] = {
  magic : magic ("dex\n035\0x00");
  checksum : uint32;
  signature : binstring(20);
  file_size : uint32;
  file_content : container(file_size - 36) of file_content;
}
