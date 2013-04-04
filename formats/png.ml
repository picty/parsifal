open Lwt
open Parsifal
open PTypes

struct image_header = {
  width : uint32;
  height : uint32;
  bit_depth : uint8;
  color_type : uint8;
  compression_method : uint8;
  filter_method : uint8;
  interlace_method : uint8;
}

union chunk_content [enrich] (UnparsedChunkContent) =
  | "IHDR" -> ImageHeader of image_header

struct chunk [with_lwt] = {
  chunk_size : uint32;
  chunk_type : string(4);
  chunk_data : container(chunk_size) of chunk_content(chunk_type);
  chunk_crc : uint32;
}

struct png_file [with_lwt] = {
  png_magic : magic("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a");
  chunks : list of chunk;
}
