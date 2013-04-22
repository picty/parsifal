open Lwt
open Parsifal
open PTypes

enum color_type (8, UnknownVal UnknownColorType) =
  | 0 -> CT_Grayscale, "grayscale"
  | 2 -> CT_RGB, "RGB"
  | 3 -> CT_Palette, "palette"
  | 4 -> CT_GrayscaleAlpha, "grayscale+alpha"
  | 6 -> CT_RGBAlpha, "RGV+alpha"


struct image_header = {
  width : uint32;
  height : uint32;
  bit_depth : uint8;
  color_type : color_type;
  compression_method : uint8;
  filter_method : uint8;
  interlace_method : uint8;
  (* TODO: Check consistency between bit_depth and color_type *)
}

union chunk_content [enrich] (UnparsedChunkContent) =
  | "IHDR" -> ImageHeader of image_header
  (* PLTE is only present for some values of color_type *)
  | "PLTE" -> Palette of list of array(3) of uint8
  | "IDATA" -> ImageData of binstring (* TODO *)
  | "IEND" -> ImageEnd

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
