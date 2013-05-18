open Lwt
open Parsifal
open PTypes
open BasePTypes


(* TODO: Maybe this PType should be moved into parsifal_core? *)
(* azt_string reads a string until a null character arises *)
type azt_string = string

(* TODO: Use a buffer instead *)
let rec parse_azt_string input =
  let next_char = parse_uint8 input in
  if next_char = 0
  then ""
  else (String.make 1 (char_of_int next_char)) ^ (parse_azt_string input)

let dump_azt_string buf s =
  POutput.add_string buf s;
  POutput.add_char buf '\x00'

let value_of_azt_string s = VString (s, false)



(***********************************)
(* Enumerations and useful aliases *)
(***********************************)

enum color_type (8, UnknownVal UnknownColorType) =
| 0 -> Grayscale
| 0x02 -> Truecolor
| 0x03 -> Indexedcolor
| 0x04 -> GrayscaleWithAlphaChannel
| 0x06 -> TruecolorWithAlphaChannel

enum compression_method (8, UnknownVal UnknownCompressionMethod) =
| 0 -> Deflate

enum filter_method (8, UnknownVal UnknownFilterMethod) =
| 0 -> AdaptativeFilter

enum interlace_method (8, UnknownVal UnknownInterlaceMethod) =
| 0 -> NoInterlace
| 0x01 -> Adam7

enum rendering_intent (8, UnknownVal UnknownRenderingIntent) =
| 0 -> Perceptual
| 0x01 -> RelativeColorimetric
| 0x02 -> Saturation
| 0x03 -> AbsoluteColorimetric

enum compression_flag (8, UnknownVal UnknownCompressionFlag) =
| 0 -> NoCompression
| 0x01 -> Compression

enum pixel_physical_unit (8, UnknownVal UnknownPixelPhysicalUnit) =
| 0 -> Unknown
| 0x01 -> Meter

alias color_definition = array(3) of uint8
alias truecolor_definition = array(3) of uint16



(***************)
(* PNG Context *)
(***************)

(* For now, it only remembers the color_type parsed in IHDR *)
type png_context = {
  mutable ihdr_color_type : color_type;
}

let parse_png_context _input =
  { ihdr_color_type = UnknownColorType 0xff }

let parse_update_color_type ctx color_type _input =
  ctx.ihdr_color_type <- color_type



(*******************)
(* Critical Chunks *)
(*******************)

(* Image Header *)
struct image_header [param ctx] = {
  width : uint32;
  height : uint32;
  bit_depth : uint8;
  color_type : color_type;
  parse_checkpoint : update_color_type(ctx; color_type);
  compression_method : compression_method;
  filter_method : filter_method;
  interlace_method : interlace_method;
}


(* Image Data can not be treated as a chunk, since we must wait for *)
(* the concatenation of IDAT chunks to uncomress the zlib container *)



(********************)
(* Anscillary Chunk *)
(********************)

(* Image Transparency *)
union image_transparency_type [enrich] (UnparsedChunkContent) =
| Grayscale -> GrayscaleTransparency of uint16
| Truecolor -> TruecolorTransparency of truecolor_definition
| Indexedcolor -> IndexedcolorTransparency of list of uint8
  (* One for each palette entry (default is 0xff [opaque] for the remaining) *)


(* Image Chromaticity *)
(* TODO: the value should be divided by 1000 *)
struct image_chromaticity = {
  white_chromaticity_x : uint32;
  white_chromaticity_y : uint32;
  red_chromaticity_x : uint32;
  red_chromaticity_y : uint32;
  green_chromaticity_x : uint32;
  green_chromaticity_y : uint32;
  blue_chromaticity_x : uint32;
  blue_chromaticity_y : uint32;
}


(* Image embedded ICC profile *)
(* TODO: should be uncompressed *)
struct image_embedded_profile = {
  embedded_profile_name : azt_string;
  embedded_profile_compression_method : uint8;
  _embedded_profile_compress : binstring;
}


(* Image significant bit - To recover the real image bitdepth *)
union image_significant_bit_type [enrich] (UnparsedChunkContent) =
| Grayscale -> GrayscaleSignificantBit of uint8
| Truecolor -> TruecolorSignificantBit of array(3) of uint8
| Indexedcolor -> IndexedcolorSignificantBit of array(3) of uint8
| GrayscaleWithAlphaChannel -> GrayscaleWithAlphaChannelSignificantBit of array(2) of uint8
| TruecolorWithAlphaChannel -> TruecolorWithAlphaChannelSignificantBit of array(4) of uint8


(* Image standard RGB profile *)
(* TODO...*)
struct image_standard_rgb_profile = {
  rendering_intent : rendering_intent;
}


(* Image textual data - Latin-1 *)
struct image_textual_data = {
  key_word : length_constrained_container(AtMost 80) of azt_string;
  text : string;
}

let value_of_image_textual_data t = VString (t.key_word ^ ": " ^ t.text, false)


(* Image compressed textual data - Latin-1 *)
(* TODO: Uncompress *)
struct image_compressed_textual_data = {
  key_word : length_constrained_container(AtMost 80) of azt_string;
  textual_compression_method : uint8;
  text_compress : ZLib.zlib_container of string;
}

let value_of_image_compressed_textual_data t = VString (t.key_word ^ ": " ^ t.text_compress, false)


(* Image international textual data *)
(* String: ...UTF-8... ? *)
struct image_international_textual_data = {
  key_word : length_constrained_container(AtMost 80) of azt_string;
  compression_flag : compression_flag;
  compression_method : compression_method;
  language_tag : azt_string;
  translated_keyword : azt_string;
  text : string;
}


(* Image background color - background to apply *)
union image_background_color_type [enrich] (UnparsedChunkContent) =
| Grayscale -> GrayscaleBackgroundColor of uint16 (* the value uses 16 bits but only some of them may be signifiant *)
| Truecolor -> TruecolorBackgroundColor of truecolor_definition
| Indexedcolor -> IndexedcolorBackgroundColor of uint8 (* Palette index *)
| GrayscaleWithAlphaChannel -> GrayscaleWithAlphaChannelBackgroundColor of uint16
| TruecolorWithAlphaChannel -> TruecolorWithAlphaChannelBackgroundColor of truecolor_definition


(* Image physical pixel dimension - ratio - pixe number by unit *)
struct image_physical_pixel_dimension = {
  pixel_per_unit_x : uint32;
  pixel_per_unit_y : uint32;
  pixel_physical_unit : pixel_physical_unit;
}

(* Image suggested palette - used by the system when truecolor is not supported *)
(*struct image_suggested_palette = {
  palette_name : azt_string;
  bitdepth : uint8; (* 8 or 16 *)
  red_composante : (* Depends on bitdepth: 1 or 2 bytes *)
  green_composante : (* Depends on bitdepth: 1 or 2 bytes *)
  blue_composante : (* Depends on bitdepth: 1 or 2 bytes *)
  alpha_composante : (* Depends on bitdepth: 1 or 2 bytes *)
  color_frequency : uint16;
}*)


(* Image time - Last modification date *)
struct image_time = {
  year : uint16;
  month : uint8;
  day : uint8;
  hour : uint8;
  minute : uint8;
  second : uint8;
}

let string_of_image_time t =
  Printf.sprintf "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d"
    t.year t.month t.day t.hour t.minute t.second

let value_of_image_time t = VRecord [
  "@name", VString ("image_time", false);
  "@string_of", VString (string_of_image_time t, false);
  "year", VSimpleInt t.year;
  "month", VSimpleInt t.month;
  "day", VSimpleInt t.day;
  "hour", VSimpleInt t.hour;
  "minute", VSimpleInt t.minute;
  "second", VSimpleInt t.second;
]


union chunk_content [enrich;param ctx] (UnparsedChunkContent) =
| "IHDR" -> ImageHeader of image_header(ctx)
| "IDAT" -> ImageData of binstring
| "IEND" -> ImageEnd
| "PLTE" -> ImagePalette of list of color_definition
| "gAMA" -> ImageGama of uint32 (*Image Gama -TODO: controle 4 octets - divisé par 10000*)
| "tRNS" -> ImageTransparency of image_transparency_type(ctx.ihdr_color_type)
| "cHRM" -> ImageChromaticity of image_chromaticity
| "iCCP" -> ImageEmbeddedProfile of image_embedded_profile
| "sBIT" -> ImageSignificantBit of image_significant_bit_type(ctx.ihdr_color_type)
| "sRGB" -> ImageStandardRGBProfile of image_standard_rgb_profile
| "tEXt" -> ImageTextualData of image_textual_data
| "zTXt" -> ImageCompressedTextualDatat of image_compressed_textual_data
| "iTXt" -> ImageInternationalTextualData of image_international_textual_data
| "bKGD" -> ImageBackgroundClour of image_background_color_type(ctx.ihdr_color_type)
| "hIST" -> ImageHistogramme of list of uint16
| "pHYs" -> ImagePhysicalPixelDimensions of image_physical_pixel_dimension
(*| "sPLT" -> ImageSuggestedPalette of image_suggested_palette*)
| "tIME" -> ImageTime of image_time



(* Chunk definition, with a context *)
struct chunk [param ctx] = {
  chunk_size : uint32;
  chunk_type : string(4);
  chunk_data : container(chunk_size) of chunk_content(ctx;chunk_type);
  chunk_crc : uint32;
}

(* PNG global structure *)
struct png_file = {
  parse_checkpoint ctx : png_context;
  png_magic : magic("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a");
  chunks : list of chunk(ctx);
}
