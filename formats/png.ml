open Lwt
open Parsifal
open PTypes
open BasePTypes



(*azt - decoupe au caractère 0x00 soit en entier: 0*)
type azt_string = string

let rec parse_azt_string input =
  let next_char = parse_uint8 input in
  if next_char = 0
  then ""
  else (String.make 1 (char_of_int next_char)) ^ (parse_azt_string input)

let dump_azt_string buf s =
  POutput.add_string buf s;
  POutput.add_char buf '\x00'

let value_of_azt_string s = VString (s, false)



(* ******Critical Chunk****** *)

(*Image Header*)
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


(* PNG Context - contient paramètre color_type*)
type png_context = {
  mutable ihdr_color_type : color_type;
}

(*Fonction parse de png_contexte avec une valeur par défaut 0xff*)
let parse_png_context _input =
  { ihdr_color_type = UnknownColorType 0xff }

(*Fonction parse update color type pour récupérer color_type et le mettre dans le contexte*)
let parse_update_color_type ctx color_type _input =
  ctx.ihdr_color_type <- color_type


struct image_header [param ctx] = {
  width : uint32; (*Nombre de pixel en largueur*)
  height : uint32; (*Nombre de pixel en longueur*)
  bit_depth : uint8; (*en fonction de color type*)
  color_type : color_type;
  parse_checkpoint _update_color_type : update_color_type(ctx; color_type); (*parse_checkpoint identifiant _update_color_type*)
  compression_method : compression_method;
  filter_method : filter_method;
  interlace_method : interlace_method;
}


(*Image Data - TODO: A decompresser via zlib*)
(* Format zlib : 
Compression method/flags code (4b->8 pour PNG - 4b-> 7:32k windows size): 1 byte
Additional flags/check bits:   (4b-> check bit - 1b-> preset dico - 2b->compression level):1 byte
Compressed data blocks:        n bytes
Check value:                   4 bytes
input_byte ?
*)
(* Premier octet decompressé : type de filtre - 0 à 5 *)
struct image_data = {
  compression_method_and_info : binstring(1);
  additional_flag : binstring(1);
  data_compress : binstring(input.cur_length-6); (*input: entrée courante*)
  checksum_compress_data : binstring(4);
}

(*Image Palette - TODO: controle:chunksize divisible par 3*)
struct index_palette = {
  red_index : uint8;
  green_index : uint8;
  blue_index : uint8;
}

struct image_palette = {
  palette_indexes : list of index_palette;
}


(* ******Anscillary Chunk****** *)

(*Image Transparency *)

struct truecolor_trns = {
  red_truecolor_trns : uint16;
  green_truecolor_trns : uint16;
  blue_truecolor_trns : uint16;
}

struct indexedcolor_list_trns = {
  indexedcolor_list_transparency : list of uint8; (*Une par entrée de la palette - complément par défaut à 0xff: opaque*)
}

union image_transparency_type [enrich] (UnparsedChunkContent) =
| Grayscale -> GrayscaleTransparency of uint16
| Truecolor -> TruecolorTransparency of truecolor_trns
| Indexedcolor -> IndexedcolorTransparency of indexedcolor_list_trns


(*Image Chromaticity *)
(*TODO: divisé par 10000*)
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


(*Image embedded ICC profile*)
(*TODO: a décompresser*)

struct image_embedded_profile = {
  embedded_profile_name : azt_string;
  embedded_profile_compression_method : uint8;
  _embedded_profile_compress : binstring;
}


(*Image significant bit - Pour retrouver le bithdepth réel de l'image*)
(*bitdepth réel de l'image est inférieur au bitdepth ajusté : 1,2,4,8 ou 16»*)
(*Méthode de complément à bitdepht ajusté *)

struct truecolor_significant_bit = {
  significant_red_bits : uint8;
  significant_green_bits : uint8;
  significant_blue_bits : uint8;
}

struct indexedcolor_significant_bit = {
  significant_red_bits : uint8;
  significant_green_bits : uint8;
  significant_blue_bits : uint8;
}

struct grayscalewithalphachannel_significant_bit = {
  significant_grayscale_bit : uint8;
  significant_alpha_bit : uint8;
}

struct truecolorwithalphachannel_significantbit = {
  significant_red_bits : uint8;
  significant_green_bits : uint8;
  significant_blue_bits : uint8;
  significant_alpha_bit : uint8;
}

union image_significant_bit_type [enrich] (UnparsedChunkContent) =
| Grayscale -> GrayscaleSignificantBit of uint8
| Truecolor -> TruecolorSignificantBit of truecolor_significant_bit
| Indexedcolor -> IndexedcolorSignificantBit of indexedcolor_significant_bit
| GrayscaleWithAlphaChannel -> GrayscaleWithAlphaChannelSignificantBit of grayscalewithalphachannel_significant_bit
| TruecolorWithAlphaChannel -> TruecolorWithAlphaChannelSignificantBit of truecolorwithalphachannel_significantbit


(*Image standard RGB profile*)
(*TODO: a détailler...*)
enum rendering_intent (8, UnknownVal UnknownColorType) =
| 0 -> Perceptual
| 0x01 -> RelativeColorimetric
| 0x02 -> Saturation
| 0x03 -> AbsoluteColorimetric

struct image_standard_rgb_profile = {
  rendering_intent : rendering_intent;
}


(*Image textual data - Latin-1*)
(*TODO: contrôle de taille du key_word: de 1 à 79 octets*)
struct image_textual_data = {
  key_word : azt_string;
  text : string;
}

let value_of_image_textual_data t = VString (t.key_word ^ ": " ^ t.text, false)


(*Image compressed textual data - Latin-1*)
(*TODO: à décompresser *)
struct image_compressed_textual_data = {
  key_word : azt_string;
  textual_compression_method : uint8;
  text_compress : binstring;
}

let value_of_image_compressed_textual_data t = VString (t.key_word ^ ": " ^ t.text_compress, false)


(*Image international textual data*)
(*TODO: contrôle de taille du key_word: de 1 à 79 octets*)
(*String: ...UTF-8... ?*)

enum compression_flag (8, UnknownVal UnknownInterlaceMethod) =
| 0 -> NoCompression
| 0x01 -> Compression

struct image_international_textual_data = {
  key_word : azt_string;
  compression_flag : uint8;
  compression_method : compression_flag;
  language_tag : azt_string;
  translated_keyword : azt_string;
  text : string;
}


(*Image background color - background à appliquer*)
struct truecolor_background_color = {
  background_red_bits : uint16;
  background_green_bits : uint16;
  background_blue_bits : uint16;  
}

union image_background_color_type [enrich] (UnparsedChunkContent) =
(*sur 16 bits mais ne garder que les bits significatifs au regard du bitdepth s'il est inférieur à 16*)
| Grayscale -> GrayscaleBackgroundColor of uint16
| Truecolor -> TruecolorBackgroundColor of truecolor_background_color
| Indexedcolor -> IndexedcolorBackgroundColor of uint8 (*Index de la palette à utiliser*)
| GrayscaleWithAlphaChannel -> GrayscaleWithAlphaChannelBackgroundColor of uint16
| TruecolorWithAlphaChannel -> TruecolorWithAlphaChannelBackgroundColor of truecolor_background_color


(*Image histogramme - fréquence d'appel à l'index d'une palette*)
struct image_histogramme_list = {
  image_hist_list : list of uint16; (*Une par entrée de la palette exactement*)
}

(*Image physical pixel dimension - ratio - nombre de pixel par unité*)
enum pixel_physical_unit (8, UnknownVal UnknownInterlaceMethod) =
| 0 -> Unknown
| 0x01 -> Meter

struct image_physical_pixel_dimension = {
  pixel_per_unit_x : uint32;
  pixel_per_unit_y : uint32;
  pixel_physical_unit : pixel_physical_unit;
}

(*Image suggested palette - utilisé par le système si truecolor non supporté par le système et PLTE absent - quantification*)

(*struct image_suggested_palette = {
  palette_name : azt_string;
  bitdepth : uint8; (*8 ou 16*)
  red_composante : (*Fonction de bitdepth: 1 ou 2 octets*)
  green_composante : (*Fonction de bitdepth*)
  blue_composante : (*Fonction de bitdepth*)
  alpha_composante : (*Fonction de bitdepth*)
  color_frequency : uint16;
}*)


(*Image time - Date de dernière modification de l'image*)
struct image_time = {
  year : uint16;
  month : uint8;
  day : uint8;
  hour : uint8;
  minute : uint8;
  second : uint8;
}


union chunk_content [enrich;param ctx] (UnparsedChunkContent) =
(* traitement avec valeurs binaires ? - 5ème bit: uppercase / lowercase*)
| "IHDR" -> ImageHeader of image_header(ctx)
| "IDAT" -> ImageData of image_data (*binstring*) (*simple binstring: besoin de concaténer les IDAT avant traitement décompression ou image_data*)
| "IEND" -> ImageEnd
| "PLTE" -> ImagePalette of image_palette
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
| "hIST" -> ImageHistogramme of image_histogramme_list
| "pHYs" -> ImagePhysicalPixelDimensions of image_physical_pixel_dimension
(*| "sPLT" -> ImageSuggestedPalette of image_suggested_palette*)
| "tIME" -> ImageTime of image_time



(*Format d'un chunk - avec paramètres contexte*)
struct chunk [param ctx] = {
  chunk_size : uint32;
  chunk_type : string(4);
  chunk_data : container(chunk_size) of chunk_content(ctx;chunk_type);
  chunk_crc : uint32;
}

(*Structure fichier PNG - Ajout d'un contexte via parse_checkpoint*)
struct png_file = {
  parse_checkpoint ctx : png_context;
  png_magic : magic("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a");
  chunks : list of chunk(ctx);
}
