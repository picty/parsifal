union autonomous_system (UnparsedAS, [enrich]) =
  | 16 -> AS16 of uint16
  | 32 -> AS32 of uint32

struct bgp_as_path_segment [param as_size] =
{
  path_segment_type : uint8;
  path_segment_length : uint8;
  path_segment_value : list(path_segment_length) of autonomous_system(as_size)
}
