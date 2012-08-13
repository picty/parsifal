let mrt_message_d = [
  "mrt_timestamp", FT_Integer IT_UInt32, false;
  "mrt_type",      FT_Enum (IT_UInt16, "MrtEnums", "mrt_type"), false;
  "mrt_subtype",   FT_Integer IT_UInt16, false;
  "mrt_message",   FT_Container (IT_UInt32, FT_String Remaining), false;
]

let descriptions = [
  Record ("mrt_message", mrt_message_d, [CO_EnrichByDefault]);
]
