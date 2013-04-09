import qualified Data.ByteString.Lazy as B
import qualified GHC.Word as W

class Parse a where
  parse :: B.ByteString -> (a, B.ByteString)
  parse bs =
    let (res, remaining) = parse_bytes (B.unpack bs) in
    (res, B.pack remaining)

  parse_bytes :: [W.Word8] -> (a, [W.Word8])


class Dump a where
  dump :: a -> B.ByteString
  dump x = B.pack $ dump_bytes x
  
  dump_bytes :: a -> [W.Word8]

  
data TlsAlertLevel =
    AL_Warning
  | AL_Fatal
  | AL_Unknown W.Word8
  deriving (Eq, Ord, Show)

instance Parse TlsAlertLevel where
  parse_bytes (1:xs) = (AL_Warning, xs)
  parse_bytes (2:xs) = (AL_Fatal, xs)
  parse_bytes (x:xs) = (AL_Unknown x, xs)

instance Dump TlsAlertLevel where
  dump_bytes AL_Warning = [1]
  dump_bytes AL_Fatal = [2]
  dump_bytes (AL_Unknown x) = [x]



data TlsAlertType =
    AT_CloseNotify
  | AT_UnexpectedMessage
  | AT_BadRecordMAC
--  | ...
  | AT_Unknown W.Word8
  deriving (Eq, Ord, Show)

instance Parse TlsAlertType where
  parse_bytes (0:xs) = (AT_CloseNotify, xs)
  parse_bytes (10:xs) = (AT_UnexpectedMessage, xs)
  parse_bytes (20:xs) = (AT_BadRecordMAC, xs)
  parse_bytes (x:xs) = (AT_Unknown x, xs)

instance Dump TlsAlertType where
  dump_bytes AT_CloseNotify = [0]
  dump_bytes AT_UnexpectedMessage = [10]
  dump_bytes AT_BadRecordMAC = [20]
  dump_bytes (AT_Unknown x) = [x]



instance (Parse a, Parse b) => Parse (a, b) where
  parse_bytes xs =
    let (a, r1) = parse_bytes xs
        (b, r2) = parse_bytes r1 in
    ((a, b), r2)



-- parse (B.pack [1,10,65]) :: ((TlsAlertLevel, TlsAlertType), ByteString)


-- data TlsAlert = TlsAlert 
--   alert_level :: TlsAlertLevel,
--   alert_type  :: TlsAlertType
-- } deriving (Eq, Ord, Show, Parse)
