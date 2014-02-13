enum test (8, UnknownVal Unknown) =
  | 0 -> Zero, "0"
  | 1 -> One
  | 2 | 3 -> TwoOrThree, "2 or 3"
  | 4 | 5 -> FourOrFive
  | 6, 10 -> SixToTen, "6 .. 10"
  | 11, 20 -> More
