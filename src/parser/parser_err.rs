pub enum ParserError<I> {
    NextNotArg,
    Nom(I, nom::error::ErrorKind),
}
impl<I> nom::error::ParseError<I> for ParserError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::Nom(input, kind)
    }
    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}
