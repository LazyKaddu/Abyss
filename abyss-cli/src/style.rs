//! Zero-dependency ANSI terminal styling utilities for `abyssctl`.

use std::fmt;

pub trait Stylize: fmt::Display {
    fn bold(&self) -> Styled<&Self> {
        Styled { val: self, code: "\x1b[1m" }
    }

    fn dimmed(&self) -> Styled<&Self> {
        Styled { val: self, code: "\x1b[2m" }
    }

    fn red(&self) -> Styled<&Self> {
        Styled { val: self, code: "\x1b[31m" }
    }

    fn green(&self) -> Styled<&Self> {
        Styled { val: self, code: "\x1b[32m" }
    }

    fn yellow(&self) -> Styled<&Self> {
        Styled { val: self, code: "\x1b[33m" }
    }

    fn cyan(&self) -> Styled<&Self> {
        Styled { val: self, code: "\x1b[36m" }
    }
}

impl<T: fmt::Display + ?Sized> Stylize for T {}

pub struct Styled<T: fmt::Display> {
    val: T,
    code: &'static str,
}

impl<T: fmt::Display> Styled<T> {
    pub fn bold(self) -> StyledBold<T> {
        StyledBold { val: self.val, code: self.code }
    }
}

impl<T: fmt::Display> fmt::Display for Styled<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}\x1b[0m", self.code, self.val)
    }
}

pub struct StyledBold<T: fmt::Display> {
    val: T,
    code: &'static str,
}

impl<T: fmt::Display> fmt::Display for StyledBold<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\x1b[1m{}\x1b[0m", self.code, self.val)
    }
}
