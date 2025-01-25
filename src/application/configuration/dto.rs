use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use std::num::ParseIntError;

#[derive(Clone, Serialize)]
pub struct DurationInSeconds(pub u64);

impl DurationInSeconds {
    pub fn to_unsigned(self) -> u64 {
        self.0
    }
    pub fn to_signed(self) -> i64 {
        self.0 as i64
    }
}

impl Debug for DurationInSeconds {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}s ({}m/{}h/{}d)",
            self.0,
            self.0 / 60,
            self.0 / 60 / 60,
            self.0 / 60 / 60 / 24,
        )
    }
}

impl From<DurationInSeconds> for i64 {
    fn from(dur: DurationInSeconds) -> Self {
        dur.0 as i64
    }
}

impl From<DurationInSeconds> for u64 {
    fn from(dur: DurationInSeconds) -> Self {
        dur.0
    }
}

impl From<i64> for DurationInSeconds {
    fn from(i: i64) -> Self {
        DurationInSeconds(i as u64)
    }
}

impl From<u64> for DurationInSeconds {
    fn from(value: u64) -> Self {
        DurationInSeconds(value)
    }
}

impl TryFrom<String> for DurationInSeconds {
    type Error = ParseIntError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(DurationInSeconds::from(value.parse::<u64>()?))
    }
}

#[derive(Clone, Serialize)]
pub struct HiddenString(pub String);

impl HiddenString {
    pub fn to_string(self) -> String {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for HiddenString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "*".repeat(self.0.len()))
    }
}

impl Debug for HiddenString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "*".repeat(self.0.len()))
    }
}

impl From<String> for HiddenString {
    fn from(value: String) -> Self {
        HiddenString(value)
    }
}
