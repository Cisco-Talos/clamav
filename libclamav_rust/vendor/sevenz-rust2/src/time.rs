/// An error that can be thrown when converting to [`NtTime`]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum NtTimeError {
    Negative,
    Overflow,
}

/// A type that represents a Windows file time and is used in the 7z archive format.
///
/// Can easily be converted to and from [`std::time::SystemTime`].
///
/// The feature flag `nt-time` implements conversions for [`nt_time::FileTime`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NtTime(pub(crate) u64);

impl Default for NtTime {
    fn default() -> Self {
        Self::NT_TIME_EPOCH
    }
}

impl NtTime {
    const FILE_TIMES_PER_SEC: u64 = 10_000_000;

    /// The [`NtTime`] of the  unix epoch (1970-01-01).
    pub const UNIX_EPOCH: NtTime = NtTime::new(134774 * 86400 * Self::FILE_TIMES_PER_SEC);

    /// The epoch of the [`NtTime`] (0001-01-01).
    pub const NT_TIME_EPOCH: NtTime = NtTime::new(0);

    /// Creates a new [`NtTime`] with the given file time.
    #[must_use]
    #[inline]
    pub const fn new(ft: u64) -> Self {
        Self(ft)
    }

    /// Returns the current system time as an [`NtTime`].
    #[must_use]
    #[inline]
    pub fn now() -> Self {
        use std::time::SystemTime;

        SystemTime::now()
            .try_into()
            .expect("the current date and time is not a valid NtTime")
    }

    fn sub(self, rhs: Self) -> std::time::Duration {
        let duration = self.0 - rhs.0;
        std::time::Duration::new(
            duration / Self::FILE_TIMES_PER_SEC,
            u32::try_from((duration % Self::FILE_TIMES_PER_SEC) * 100)
                .expect("the number of nanoseconds is not a valid `u32`"),
        )
    }
}

impl From<u64> for NtTime {
    /// Converts the file time to a [`NtTime`].
    #[inline]
    fn from(file_time: u64) -> Self {
        Self::new(file_time)
    }
}

impl From<NtTime> for u64 {
    /// Converts the [`NtTime`] into a file time.
    #[inline]
    fn from(nt_time: NtTime) -> Self {
        nt_time.0
    }
}

impl TryFrom<i64> for NtTime {
    type Error = NtTimeError;

    /// Converts the file time to a [`NtTime`].
    #[inline]
    fn try_from(file_time: i64) -> Result<Self, Self::Error> {
        file_time
            .try_into()
            .map_err(|_| NtTimeError::Negative)
            .map(Self::new)
    }
}

impl From<NtTime> for std::time::SystemTime {
    /// Converts a [`NtTime`] to a [`SystemTime`](std::time::SystemTime).
    #[inline]
    fn from(file_time: NtTime) -> Self {
        let duration = std::time::Duration::new(
            file_time.0 / NtTime::FILE_TIMES_PER_SEC,
            u32::try_from((file_time.0 % NtTime::FILE_TIMES_PER_SEC) * 100)
                .expect("the number of nanoseconds is not a valid `u32`"),
        );

        (std::time::SystemTime::UNIX_EPOCH - (NtTime::UNIX_EPOCH.sub(NtTime::NT_TIME_EPOCH)))
            + duration
    }
}

impl TryFrom<std::time::SystemTime> for NtTime {
    type Error = NtTimeError;

    /// Converts a [`SystemTime`](std::time::SystemTime) to a `FileTime`.
    #[inline]
    fn try_from(st: std::time::SystemTime) -> Result<Self, Self::Error> {
        use std::time::SystemTime;

        let elapsed = st
            .duration_since(
                SystemTime::UNIX_EPOCH - (NtTime::UNIX_EPOCH.sub(NtTime::NT_TIME_EPOCH)),
            )
            .map(|d| d.as_nanos())
            .map_err(|_| NtTimeError::Negative)?;

        let file_time = u64::try_from(elapsed / 100).map_err(|_| NtTimeError::Overflow)?;

        Ok(Self::new(file_time))
    }
}

#[cfg(feature = "nt-time")]
impl From<NtTime> for nt_time::FileTime {
    fn from(value: NtTime) -> Self {
        Self::new(value.0)
    }
}

#[cfg(feature = "nt-time")]
impl From<nt_time::FileTime> for NtTime {
    fn from(value: nt_time::FileTime) -> Self {
        Self::new(value.to_raw())
    }
}
