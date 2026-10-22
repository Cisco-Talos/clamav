//! Types shared by every sans-I/O decoder in the crate.
//!
//! `LzmaStream`, `Lzma2Stream` and `XzStream` all expose the same push/pull
//! shape: hand `process()` an input slice, an output slice and an [`Action`],
//! and get back a [`StreamResult`].

/// Action to perform during stream processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Process available data without flushing.
    Run,
    /// Signal that no more input will be provided.
    Finish,
}

/// Status returned by stream processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// More input or output space needed to continue.
    Ok,
    /// The stream has been fully processed.
    StreamEnd,
}

/// Result of a single `process()` call.
#[derive(Debug, Clone, Copy)]
pub struct StreamResult {
    /// Number of bytes consumed from the input buffer.
    pub bytes_consumed: usize,
    /// Number of bytes written to the output buffer.
    pub bytes_produced: usize,
    /// Current stream status.
    pub status: Status,
}
