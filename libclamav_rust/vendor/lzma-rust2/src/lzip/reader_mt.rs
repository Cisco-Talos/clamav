use std::{
    io::{self, Cursor, Seek, SeekFrom},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::SyncSender,
    },
};

use super::{LzipMember, scan_members};
use crate::{
    LzipReader, Read, set_error,
    work_pool::{WorkPool, WorkPoolConfig, WorkPoolState},
    work_queue::WorkerHandle,
};

/// A work unit for a worker thread.
#[derive(Debug)]
struct WorkUnit {
    member_data: Vec<u8>,
}

/// A multi-threaded LZIP decompressor.
pub struct LzipReaderMt<R: Read + Seek> {
    inner: R,
    members: Vec<LzipMember>,
    work_pool: WorkPool<WorkUnit, Vec<u8>>,
    current_chunk: Cursor<Vec<u8>>,
}

impl<R: Read + Seek> LzipReaderMt<R> {
    /// Creates a new multi-threaded LZIP reader.
    ///
    /// - `inner`: The reader to read compressed data from. Must implement Seek.
    /// - `num_workers`: The maximum number of worker threads for decompression. Currently capped at 256 threads.
    pub fn new(inner: R, num_workers: u32) -> io::Result<Self> {
        let (inner, members) = scan_members(inner)?;
        let num_members = members.len() as u64;

        Ok(Self {
            inner,
            members,
            work_pool: WorkPool::new(
                WorkPoolConfig::new(num_workers, num_members),
                worker_thread_logic,
            ),
            current_chunk: Cursor::new(Vec::new()),
        })
    }

    /// Get the count of LZIP members found in the file.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    fn get_next_uncompressed_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Check if we've processed all members
        if matches!(self.work_pool.state(), WorkPoolState::Finished) {
            return Ok(None);
        }

        self.work_pool.get_result(|index| {
            let member = &self.members[index as usize];
            self.inner.seek(SeekFrom::Start(member.start_pos))?;
            let mut member_data = vec![0u8; member.compressed_size as usize];
            self.inner.read_exact(&mut member_data)?;
            Ok(WorkUnit { member_data })
        })
    }
}

/// The logic for a single worker thread.
fn worker_thread_logic(
    worker_handle: WorkerHandle<(u64, WorkUnit)>,
    result_tx: SyncSender<(u64, Vec<u8>)>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    active_workers: Arc<AtomicU32>,
) {
    while !shutdown_flag.load(Ordering::Acquire) {
        let work_unit = match worker_handle.steal() {
            Some(work) => {
                active_workers.fetch_add(1, Ordering::Release);
                work
            }
            None => {
                // No more work available and queue is closed.
                break;
            }
        };

        let (index, WorkUnit { member_data }) = work_unit;

        let mut lzip_reader = LzipReader::new(member_data.as_slice());

        let mut decompressed_data = Vec::new();
        let result = match lzip_reader.read_to_end(&mut decompressed_data) {
            Ok(_) => decompressed_data,
            Err(error) => {
                active_workers.fetch_sub(1, Ordering::Release);
                set_error(error, &error_store, &shutdown_flag);
                return;
            }
        };

        if result_tx.send((index, result)).is_err() {
            active_workers.fetch_sub(1, Ordering::Release);
            return;
        }

        active_workers.fetch_sub(1, Ordering::Release);
    }
}

impl<R: Read + Seek> Read for LzipReaderMt<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bytes_read = self.current_chunk.read(buf)?;

        if bytes_read > 0 {
            return Ok(bytes_read);
        }

        let chunk_data = self.get_next_uncompressed_chunk()?;

        let Some(chunk_data) = chunk_data else {
            // This is the clean end of the stream.
            return Ok(0);
        };

        self.current_chunk = Cursor::new(chunk_data);

        // Recursive call to read the new chunk data.
        self.read(buf)
    }
}
