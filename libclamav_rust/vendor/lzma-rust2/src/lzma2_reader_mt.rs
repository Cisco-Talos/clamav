use std::{
    collections::BTreeMap,
    io,
    io::{Cursor, Read},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::Duration,
};

/// Interval for checking worker errors while waiting for results.
const ERROR_CHECK_INTERVAL: Duration = Duration::from_millis(100);

use crate::{
    Lzma2Reader, set_error,
    work_queue::{WorkStealingQueue, WorkerHandle},
};

/// A work unit for a worker thread.
/// Contains the sequence number and the raw compressed bytes for a series of chunks.
type WorkUnit = (u64, Vec<u8>);

/// A result unit from a worker thread.
/// Contains the sequence number and the decompressed data.
type ResultUnit = (u64, Vec<u8>);

enum State {
    /// Actively reading from the inner reader and sending work to threads.
    Reading,
    /// The inner reader has reached EOF. We are now waiting for the remaining
    /// work to be completed by the worker threads.
    Draining,
    /// All data has been decompressed and returned. The stream is exhausted.
    Finished,
    /// A fatal error occurred in either the reader or a worker thread.
    Error,
}

/// A multi-threaded LZMA2 decompressor.
pub struct Lzma2ReaderMt<R: Read> {
    inner: R,
    result_rx: Receiver<ResultUnit>,
    result_tx: SyncSender<ResultUnit>,
    current_work_unit: Vec<u8>,
    next_sequence_to_dispatch: u64,
    next_sequence_to_return: u64,
    last_sequence_id: Option<u64>,
    out_of_order_chunks: BTreeMap<u64, Vec<u8>>,
    current_chunk: Cursor<Vec<u8>>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    state: State,
    work_queue: WorkStealingQueue<WorkUnit>,
    active_workers: Arc<AtomicU32>,
    max_workers: u32,
    dict_size: u32,
    preset_dict: Option<Arc<Vec<u8>>>,
    worker_handles: Vec<thread::JoinHandle<()>>,
}

impl<R: Read> Lzma2ReaderMt<R> {
    /// Creates a new multi-threaded LZMA2 reader.
    ///
    /// - `inner`: The reader to read compressed data from.
    /// - `dict_size`: The dictionary size in bytes, as specified in the stream properties.
    /// - `preset_dict`: An optional preset dictionary.
    /// - `num_workers`: The maximum number of worker threads for decompression. Currently capped at 256 Threads.
    pub fn new(inner: R, dict_size: u32, preset_dict: Option<&[u8]>, num_workers: u32) -> Self {
        let max_workers = num_workers.clamp(1, 256);

        let work_queue = WorkStealingQueue::new();
        let (result_tx, result_rx) = mpsc::sync_channel::<ResultUnit>(1);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let error_store = Arc::new(Mutex::new(None));
        let active_workers = Arc::new(AtomicU32::new(0));
        let preset_dict = preset_dict.map(|s| s.to_vec()).map(Arc::new);

        let mut reader = Self {
            inner,
            result_rx,
            result_tx,
            current_work_unit: Vec::with_capacity(1024 * 1024),
            next_sequence_to_dispatch: 0,
            next_sequence_to_return: 0,
            last_sequence_id: None,
            out_of_order_chunks: BTreeMap::new(),
            current_chunk: Cursor::new(Vec::new()),
            shutdown_flag,
            error_store,
            state: State::Reading,
            work_queue,
            active_workers,
            max_workers,
            dict_size,
            preset_dict,
            worker_handles: Vec::new(),
        };

        reader.spawn_worker_thread();

        reader
    }

    fn spawn_worker_thread(&mut self) {
        let worker_handle = self.work_queue.worker();
        let result_tx = self.result_tx.clone();
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let error_store = Arc::clone(&self.error_store);
        let active_workers = Arc::clone(&self.active_workers);
        let preset_dict = self.preset_dict.clone();
        let dict_size = self.dict_size;

        let handle = thread::spawn(move || {
            worker_thread_logic(
                worker_handle,
                result_tx,
                dict_size,
                preset_dict,
                shutdown_flag,
                error_store,
                active_workers,
            );
        });

        self.worker_handles.push(handle);
    }

    /// The count of independent chunks found inside the compressed file.
    /// This is effectively tha maximum parallelization possible.
    pub fn chunk_count(&self) -> u64 {
        self.next_sequence_to_return
    }

    /// Reads one LZMA2 chunk from the inner reader and appends it to the current work unit.
    /// If the chunk is an independent block, it dispatches the current work unit.
    ///
    /// Returns `Ok(false)` on clean EOF, `Ok(true)` on success, and `Err` on I/O error.
    fn read_and_dispatch_chunk(&mut self) -> io::Result<bool> {
        let mut control_buf = [0u8; 1];
        match self.inner.read_exact(&mut control_buf) {
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // Clean end of stream.
                return Ok(false);
            }
            Err(error) => return Err(error),
        }

        let control = control_buf[0];

        if control == 0x00 {
            // End of stream marker.
            self.current_work_unit.push(0x00);
            self.send_work_unit();
            return Ok(false);
        }

        let is_independent_chunk = control >= 0xE0 || control == 0x01;

        // Split work units before independent chunks (but not for the very first chunk).
        if is_independent_chunk && !self.current_work_unit.is_empty() {
            self.current_work_unit.push(0x00);
            self.send_work_unit();
        }

        self.current_work_unit.push(control);

        let chunk_data_size = if control >= 0x80 {
            // Compressed chunk. Read header to find size.
            let header_len = if control >= 0xC0 { 5 } else { 4 };
            let mut header_buf = [0; 5];
            self.inner.read_exact(&mut header_buf[..header_len])?;
            self.current_work_unit
                .extend_from_slice(&header_buf[..header_len]);
            u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize + 1
        } else if control == 0x01 || control == 0x02 {
            // Uncompressed chunk.
            let mut size_buf = [0u8; 2];
            self.inner.read_exact(&mut size_buf)?;
            self.current_work_unit.extend_from_slice(&size_buf);
            u16::from_be_bytes(size_buf) as usize + 1
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid LZMA2 control byte: {control:X}"),
            ));
        };

        // Read the chunk data itself.
        if chunk_data_size > 0 {
            let start_len = self.current_work_unit.len();
            self.current_work_unit
                .resize(start_len + chunk_data_size, 0);
            self.inner
                .read_exact(&mut self.current_work_unit[start_len..])?;
        }

        Ok(true)
    }

    /// Sends the current work unit to the workers.
    fn send_work_unit(&mut self) {
        if self.current_work_unit.is_empty() {
            return;
        }

        let work_unit =
            core::mem::replace(&mut self.current_work_unit, Vec::with_capacity(1024 * 1024));

        if !self
            .work_queue
            .push((self.next_sequence_to_dispatch, work_unit))
        {
            // Queue is closed, this indicates shutdown.
            self.state = State::Error;
            set_error(
                io::Error::new(io::ErrorKind::BrokenPipe, "worker threads have shut down"),
                &self.error_store,
                &self.shutdown_flag,
            );
        }

        // We spawn a new thread if we have work queued, no available workers, and haven't reached
        // the maximal allowed parallelism yet.
        let spawned_workers = self.worker_handles.len() as u32;
        let active_workers = self.active_workers.load(Ordering::Acquire);
        let queue_len = self.work_queue.len();

        if queue_len > 0 && active_workers == spawned_workers && spawned_workers < self.max_workers
        {
            self.spawn_worker_thread();
        }

        self.next_sequence_to_dispatch += 1;
    }

    fn get_next_uncompressed_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            // Always check for already-received chunks first.
            if let Some(result) = self
                .out_of_order_chunks
                .remove(&self.next_sequence_to_return)
            {
                self.next_sequence_to_return += 1;
                return Ok(Some(result));
            }

            // Check for a globally stored error.
            if let Some(err) = self.error_store.lock().unwrap().take() {
                self.state = State::Error;
                return Err(err);
            }

            match self.state {
                State::Reading => {
                    // First, always try to receive a result without blocking.
                    // This keeps the pipeline moving and avoids unnecessary blocking on I/O.
                    match self.result_rx.try_recv() {
                        Ok((seq, result)) => {
                            if seq == self.next_sequence_to_return {
                                self.next_sequence_to_return += 1;
                                return Ok(Some(result));
                            } else {
                                self.out_of_order_chunks.insert(seq, result);
                                continue; // Loop again to check the out_of_order_chunks
                            }
                        }
                        Err(mpsc::TryRecvError::Disconnected) => {
                            // All workers are done.
                            self.state = State::Draining;
                            continue;
                        }
                        Err(mpsc::TryRecvError::Empty) => {
                            // No results are ready. Now, we can consider reading more input.
                        }
                    }

                    // If the work queue has capacity, try to read more from the source.
                    if self.work_queue.is_empty() {
                        match self.read_and_dispatch_chunk() {
                            Ok(true) => {
                                // Successfully read and dispatched a chunk, loop to continue.
                                continue;
                            }
                            Ok(false) => {
                                // Clean EOF from inner reader.
                                // Send any remaining data as the final work unit.
                                self.send_work_unit();
                                self.last_sequence_id =
                                    Some(self.next_sequence_to_dispatch.saturating_sub(1));
                                self.state = State::Draining;
                                continue;
                            }
                            Err(error) => {
                                set_error(error, &self.error_store, &self.shutdown_flag);
                                self.state = State::Error;
                                continue;
                            }
                        }
                    }

                    // Now we MUST wait for a result to make progress.
                    loop {
                        match self.result_rx.recv_timeout(ERROR_CHECK_INTERVAL) {
                            Ok((seq, result)) => {
                                if seq == self.next_sequence_to_return {
                                    self.next_sequence_to_return += 1;
                                    return Ok(Some(result));
                                } else {
                                    self.out_of_order_chunks.insert(seq, result);
                                    // We've made progress, loop to check the out_of_order_chunks.
                                    break;
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Some(err) = self.error_store.lock().unwrap().take() {
                                    self.state = State::Error;
                                    return Err(err);
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                // All workers are done.
                                self.state = State::Draining;
                                break;
                            }
                        }
                    }
                }
                State::Draining => {
                    if let Some(last_seq) = self.last_sequence_id {
                        if self.next_sequence_to_return > last_seq {
                            self.state = State::Finished;
                            continue;
                        }
                    }

                    // In Draining state, we only wait for results.
                    loop {
                        match self.result_rx.recv_timeout(ERROR_CHECK_INTERVAL) {
                            Ok((seq, result)) => {
                                if seq == self.next_sequence_to_return {
                                    self.next_sequence_to_return += 1;
                                    return Ok(Some(result));
                                } else {
                                    self.out_of_order_chunks.insert(seq, result);
                                    break;
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Some(err) = self.error_store.lock().unwrap().take() {
                                    self.state = State::Error;
                                    return Err(err);
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                // All workers finished, and channel is empty. We are done.
                                self.state = State::Finished;
                                break;
                            }
                        }
                    }
                }
                State::Finished => {
                    return Ok(None);
                }
                State::Error => {
                    // The error was already logged, now we just propagate it.
                    return Err(self.error_store.lock().unwrap().take().unwrap_or_else(|| {
                        io::Error::other("decompression failed with an unknown error")
                    }));
                }
            }
        }
    }
}

/// The logic for a single worker thread.
fn worker_thread_logic(
    worker_handle: WorkerHandle<WorkUnit>,
    result_tx: SyncSender<ResultUnit>,
    dict_size: u32,
    preset_dict: Option<Arc<Vec<u8>>>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    active_workers: Arc<AtomicU32>,
) {
    while !shutdown_flag.load(Ordering::Acquire) {
        let (seq, work_unit_data) = match worker_handle.steal() {
            Some(work) => {
                active_workers.fetch_add(1, Ordering::Release);
                work
            }
            None => {
                // No more work available and queue is closed
                break;
            }
        };

        let mut reader = Lzma2Reader::new(
            work_unit_data.as_slice(),
            dict_size,
            preset_dict.as_deref().map(|v| v.as_slice()),
        );

        let mut decompressed_data = Vec::with_capacity(work_unit_data.len());
        let result = match reader.read_to_end(&mut decompressed_data) {
            Ok(_) => decompressed_data,
            Err(error) => {
                active_workers.fetch_sub(1, Ordering::Release);
                set_error(error, &error_store, &shutdown_flag);
                return;
            }
        };

        if result_tx.send((seq, result)).is_err() {
            active_workers.fetch_sub(1, Ordering::Release);
            return;
        }

        active_workers.fetch_sub(1, Ordering::Release);
    }
}

impl<R: Read> Read for Lzma2ReaderMt<R> {
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

impl<R: Read> Drop for Lzma2ReaderMt<R> {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        self.work_queue.close();
        // Worker threads will exit when the work queue is closed.
        // JoinHandles will be dropped, which is fine since we set the shutdown flag,
    }
}
