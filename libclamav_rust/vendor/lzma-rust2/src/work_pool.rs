use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread,
    time::Duration,
};

/// Interval for checking worker errors while waiting for results.
const ERROR_CHECK_INTERVAL: Duration = Duration::from_millis(100);

use crate::{
    set_error,
    work_queue::{WorkStealingQueue, WorkerHandle},
};

/// Configuration for a work pool.
#[derive(Debug, Clone)]
pub(crate) struct WorkPoolConfig {
    pub(crate) num_workers: u32,
    pub(crate) num_work: u64,
}

impl WorkPoolConfig {
    pub(crate) fn new(num_workers: u32, num_work: u64) -> Self {
        Self {
            num_workers,
            num_work,
        }
    }
}

/// States for the work pool.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WorkPoolState {
    /// Actively accepting work and dispatching to threads.
    Dispatching,
    /// No more work will be submitted, draining existing work.
    Draining,
    /// All work completed.
    Finished,
    /// An error occurred.
    Error,
}

pub(crate) type WorkerFunction<W, R> = fn(
    WorkerHandle<(u64, W)>,
    SyncSender<(u64, R)>,
    Arc<AtomicBool>,
    Arc<Mutex<Option<io::Error>>>,
    Arc<AtomicU32>,
);

/// A generic work pool for the multi threading reader and writer.
pub(crate) struct WorkPool<W, R> {
    work_queue: WorkStealingQueue<(u64, W)>,
    result_rx: Receiver<(u64, R)>,
    result_tx: SyncSender<(u64, R)>,
    next_index_to_dispatch: u64,
    next_index_to_return: u64,
    last_sequence_id: Option<u64>,
    out_of_order_results: BTreeMap<u64, R>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    state: WorkPoolState,
    active_workers: Arc<AtomicU32>,
    num_workers: u32,
    num_work: u64,
    worker_handles: Vec<thread::JoinHandle<()>>,
    worker_fn: WorkerFunction<W, R>,
}

impl<W, R> WorkPool<W, R>
where
    W: Send + 'static,
    R: Send + 'static,
{
    /// Create a new work pool that spawns workers using the provided worker function.
    pub(crate) fn new(config: WorkPoolConfig, worker_fn: WorkerFunction<W, R>) -> Self {
        let (result_tx, result_rx) = mpsc::sync_channel::<(u64, R)>(1);

        let mut pool = Self {
            work_queue: WorkStealingQueue::new(),
            result_rx,
            result_tx,
            next_index_to_dispatch: 0,
            next_index_to_return: 0,
            last_sequence_id: None,
            out_of_order_results: BTreeMap::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            error_store: Arc::new(Mutex::new(None)),
            state: WorkPoolState::Dispatching,
            active_workers: Arc::new(AtomicU32::new(0)),
            num_workers: config.num_workers.clamp(1, 256),
            num_work: config.num_work,
            worker_handles: Vec::new(),
            worker_fn,
        };

        pool.spawn_worker_thread();

        pool
    }

    pub(crate) fn next_index_to_dispatch(&self) -> u64 {
        self.next_index_to_dispatch
    }

    /// Submit work to the pool. Returns `false` if there is no more work to work on.
    pub(crate) fn dispatch_next_work<F>(&mut self, next_work_function: &mut F) -> io::Result<bool>
    where
        F: FnMut(u64) -> io::Result<W>,
    {
        let next_index = self.next_index_to_dispatch;

        if next_index >= self.num_work {
            // No more members to dispatch.
            return Ok(false);
        }

        let work = next_work_function(next_index)?;

        if !self.work_queue.push((next_index, work)) {
            // Queue is closed, this indicates shutdown.
            self.state = WorkPoolState::Error;
            set_error(
                io::Error::new(io::ErrorKind::BrokenPipe, "worker threads have shut down"),
                &self.error_store,
                &self.shutdown_flag,
            );
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker threads have shut down",
            ));
        }

        self.maybe_spawn_worker();

        self.next_index_to_dispatch += 1;

        Ok(true)
    }

    /// Try to get the next result in sequence order. Returns None if no result is ready.
    pub(crate) fn try_get_result(&mut self) -> io::Result<Option<R>> {
        // Check if we have the next result in sequence.
        if let Some(result) = self.out_of_order_results.remove(&self.next_index_to_return) {
            self.next_index_to_return += 1;
            return Ok(Some(result));
        }

        // Check for errors.
        if let Some(err) = self.error_store.lock().unwrap().take() {
            self.state = WorkPoolState::Error;
            return Err(err);
        }

        // Try to receive a result without blocking.
        match self.result_rx.try_recv() {
            Ok((seq, result)) => {
                if seq == self.next_index_to_return {
                    self.next_index_to_return += 1;
                    Ok(Some(result))
                } else {
                    self.out_of_order_results.insert(seq, result);
                    Ok(None)
                }
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                if matches!(self.state, WorkPoolState::Dispatching) {
                    self.state = WorkPoolState::Draining;
                }
                Ok(None)
            }
        }
    }

    /// Get the next result in sequence order, blocking until available.
    pub(crate) fn get_result<F>(&mut self, mut next_work_function: F) -> io::Result<Option<R>>
    where
        F: FnMut(u64) -> io::Result<W>,
    {
        loop {
            // Always check for already-received results first.
            if let Some(result) = self.out_of_order_results.remove(&self.next_index_to_return) {
                self.next_index_to_return += 1;
                return Ok(Some(result));
            }

            // Check for a globally stored error.
            if let Some(err) = self.error_store.lock().unwrap().take() {
                self.state = WorkPoolState::Error;
                return Err(err);
            }

            match self.state {
                WorkPoolState::Dispatching => {
                    // First, always try to receive a result without blocking.
                    // This keeps the pipeline moving and avoids unnecessary blocking.
                    match self.result_rx.try_recv() {
                        Ok((seq, result)) => {
                            if seq == self.next_index_to_return {
                                self.next_index_to_return += 1;
                                return Ok(Some(result));
                            } else {
                                self.out_of_order_results.insert(seq, result);
                                continue; // Loop again to check the out_of_order_results.
                            }
                        }
                        Err(TryRecvError::Disconnected) => {
                            // All workers are done.
                            self.state = WorkPoolState::Draining;
                            continue;
                        }
                        Err(TryRecvError::Empty) => {
                            // No results are ready. Now, we can consider dispatching more work.
                        }
                    }

                    // If the work queue has capacity, try to read more from the source.
                    if self.work_queue.len() < 2 {
                        match self.dispatch_next_work(&mut next_work_function) {
                            Ok(true) => {
                                // Successfully read and dispatched a chunk, loop to continue.
                                continue;
                            }
                            Ok(false) => {
                                // No more work to dispatch.
                                self.finish();
                                continue;
                            }
                            Err(error) => {
                                set_error(error, &self.error_store, &self.shutdown_flag);
                                self.state = WorkPoolState::Error;
                                continue;
                            }
                        }
                    }

                    // Now we MUST wait for a result to make progress.
                    loop {
                        match self.result_rx.recv_timeout(ERROR_CHECK_INTERVAL) {
                            Ok((seq, result)) => {
                                if seq == self.next_index_to_return {
                                    self.next_index_to_return += 1;
                                    return Ok(Some(result));
                                } else {
                                    self.out_of_order_results.insert(seq, result);
                                    // We've made progress, loop to check the out_of_order_results.
                                    break;
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Some(err) = self.error_store.lock().unwrap().take() {
                                    self.state = WorkPoolState::Error;
                                    return Err(err);
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                // All workers are done.
                                self.state = WorkPoolState::Draining;
                                break;
                            }
                        }
                    }
                }
                WorkPoolState::Draining => {
                    if let Some(last_seq) = self.last_sequence_id {
                        if self.next_index_to_return > last_seq {
                            self.state = WorkPoolState::Finished;
                            continue;
                        }
                    }

                    // In Draining state, we only wait for results.
                    loop {
                        match self.result_rx.recv_timeout(ERROR_CHECK_INTERVAL) {
                            Ok((seq, result)) => {
                                if seq == self.next_index_to_return {
                                    self.next_index_to_return += 1;
                                    return Ok(Some(result));
                                } else {
                                    self.out_of_order_results.insert(seq, result);
                                    break;
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Some(err) = self.error_store.lock().unwrap().take() {
                                    self.state = WorkPoolState::Error;
                                    return Err(err);
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                // All workers finished, and channel is empty. We are done.
                                self.state = WorkPoolState::Finished;
                                break;
                            }
                        }
                    }
                }
                WorkPoolState::Finished => {
                    return Ok(None);
                }
                WorkPoolState::Error => {
                    return Err(self.error_store.lock().unwrap().take().unwrap_or_else(|| {
                        io::Error::other("work pool failed with unknown error")
                    }));
                }
            }
        }
    }

    /// Mark that no more work will be submitted and begin draining.
    pub(crate) fn finish(&mut self) {
        if matches!(self.state, WorkPoolState::Dispatching) {
            self.last_sequence_id = Some(self.next_index_to_dispatch.saturating_sub(1));
            self.state = WorkPoolState::Draining;
        }
    }

    /// Check if the work queue is empty.
    pub(crate) fn is_work_queue_empty(&self) -> bool {
        self.work_queue.is_empty()
    }

    /// Get the current state.
    pub(crate) fn state(&self) -> WorkPoolState {
        self.state
    }

    fn spawn_worker_thread(&mut self) {
        let worker_handle = self.work_queue.worker();
        let result_tx = self.result_tx.clone();
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let error_store = Arc::clone(&self.error_store);
        let active_workers = Arc::clone(&self.active_workers);
        let worker_fn = self.worker_fn;

        let handle = thread::spawn(move || {
            worker_fn(
                worker_handle,
                result_tx,
                shutdown_flag,
                error_store,
                active_workers,
            );
        });

        self.worker_handles.push(handle);
    }

    fn maybe_spawn_worker(&mut self) {
        let spawned_workers = self.worker_handles.len() as u32;
        let active_workers = self.active_workers.load(Ordering::Acquire);
        let queue_len = self.work_queue.len();

        // Spawn a new worker if:
        // 1. There's work in the queue
        // 2. All current workers are busy (active == spawned)
        // 3. We haven't reached the maximum worker count
        if queue_len > 0 && active_workers == spawned_workers && spawned_workers < self.num_workers
        {
            self.spawn_worker_thread();
        }
    }
}

impl<W, R> Drop for WorkPool<W, R> {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        self.work_queue.close();
        // Worker threads will exit when the work queue is closed
        // JoinHandles will be dropped, which is fine since we set the shutdown flag
    }
}
