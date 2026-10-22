use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, atomic::AtomicBool},
};

/// A work-stealing queue that supports multiple workers taking work from a shared queue.
///
/// Will be removed once core::sync::mpsc is stable.
pub(crate) struct WorkStealingQueue<T> {
    inner: Arc<Inner<T>>,
}

struct Inner<T> {
    queue: Mutex<VecDeque<T>>,
    condvar: Condvar,
    closed: AtomicBool,
}

impl<T> WorkStealingQueue<T> {
    /// Creates a new work-stealing queue.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                queue: Mutex::new(VecDeque::new()),
                condvar: Condvar::new(),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Creates a worker handle that can steal work from this queue.
    pub(crate) fn worker(&self) -> WorkerHandle<T> {
        WorkerHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Pushes work to the queue. Returns false if the queue is closed.
    pub(crate) fn push(&self, item: T) -> bool {
        if self
            .inner
            .closed
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return false;
        }

        {
            let mut queue = self.inner.queue.lock().unwrap();
            queue.push_back(item);
        }

        // Notify one waiting worker
        self.inner.condvar.notify_one();
        true
    }

    /// Closes the queue, preventing new work from being added.
    /// Workers will continue to process remaining work until the queue is empty.
    pub(crate) fn close(&self) {
        self.inner
            .closed
            .store(true, core::sync::atomic::Ordering::Release);
        // Wake up all waiting workers so they can check the closed status
        self.inner.condvar.notify_all();
    }

    /// Returns the current number of items in the queue.
    pub(crate) fn len(&self) -> usize {
        self.inner.queue.lock().unwrap().len()
    }

    /// Returns true if the queue is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.queue.lock().unwrap().is_empty()
    }
}

impl<T> Default for WorkStealingQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A handle for workers to steal work from the queue.
pub(crate) struct WorkerHandle<T> {
    inner: Arc<Inner<T>>,
}

impl<T> WorkerHandle<T> {
    /// Attempts to steal work from the queue. Blocks until work is available or the queue is closed.
    /// Returns `None` if the queue is closed and empty.
    pub(crate) fn steal(&self) -> Option<T> {
        let mut queue = self.inner.queue.lock().unwrap();

        loop {
            // Try to get work
            if let Some(item) = queue.pop_front() {
                return Some(item);
            }

            // Check if queue is closed
            if self
                .inner
                .closed
                .load(core::sync::atomic::Ordering::Acquire)
            {
                return None;
            }

            // Wait for new work or closure
            queue = self.inner.condvar.wait(queue).unwrap();
        }
    }

    /// Attempts to steal work without blocking.
    /// Returns `None` if no work is currently available.
    pub(crate) fn try_steal(&self) -> Option<T> {
        self.inner.queue.lock().unwrap().pop_front()
    }

    /// Returns `true` if the queue is closed and empty (no more work will ever be available).
    pub(crate) fn is_closed_and_empty(&self) -> bool {
        let queue = self.inner.queue.lock().unwrap();
        let closed = self
            .inner
            .closed
            .load(core::sync::atomic::Ordering::Acquire);
        closed && queue.is_empty()
    }
}

impl<T> Clone for WorkerHandle<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    #[test]
    fn test_basic_functionality() {
        let queue = WorkStealingQueue::new();
        let worker = queue.worker();

        assert!(queue.push(1));
        assert!(queue.push(2));
        assert!(queue.push(3));

        assert_eq!(worker.steal(), Some(1));
        assert_eq!(worker.steal(), Some(2));

        assert_eq!(worker.try_steal(), Some(3));
        assert_eq!(worker.try_steal(), None);

        queue.close();
        assert!(!queue.push(4));
        assert!(worker.is_closed_and_empty());
    }

    #[test]
    fn test_multiple_workers() {
        let queue = WorkStealingQueue::new();
        let worker1 = queue.worker();
        let worker2 = queue.worker();

        for i in 0..10 {
            queue.push(i);
        }

        let mut results = Vec::new();
        while let Some(item) = worker1.try_steal() {
            results.push(item);
        }
        while let Some(item) = worker2.try_steal() {
            results.push(item);
        }

        results.sort();
        assert_eq!(results, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn test_blocking_behavior() {
        let queue = WorkStealingQueue::new();
        let worker = queue.worker();

        let queue_clone = WorkStealingQueue {
            inner: Arc::clone(&queue.inner),
        };

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            queue_clone.push(42);
            queue_clone.close();
        });

        assert_eq!(worker.steal(), Some(42));
        assert_eq!(worker.steal(), None);
    }
}
