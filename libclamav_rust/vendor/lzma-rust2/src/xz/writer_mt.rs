use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::SyncSender,
    },
};

use super::{
    CheckType, ChecksumCalculator, FilterConfig, FilterType, IndexRecord, add_padding,
    write_xz_block_header, write_xz_index, write_xz_stream_footer, write_xz_stream_header,
};
use crate::{
    AutoFinish, AutoFinisher, Lzma2Options, Result, XzOptions,
    enc::{Lzma2Writer, LzmaOptions},
    error_invalid_input, set_error,
    work_pool::{WorkPool, WorkPoolConfig},
    work_queue::WorkerHandle,
};

/// A work unit for a worker thread.
#[derive(Debug, Clone)]
struct WorkUnit {
    uncompressed_data: Vec<u8>,
    lzma_options: LzmaOptions,
    check_type: CheckType,
}

/// A result unit from a worker thread.
#[derive(Debug)]
struct ResultUnit {
    compressed_data: Vec<u8>,
    checksum: Vec<u8>,
    uncompressed_size: u64,
}

/// A multi-threaded XZ compressor.
pub struct XzWriterMt<W: Write> {
    inner: W,
    options: XzOptions,
    current_work_unit: Vec<u8>,
    block_size: usize,
    work_pool: WorkPool<WorkUnit, ResultUnit>,
    index_records: Vec<IndexRecord>,
    checksum_calculator: ChecksumCalculator,
    header_written: bool,
    total_uncompressed_pos: u64,
}

impl<W: Write> XzWriterMt<W> {
    /// Creates a new multi-threaded XZ writer.
    ///
    /// - `inner`: The writer to write compressed data to.
    /// - `options`: The XZ options used for compressing. Block size must be set when using the
    ///   multi-threaded encoder. If you need just one block, then use the single-threaded encoder.
    /// - `num_workers`: The maximum number of worker threads for compression.
    ///   Currently capped at 256 threads.
    pub fn new(inner: W, options: XzOptions, num_workers: u32) -> Result<Self> {
        if options.filters.len() > 3 {
            return Err(error_invalid_input(
                "XZ allows only at most 3 pre-filters plus LZMA2",
            ));
        }

        let block_size = match options.block_size {
            None => return Err(error_invalid_input("block size must be set")),
            Some(block_size) => block_size.get().max(options.lzma_options.dict_size as u64),
        };

        let block_size = usize::try_from(block_size)
            .map_err(|_| error_invalid_input("block size bigger than usize"))?;

        let checksum_calculator = ChecksumCalculator::new(options.check_type);

        // We don't know how many work units we'll have ahead of time.
        let num_work = u64::MAX;

        Ok(Self {
            inner,
            options,
            current_work_unit: Vec::with_capacity(block_size.min(1024 * 1024)),
            block_size,
            work_pool: WorkPool::new(
                WorkPoolConfig::new(num_workers, num_work),
                worker_thread_logic,
            ),
            index_records: Vec::new(),
            checksum_calculator,
            header_written: false,
            total_uncompressed_pos: 0,
        })
    }

    fn write_stream_header(&mut self) -> Result<()> {
        if self.header_written {
            return Ok(());
        }

        write_xz_stream_header(&mut self.inner, self.options.check_type)?;
        self.header_written = true;

        Ok(())
    }

    fn write_block_header(&mut self, _block_uncompressed_size: u64) -> Result<u64> {
        // Add LZMA2 filter to the list
        let mut filters = self.options.filters.clone();
        filters.push(FilterConfig {
            filter_type: FilterType::Lzma2,
            property: 0,
        });

        write_xz_block_header(
            &mut self.inner,
            &filters,
            self.options.lzma_options.dict_size,
        )
    }

    /// Sends the current work unit to the workers.
    fn send_work_unit(&mut self) -> Result<()> {
        if self.current_work_unit.is_empty() {
            return Ok(());
        }

        // Ensure stream header is written before any blocks
        self.write_stream_header()?;

        self.drain_available_results()?;

        let work_data = core::mem::take(&mut self.current_work_unit);
        let mut work_data_opt = Some(work_data);

        self.work_pool.dispatch_next_work(&mut |_seq| {
            let data = work_data_opt.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "work already provided")
            })?;
            Ok(WorkUnit {
                uncompressed_data: data,
                lzma_options: self.options.lzma_options.clone(),
                check_type: self.options.check_type,
            })
        })?;

        self.drain_available_results()?;

        Ok(())
    }

    /// Drains all currently available results from the work pool and writes them.
    fn drain_available_results(&mut self) -> Result<()> {
        while let Some(result) = self.work_pool.try_get_result()? {
            self.write_compressed_block(
                result.compressed_data,
                result.checksum,
                result.uncompressed_size,
            )?;
        }
        Ok(())
    }

    fn write_compressed_block(
        &mut self,
        compressed_data: Vec<u8>,
        checksum: Vec<u8>,
        block_uncompressed_size: u64,
    ) -> Result<()> {
        let block_header_size = self.write_block_header(block_uncompressed_size)?;

        let data_size = compressed_data.len() as u64;
        let padding_needed = (4 - (data_size % 4)) % 4;

        self.inner.write_all(&compressed_data)?;

        add_padding(&mut self.inner, padding_needed as usize)?;

        self.inner.write_all(&checksum)?;

        let unpadded_size = block_header_size + data_size + self.options.check_type.checksum_size();
        self.index_records.push(IndexRecord {
            unpadded_size,
            uncompressed_size: block_uncompressed_size,
        });

        self.total_uncompressed_pos += block_uncompressed_size;

        Ok(())
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Consume the XzWriterMt and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    #[inline(always)]
    fn write_index(&mut self) -> Result<()> {
        write_xz_index(&mut self.inner, &self.index_records)
    }

    #[inline(always)]
    fn write_stream_footer(&mut self) -> Result<()> {
        write_xz_stream_footer(
            &mut self.inner,
            &self.index_records,
            self.options.check_type,
        )
    }

    /// Finishes the compression and returns the underlying writer.
    pub fn finish(mut self) -> Result<W> {
        self.write_stream_header()?;

        if !self.current_work_unit.is_empty() {
            self.send_work_unit()?;
        }

        // If no data was provided to compress, write an empty XZ file.
        if self.work_pool.next_index_to_dispatch() == 0 {
            // Write empty index and footer
            self.write_index()?;
            self.write_stream_footer()?;

            self.inner.flush()?;

            return Ok(self.inner);
        }

        // Mark the WorkPool as finished so it knows no more work is coming.
        self.work_pool.finish();

        // Wait for all remaining work to complete.
        while let Some(result) = self.work_pool.get_result(|_| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no more work to dispatch",
            ))
        })? {
            self.write_compressed_block(
                result.compressed_data,
                result.checksum,
                result.uncompressed_size,
            )?;
        }

        self.write_index()?;
        self.write_stream_footer()?;

        self.inner.flush()?;

        Ok(self.inner)
    }
}

/// The logic for a single worker thread.
fn worker_thread_logic(
    worker_handle: WorkerHandle<(u64, WorkUnit)>,
    result_tx: SyncSender<(u64, ResultUnit)>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    active_workers: Arc<AtomicU32>,
) {
    while !shutdown_flag.load(Ordering::Acquire) {
        let (index, work_unit) = match worker_handle.steal() {
            Some(work) => {
                active_workers.fetch_add(1, Ordering::Release);
                work
            }
            None => {
                // No more work available and queue is closed.
                break;
            }
        };

        let mut compressed_buffer = Vec::new();
        let uncompressed_size = work_unit.uncompressed_data.len() as u64;

        let mut checksum_calculator = ChecksumCalculator::new(work_unit.check_type);
        checksum_calculator.update(&work_unit.uncompressed_data);
        let checksum = checksum_calculator.finalize_to_bytes();

        let options = Lzma2Options {
            lzma_options: work_unit.lzma_options,
            ..Default::default()
        };

        let mut writer = Lzma2Writer::new(&mut compressed_buffer, options);
        let result = match writer.write_all(&work_unit.uncompressed_data) {
            Ok(_) => match writer.finish() {
                Ok(_) => ResultUnit {
                    compressed_data: compressed_buffer,
                    checksum,
                    uncompressed_size,
                },
                Err(error) => {
                    active_workers.fetch_sub(1, Ordering::Release);
                    set_error(error, &error_store, &shutdown_flag);
                    return;
                }
            },
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

impl<W: Write> Write for XzWriterMt<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut total_written = 0;
        let mut remaining_buf = buf;

        while !remaining_buf.is_empty() {
            let block_remaining = self.block_size.saturating_sub(self.current_work_unit.len());
            let to_write = remaining_buf.len().min(block_remaining);

            if to_write > 0 {
                self.current_work_unit
                    .extend_from_slice(&remaining_buf[..to_write]);
                total_written += to_write;
                remaining_buf = &remaining_buf[to_write..];
            }

            if self.current_work_unit.len() >= self.block_size {
                self.send_work_unit()?;
            }

            self.drain_available_results()?;
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> Result<()> {
        if !self.current_work_unit.is_empty() {
            self.send_work_unit()?;
        }

        // Wait for all pending work to complete and write the results.
        while let Some(result) = self.work_pool.try_get_result()? {
            self.write_compressed_block(
                result.compressed_data,
                result.checksum,
                result.uncompressed_size,
            )?;
        }

        self.inner.flush()
    }
}

impl<W: Write> AutoFinish for XzWriterMt<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}
