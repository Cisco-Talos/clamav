const CRC32_POLY: u32 = 0xEDB88320;

const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = make_crc32_table();

/// CRC_32_ISO_HDLC
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub(crate) fn new() -> Self {
        Self { state: 0xFFFFFFFF }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.state ^ (byte as u32)) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC32_TABLE[index];
        }
    }

    pub(crate) fn finalize(self) -> u32 {
        self.state ^ 0xFFFFFFFF
    }

    pub(crate) fn checksum(data: &[u8]) -> u32 {
        let mut crc = Self::new();
        crc.update(data);
        crc.finalize()
    }
}

const CRC64_POLY: u64 = 0xC96C5795D7870F42;

const fn make_crc64_table() -> [u64; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC64_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC64_TABLE: [u64; 256] = make_crc64_table();

/// CRC_64_XZ
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Crc64 {
    state: u64,
}

impl Crc64 {
    pub(crate) fn new() -> Self {
        Self {
            state: 0xFFFFFFFFFFFFFFFF,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.state ^ (byte as u64)) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC64_TABLE[index];
        }
    }

    pub(crate) fn finalize(self) -> u64 {
        self.state ^ 0xFFFFFFFFFFFFFFFF
    }

    pub(crate) fn checksum(data: &[u8]) -> u64 {
        let mut crc = Self::new();
        crc.update(data);
        crc.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_DATA: &[u8] = &[1, 2, 3, 7, 16, 31, 64, 255];

    #[test]
    fn crc32_empty() {
        assert_eq!(Crc32::checksum(&[]), 0);
    }

    #[test]
    fn crc64_empty() {
        assert_eq!(Crc64::checksum(&[]), 0);
    }

    #[test]
    fn crc32_simple_data() {
        assert_eq!(Crc32::checksum(SIMPLE_DATA), 2428203834);
    }

    #[test]
    fn crc64_simple_data() {
        assert_eq!(Crc64::checksum(SIMPLE_DATA), 11721292222009571391);
    }
}
