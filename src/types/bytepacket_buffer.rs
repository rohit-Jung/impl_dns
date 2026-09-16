type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn pos(&mut self) -> usize {
        return self.pos;
    }

    // change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn get_pos(&mut self) -> usize {
        self.pos
    }

    // give range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("range is not valid".into());
        }

        Ok(&self.buf[start..start + len])
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("Pos greater than 512 used".into());
        }

        Ok(self.buf[pos])
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        if pos >= 512 {
            return Err("Invalid buffer position set".into());
        }

        self.buf[pos] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        if pos >= 512 {
            return Err("Invalid buffer position set".into());
        }

        self.set(pos, (val >> 8) as u8)?;
        self.set(pos, (val & 0xFF) as u8)?;

        Ok(())
    }

    // reads single byte and move forward
    pub fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }

        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    // reads 16 bits (2 bytes)
    pub fn read_u16(&mut self) -> Result<u16> {
        let res: u16 = ((self.read()? as u16) << 8) | self.read()? as u16;
        Ok(res)
    }

    // reads 32 bits (4 bytes)
    pub fn read_u32(&mut self) -> Result<u32> {
        let res: u32 = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }

        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split(".") {
            let label_len = label.len();
            if label_len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(label_len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;
        Ok(())
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // keeping track of position as there might be jumps
        let mut pos = self.get_pos();

        let max_jumps = 5;
        let mut jumped: bool = false;
        let mut jump_performed = 0;

        let mut delim = "";
        loop {
            if jump_performed > max_jumps {
                return Err(format!("Jumps Limit of {} exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            // len = 1100 0010 | so 1100 is jump marker and other is offset
            // 0xC0 = 1100 0000 so &
            // last 2 msb are set if we need to jump
            //   first byte        second byte
            // ┌─────────────┬────────────────┐
            // │ 11 │ 6 bits │    8 bits      │
            // └─────────────┴────────────────┘
            // flags   offset
            if (len & 0xC0) == 0xC0 {
                // update it past the current label
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16; // get the second byte

                // remove the flag, shift it and add
                // infront of second byte
                // a ^ 1 = a complement
                let offset = ((len as u16 ^ 0xC0) << 8) | b2;

                // perform jump
                pos = offset as usize;
                jumped = true;
                jump_performed += 1;
                continue;
            } else {
                // mov a single byte forward
                pos += 1;

                // if len is zero we are done domain names are terminated by empty label
                if len == 0 {
                    break;
                }

                // append delimiter to output buffer
                outstr.push_str(delim);

                //extract the ascii byte for label
                let str = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str).to_lowercase());

                delim = ".";
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}
