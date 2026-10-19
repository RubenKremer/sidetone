// G.726 ADPCM (16/24/32/40 kbit/s), from the soundkit-g726 crate
// (https://github.com/wavey-ai/soundkit, MIT licence), without the soundkit
// framework traits.
#![allow(dead_code)]
// G.726 is implemented as a Rust port of the Sun Microsystems G.72x reference
// code, whose header permits unrestricted use, copying, and modification
// without charge. No SpanDSP/libg726 C dependency is used here.

pub const G726_SAMPLE_RATE: u32 = 8_000;
pub const G726_CHANNELS: u8 = 1;

const G726_16K_BIT_RATE: u32 = 16_000;
const G726_24K_BIT_RATE: u32 = 24_000;
const G726_32K_BIT_RATE: u32 = 32_000;
const G726_40K_BIT_RATE: u32 = 40_000;

const POWER2: [i32; 15] = [
    1 << 0,
    1 << 1,
    1 << 2,
    1 << 3,
    1 << 4,
    1 << 5,
    1 << 6,
    1 << 7,
    1 << 8,
    1 << 9,
    1 << 10,
    1 << 11,
    1 << 12,
    1 << 13,
    1 << 14,
];

const Q_TAB_16: [i32; 1] = [261];
const DQLN_TAB_16: [i32; 4] = [116, 365, 365, 116];
const WI_TAB_16: [i32; 4] = [-22, 439, 439, -22];
const FI_TAB_16: [i32; 4] = [0, 0xE00, 0xE00, 0];

const Q_TAB_24: [i32; 3] = [8, 218, 331];
const DQLN_TAB_24: [i32; 8] = [-2048, 135, 273, 373, 373, 273, 135, -2048];
const WI_TAB_24: [i32; 8] = [-4, 30, 137, 582, 582, 137, 30, -4];
const FI_TAB_24: [i32; 8] = [0, 0x200, 0x400, 0xE00, 0xE00, 0x400, 0x200, 0];

const Q_TAB_32: [i32; 7] = [-124, 80, 178, 246, 300, 349, 400];
const DQLN_TAB_32: [i32; 16] = [
    -2048, 4, 135, 213, 273, 323, 373, 425, 425, 373, 323, 273, 213, 135, 4, -2048,
];
const WI_TAB_32: [i32; 16] = [
    -12, 18, 41, 64, 112, 198, 355, 1122, 1122, 355, 198, 112, 64, 41, 18, -12,
];
const FI_TAB_32: [i32; 16] = [
    0, 0, 0, 0x200, 0x200, 0x200, 0x600, 0xE00, 0xE00, 0x600, 0x200, 0x200, 0x200, 0, 0, 0,
];

const Q_TAB_40: [i32; 15] = [
    -122, -16, 68, 139, 198, 250, 298, 339, 378, 413, 445, 475, 502, 528, 553,
];
const DQLN_TAB_40: [i32; 32] = [
    -2048, -66, 28, 104, 169, 224, 274, 318, 358, 395, 429, 459, 488, 514, 539, 566, 566, 539, 514,
    488, 459, 429, 395, 358, 318, 274, 224, 169, 104, 28, -66, -2048,
];
const WI_TAB_40: [i32; 32] = [
    14, 14, 24, 39, 40, 41, 58, 100, 141, 179, 219, 280, 358, 440, 529, 696, 696, 529, 440, 358,
    280, 219, 179, 141, 100, 58, 41, 40, 39, 24, 14, 14,
];
const FI_TAB_40: [i32; 32] = [
    0, 0, 0, 0, 0, 0x200, 0x200, 0x200, 0x200, 0x200, 0x400, 0x600, 0x800, 0xA00, 0xC00, 0xC00,
    0xC00, 0xC00, 0xA00, 0x800, 0x600, 0x400, 0x200, 0x200, 0x200, 0x200, 0x200, 0, 0, 0, 0, 0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G726Rate {
    /// G.726-16, 2-bit ADPCM.
    Rate16000,
    /// G.726-24, 3-bit ADPCM.
    Rate24000,
    /// G.726-32, also known as the 4-bit G.721 ADPCM profile.
    Rate32000,
    /// G.726-40, 5-bit ADPCM.
    Rate40000,
}

impl G726Rate {
    pub fn from_bitrate(bit_rate: u32) -> Self {
        match bit_rate {
            G726_16K_BIT_RATE => Self::Rate16000,
            G726_24K_BIT_RATE => Self::Rate24000,
            G726_40K_BIT_RATE => Self::Rate40000,
            _ => Self::Rate32000,
        }
    }

    pub fn bits_per_sample(self) -> usize {
        match self {
            Self::Rate16000 => 2,
            Self::Rate24000 => 3,
            Self::Rate32000 => 4,
            Self::Rate40000 => 5,
        }
    }

    pub fn bit_rate(self) -> u32 {
        match self {
            Self::Rate16000 => G726_16K_BIT_RATE,
            Self::Rate24000 => G726_24K_BIT_RATE,
            Self::Rate32000 => G726_32K_BIT_RATE,
            Self::Rate40000 => G726_40K_BIT_RATE,
        }
    }

    fn samples_per_byte_group(self) -> usize {
        match self {
            Self::Rate16000 => 4,
            Self::Rate24000 => 8,
            Self::Rate32000 => 2,
            Self::Rate40000 => 8,
        }
    }

    fn bytes_per_group(self) -> usize {
        match self {
            Self::Rate16000 => 1,
            Self::Rate24000 => 3,
            Self::Rate32000 => 1,
            Self::Rate40000 => 5,
        }
    }

    fn sign_bit(self) -> u8 {
        1 << (self.bits_per_sample() - 1)
    }

    fn code_mask(self) -> u8 {
        (1 << self.bits_per_sample()) - 1
    }

    fn q_table(self) -> &'static [i32] {
        match self {
            Self::Rate16000 => &Q_TAB_16,
            Self::Rate24000 => &Q_TAB_24,
            Self::Rate32000 => &Q_TAB_32,
            Self::Rate40000 => &Q_TAB_40,
        }
    }

    fn dqln_table(self) -> &'static [i32] {
        match self {
            Self::Rate16000 => &DQLN_TAB_16,
            Self::Rate24000 => &DQLN_TAB_24,
            Self::Rate32000 => &DQLN_TAB_32,
            Self::Rate40000 => &DQLN_TAB_40,
        }
    }

    fn wi_table(self) -> &'static [i32] {
        match self {
            Self::Rate16000 => &WI_TAB_16,
            Self::Rate24000 => &WI_TAB_24,
            Self::Rate32000 => &WI_TAB_32,
            Self::Rate40000 => &WI_TAB_40,
        }
    }

    fn fi_table(self) -> &'static [i32] {
        match self {
            Self::Rate16000 => &FI_TAB_16,
            Self::Rate24000 => &FI_TAB_24,
            Self::Rate32000 => &FI_TAB_32,
            Self::Rate40000 => &FI_TAB_40,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G726Packing {
    /// G.726 left-justified raw packing (`ffmpeg -f g726`).
    Left,
    /// G.726 little-endian/right-justified raw packing (`ffmpeg -f g726le`).
    Right,
}

#[derive(Clone, Debug)]
struct G726Core {
    yl: i32,
    yu: i32,
    dms: i32,
    dml: i32,
    ap: i32,
    a: [i32; 2],
    b: [i32; 6],
    pk: [i32; 2],
    dq: [i32; 6],
    sr: [i32; 2],
    td: i32,
}

impl Default for G726Core {
    fn default() -> Self {
        Self {
            yl: 34_816,
            yu: 544,
            dms: 0,
            dml: 0,
            ap: 0,
            a: [0; 2],
            b: [0; 6],
            pk: [0; 2],
            dq: [32; 6],
            sr: [32; 2],
            td: 0,
        }
    }
}

impl G726Core {
    fn encode_sample(&mut self, sample: i16, rate: G726Rate) -> u8 {
        let sl = i32::from(sample) >> 2;
        let sezi = self.predictor_zero();
        let sez = sezi >> 1;
        let se = (sezi + self.predictor_pole()) >> 1;
        let d = sl - se;
        let y = self.step_size();
        let i = quantize(d, y, rate.q_table(), rate.code_mask()) as usize;
        let dq = reconstruct((i as u8 & rate.sign_bit()) != 0, rate.dqln_table()[i], y);
        let dq_mask = if rate == G726Rate::Rate40000 {
            0x7FFF
        } else {
            0x3FFF
        };
        let sr = if dq < 0 { se - (dq & dq_mask) } else { se + dq };
        let dqsez = sr + sez - se;
        self.update(
            y,
            rate.wi_table()[i] << 5,
            rate.fi_table()[i],
            dq,
            sr,
            dqsez,
            rate,
        );
        (i as u8) & rate.code_mask()
    }

    fn decode_code(&mut self, code: u8, rate: G726Rate) -> i16 {
        let i = usize::from(code & rate.code_mask());
        let sezi = self.predictor_zero();
        let sez = sezi >> 1;
        let sei = sezi + self.predictor_pole();
        let se = sei >> 1;
        let y = self.step_size();
        let dq = reconstruct((i as u8 & rate.sign_bit()) != 0, rate.dqln_table()[i], y);
        let dq_mask = if rate == G726Rate::Rate40000 {
            0x7FFF
        } else {
            0x3FFF
        };
        let sr = if dq < 0 { se - (dq & dq_mask) } else { se + dq };
        let dqsez = sr - se + sez;
        self.update(
            y,
            rate.wi_table()[i] << 5,
            rate.fi_table()[i],
            dq,
            sr,
            dqsez,
            rate,
        );
        (sr << 2).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
    }

    fn predictor_zero(&self) -> i32 {
        self.b
            .iter()
            .zip(self.dq.iter())
            .map(|(&b, &dq)| fmult(b >> 2, dq))
            .sum()
    }

    fn predictor_pole(&self) -> i32 {
        fmult(self.a[1] >> 2, self.sr[1]) + fmult(self.a[0] >> 2, self.sr[0])
    }

    fn step_size(&self) -> i32 {
        if self.ap >= 256 {
            return self.yu;
        }

        let y = self.yl >> 6;
        let dif = self.yu - y;
        let al = self.ap >> 2;
        if dif > 0 {
            y + ((dif * al) >> 6)
        } else if dif < 0 {
            y + ((dif * al + 0x3F) >> 6)
        } else {
            y
        }
    }

    fn update(&mut self, y: i32, wi: i32, fi: i32, dq: i32, sr: i32, dqsez: i32, rate: G726Rate) {
        let pk0 = i32::from(dqsez < 0);
        let mag = dq & 0x7FFF;

        let ylint = self.yl >> 15;
        let ylfrac = (self.yl >> 10) & 0x1F;
        let thr1 = (32 + ylfrac) << ylint;
        let thr2 = if ylint > 9 { 31 << 10 } else { thr1 };
        let dqthr = (thr2 + (thr2 >> 1)) >> 1;

        let tr = i32::from(self.td != 0 && mag > dqthr);

        self.yu = y + ((wi - y) >> 5);
        self.yu = self.yu.clamp(544, 5120);
        self.yl += self.yu + ((-self.yl) >> 6);

        let a2p = if tr != 0 {
            self.a = [0; 2];
            self.b = [0; 6];
            0
        } else {
            let pks1 = pk0 ^ self.pk[0];
            let mut a2p = self.a[1] - (self.a[1] >> 7);

            if dqsez != 0 {
                let fa1 = if pks1 != 0 { self.a[0] } else { -self.a[0] };
                if fa1 < -8191 {
                    a2p -= 0x100;
                } else if fa1 > 8191 {
                    a2p += 0xFF;
                } else {
                    a2p += fa1 >> 5;
                }

                if (pk0 ^ self.pk[1]) != 0 {
                    if a2p <= -12160 {
                        a2p = -12288;
                    } else if a2p >= 12416 {
                        a2p = 12288;
                    } else {
                        a2p -= 0x80;
                    }
                } else if a2p <= -12416 {
                    a2p = -12288;
                } else if a2p >= 12160 {
                    a2p = 12288;
                } else {
                    a2p += 0x80;
                }
            }

            self.a[1] = a2p;

            self.a[0] -= self.a[0] >> 8;
            if dqsez != 0 {
                if pks1 == 0 {
                    self.a[0] += 192;
                } else {
                    self.a[0] -= 192;
                }
            }

            let a1ul = 15360 - a2p;
            self.a[0] = self.a[0].clamp(-a1ul, a1ul);

            for index in 0..6 {
                let decay_shift = if rate == G726Rate::Rate40000 { 9 } else { 8 };
                self.b[index] -= self.b[index] >> decay_shift;
                if (dq & 0x7FFF) != 0 {
                    if (dq ^ self.dq[index]) >= 0 {
                        self.b[index] += 128;
                    } else {
                        self.b[index] -= 128;
                    }
                }
            }

            a2p
        };

        for index in (1..6).rev() {
            self.dq[index] = self.dq[index - 1];
        }
        self.dq[0] = if mag == 0 {
            if dq >= 0 {
                0x20
            } else {
                -0x3E0
            }
        } else {
            let exp = quan(mag, &POWER2) as i32;
            let mant = (mag << 6) >> exp;
            let value = (exp << 6) + mant;
            if dq >= 0 {
                value
            } else {
                value - 0x400
            }
        };

        self.sr[1] = self.sr[0];
        self.sr[0] = if sr == 0 {
            0x20
        } else if sr > 0 {
            let exp = quan(sr, &POWER2) as i32;
            (exp << 6) + ((sr << 6) >> exp)
        } else if sr > -32768 {
            let mag = -sr;
            let exp = quan(mag, &POWER2) as i32;
            (exp << 6) + ((mag << 6) >> exp) - 0x400
        } else {
            -0x3E0
        };

        self.pk[1] = self.pk[0];
        self.pk[0] = pk0;

        self.td = if tr != 0 { 0 } else { i32::from(a2p < -11776) };

        self.dms += (fi - self.dms) >> 5;
        self.dml += ((fi << 2) - self.dml) >> 7;

        if tr != 0 {
            self.ap = 256;
        } else if y < 1536 || self.td != 0 || ((self.dms << 2) - self.dml).abs() >= (self.dml >> 3)
        {
            self.ap += (0x200 - self.ap) >> 4;
        } else {
            self.ap += -self.ap >> 4;
        }
    }
}

fn quan(value: i32, table: &[i32]) -> usize {
    table
        .iter()
        .position(|&threshold| value < threshold)
        .unwrap_or(table.len())
}

fn fmult(an: i32, srn: i32) -> i32 {
    let anmag = if an > 0 { an } else { (-an) & 0x1FFF };
    let anexp = quan(anmag, &POWER2) as i32 - 6;
    let anmant = if anmag == 0 {
        32
    } else if anexp >= 0 {
        anmag >> anexp
    } else {
        anmag << -anexp
    };
    let wanexp = anexp + ((srn >> 6) & 0x0F) - 13;
    let wanmant = (anmant * (srn & 0x3F) + 0x30) >> 4;
    let retval = if wanexp >= 0 {
        (wanmant << wanexp) & 0x7FFF
    } else {
        wanmant >> -wanexp
    };

    if (an ^ srn) < 0 {
        -retval
    } else {
        retval
    }
}

fn quantize(d: i32, y: i32, table: &[i32], code_mask: u8) -> u8 {
    let dqm = d.abs();
    let exp = quan(dqm >> 1, &POWER2) as i32;
    let mant = ((dqm << 7) >> exp) & 0x7F;
    let dl = (exp << 7) + mant;
    let dln = dl - (y >> 2);
    let i = quan(dln, table);

    if d < 0 {
        code_mask - i as u8
    } else if i == 0 {
        code_mask
    } else {
        i as u8
    }
}

fn reconstruct(sign: bool, dqln: i32, y: i32) -> i32 {
    let dql = dqln + (y >> 2);
    if dql < 0 {
        if sign {
            -0x8000
        } else {
            0
        }
    } else {
        let dex = (dql >> 7) & 15;
        let dqt = 128 + (dql & 127);
        let dq = (dqt << 7) >> (14 - dex);
        if sign {
            dq - 0x8000
        } else {
            dq
        }
    }
}

fn pack_code_group(codes: &[u8], bits_per_code: usize, packing: G726Packing, output: &mut [u8]) {
    output.fill(0);

    match packing {
        G726Packing::Left => {
            let mut bit_index = 0;
            for &code in codes {
                for bit in (0..bits_per_code).rev() {
                    if ((code >> bit) & 1) != 0 {
                        output[bit_index / 8] |= 1 << (7 - (bit_index % 8));
                    }
                    bit_index += 1;
                }
            }
        }
        G726Packing::Right => {
            let mut bit_index = 0;
            for &code in codes {
                for bit in 0..bits_per_code {
                    if ((code >> bit) & 1) != 0 {
                        output[bit_index / 8] |= 1 << (bit_index % 8);
                    }
                    bit_index += 1;
                }
            }
        }
    };
}

fn unpack_code_group(input: &[u8], bits_per_code: usize, packing: G726Packing, output: &mut [u8]) {
    output.fill(0);

    match packing {
        G726Packing::Left => {
            let mut bit_index = 0;
            for code in output {
                for _ in 0..bits_per_code {
                    *code <<= 1;
                    *code |= (input[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
                    bit_index += 1;
                }
            }
        }
        G726Packing::Right => {
            let mut bit_index = 0;
            for code in output {
                for bit in 0..bits_per_code {
                    *code |= ((input[bit_index / 8] >> (bit_index % 8)) & 1) << bit;
                    bit_index += 1;
                }
            }
        }
    };
}

pub struct G726Encoder {
    core: G726Core,
    rate: G726Rate,
    packing: G726Packing,
    pending_samples: Vec<i16>,
}

impl G726Encoder {
    pub fn try_new(rate: G726Rate, packing: G726Packing) -> Result<Self, String> {
        Ok(Self {
            core: G726Core::default(),
            rate,
            packing,
            pending_samples: Vec::with_capacity(rate.samples_per_byte_group()),
        })
    }

    pub fn new_32k_left() -> Self {
        Self::try_new(G726Rate::Rate32000, G726Packing::Left)
            .expect("failed to initialize G.726 encoder")
    }

    pub fn new_32k_right() -> Self {
        Self::try_new(G726Rate::Rate32000, G726Packing::Right)
            .expect("failed to initialize G.726 encoder")
    }

    pub fn new_16k_left() -> Self {
        Self::try_new(G726Rate::Rate16000, G726Packing::Left)
            .expect("failed to initialize G.726-16 encoder")
    }

    pub fn new_24k_left() -> Self {
        Self::try_new(G726Rate::Rate24000, G726Packing::Left)
            .expect("failed to initialize G.726-24 encoder")
    }

    pub fn new_40k_left() -> Self {
        Self::try_new(G726Rate::Rate40000, G726Packing::Left)
            .expect("failed to initialize G.726-40 encoder")
    }

    pub fn encode_to_vec(&mut self, input: &[i16], output: &mut Vec<u8>) -> Result<usize, String> {
        let start = output.len();
        let required = self.required_encode_bytes(input.len(), false);
        output.resize(start + required, 0);
        let written = self.encode_i16(input, &mut output[start..])?;
        output.truncate(start + written);
        Ok(written)
    }

    pub fn flush_into(&mut self, output: &mut [u8]) -> Result<usize, String> {
        let required = self.required_encode_bytes(0, true);
        if output.len() < required {
            return Err(format!(
                "Output buffer too small for G.726 flush: need {}, have {}",
                required,
                output.len()
            ));
        }

        if self.pending_samples.is_empty() {
            return Ok(0);
        }

        let mut samples = self.pending_samples.clone();
        samples.resize(self.rate.samples_per_byte_group(), 0);
        self.pending_samples.clear();
        Ok(self.encode_complete_samples(&samples, output))
    }

    pub fn flush_to_vec(&mut self, output: &mut Vec<u8>) -> Result<usize, String> {
        let start = output.len();
        let required = self.required_encode_bytes(0, true);
        output.resize(start + required, 0);
        let written = self.flush_into(&mut output[start..])?;
        output.truncate(start + written);
        Ok(written)
    }

    pub fn rate(&self) -> G726Rate {
        self.rate
    }

    pub fn packing(&self) -> G726Packing {
        self.packing
    }

    fn required_encode_bytes(&self, input_samples: usize, flush: bool) -> usize {
        let group_samples = self.rate.samples_per_byte_group();
        let total_samples = self.pending_samples.len() + input_samples;
        let groups = if flush {
            total_samples.div_ceil(group_samples)
        } else {
            total_samples / group_samples
        };
        groups * self.rate.bytes_per_group()
    }

    fn encode_complete_samples(&mut self, samples: &[i16], output: &mut [u8]) -> usize {
        let mut written = 0;
        let group_samples = self.rate.samples_per_byte_group();
        let group_bytes = self.rate.bytes_per_group();
        let bits_per_code = self.rate.bits_per_sample();
        let mut codes = vec![0u8; group_samples];

        for group in samples.chunks_exact(group_samples) {
            for (code, &sample) in codes.iter_mut().zip(group) {
                *code = self.core.encode_sample(sample, self.rate);
            }
            pack_code_group(
                &codes,
                bits_per_code,
                self.packing,
                &mut output[written..written + group_bytes],
            );
            written += group_bytes;
        }
        written
    }
}

impl Default for G726Encoder {
    fn default() -> Self {
        Self::new_32k_left()
    }
}

pub struct G726Decoder {
    core: G726Core,
    rate: G726Rate,
    packing: G726Packing,
    pending_bytes: Vec<u8>,
}

impl G726Decoder {
    pub fn try_new(rate: G726Rate, packing: G726Packing) -> Result<Self, String> {
        Ok(Self {
            core: G726Core::default(),
            rate,
            packing,
            pending_bytes: Vec::with_capacity(rate.bytes_per_group()),
        })
    }

    pub fn new_32k_left() -> Self {
        Self::try_new(G726Rate::Rate32000, G726Packing::Left)
            .expect("failed to initialize G.726 decoder")
    }

    pub fn new_32k_right() -> Self {
        Self::try_new(G726Rate::Rate32000, G726Packing::Right)
            .expect("failed to initialize G.726 decoder")
    }

    pub fn new_16k_left() -> Self {
        Self::try_new(G726Rate::Rate16000, G726Packing::Left)
            .expect("failed to initialize G.726-16 decoder")
    }

    pub fn new_24k_left() -> Self {
        Self::try_new(G726Rate::Rate24000, G726Packing::Left)
            .expect("failed to initialize G.726-24 decoder")
    }

    pub fn new_40k_left() -> Self {
        Self::try_new(G726Rate::Rate40000, G726Packing::Left)
            .expect("failed to initialize G.726-40 decoder")
    }

    pub fn sample_rate(&self) -> u32 {
        G726_SAMPLE_RATE
    }

    pub fn channels(&self) -> u8 {
        G726_CHANNELS
    }

    pub fn rate(&self) -> G726Rate {
        self.rate
    }

    pub fn packing(&self) -> G726Packing {
        self.packing
    }

    pub fn flush(&mut self) -> Result<(), String> {
        if self.pending_bytes.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "G.726 stream ended with {} trailing partial-packet byte(s)",
                self.pending_bytes.len()
            ))
        }
    }
}

impl Default for G726Decoder {
    fn default() -> Self {
        Self::new_32k_left()
    }
}

impl G726Decoder {
    /// Decodes whole code groups; a trailing partial group waits for the next call.
    pub fn decode_vec(&mut self, input: &[u8]) -> Vec<i16> {
        let group_bytes = self.rate.bytes_per_group();
        let mut bytes = std::mem::take(&mut self.pending_bytes);
        bytes.extend_from_slice(input);
        let complete = (bytes.len() / group_bytes) * group_bytes;
        let group_samples = self.rate.samples_per_byte_group();
        let bits_per_code = self.rate.bits_per_sample();
        let mut codes = vec![0u8; group_samples];
        let mut out = Vec::with_capacity(complete / group_bytes * group_samples);
        for group in bytes[..complete].chunks_exact(group_bytes) {
            unpack_code_group(group, bits_per_code, self.packing, &mut codes);
            for &code in &codes {
                out.push(self.core.decode_code(code, self.rate));
            }
        }
        self.pending_bytes.extend_from_slice(&bytes[complete..]);
        out
    }
}

impl G726Encoder {
    pub fn encode_i16(&mut self, input: &[i16], output: &mut [u8]) -> Result<usize, String> {
        let required = self.required_encode_bytes(input.len(), false);
        if output.len() < required {
            return Err(format!(
                "G.726 output buffer too small: need {required}, have {}",
                output.len()
            ));
        }
        let group_samples = self.rate.samples_per_byte_group();
        let total_samples = self.pending_samples.len() + input.len();
        let complete_samples = (total_samples / group_samples) * group_samples;
        let mut samples = Vec::with_capacity(total_samples);
        samples.extend_from_slice(&self.pending_samples);
        samples.extend_from_slice(input);
        let written = if complete_samples == 0 {
            0
        } else {
            self.encode_complete_samples(&samples[..complete_samples], output)
        };
        self.pending_samples.clear();
        self.pending_samples
            .extend_from_slice(&samples[complete_samples..]);
        Ok(written)
    }
}
