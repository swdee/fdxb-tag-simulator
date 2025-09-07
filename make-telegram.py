#!/usr/bin/env python3
# FDX-B 128-bit telegram generator
#

import argparse
import random
from typing import List

HEADER_BITS = "10000000000"  # 11 bits, fixed
MAX_NATIONAL = (1 << 38) - 1  # 274,877,906,943

def int_to_bits(value: int, width: int) -> str:
    if value < 0 or value >= (1 << width):
        raise ValueError(f"value {value} doesn't fit in {width} bits")
    return format(value, f"0{width}b")

def int_to_bits_lsb(value: int, width: int) -> str:
    if value < 0 or value >= (1 << width):
        raise ValueError(f"value {value} doesn't fit in {width} bits")
    return format(value, f"0{width}b")[::-1]  # LSB-first across the whole field

def sep_chunks(bits: str, sep: str = '1') -> list[str]:
    if len(bits) % 8 != 0:
        raise ValueError(f"length {len(bits)} not multiple of 8")
    return [sep + bits[i:i+8] for i in range(0, len(bits), 8)]

def lsb_chunk_to_byte(chunk8: str) -> int:
    """Convert an 8-char bitstring that is LSB-first into an integer byte value."""
    if len(chunk8) != 8:
        raise ValueError("chunk must be 8 bits")
    # Reverse to MSB-first then int(..., 2); equivalent to sum((bit<<i))
    return int(chunk8[::-1], 2)

def bits_lsb_from_byte(b: int) -> str:
    """Return 8 bits LSB-first for a byte value 0..255."""
    return ''.join('1' if ((b >> i) & 1) else '0' for i in range(8))

def crc16_kermit(byte_list: List[int]) -> int:
    """
    CRC-16/KERMIT: poly=0x1021 (reflected 0x8408), init=0x0000,
    refin=True, refout=True, xorout=0x0000.
    Process bytes in natural order.
    """
    poly = 0x8408
    crc = 0x0000
    for b in byte_list:
        crc ^= b
        for _ in range(8):
            crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF  # on-wire: low byte first


def make_fdxb_frame(country: int,
                    national: int,
                    animal: int = 1) -> str:

    # Build the 64-bit ID block
    # [national 38][country 10][extra bit 1][rfu 14=0][animal bit 1]
    national_bits   = int_to_bits_lsb(national, 38)
    country_bits  = int_to_bits_lsb(country, 10)
    extra_bit     = '0'
    reserved_bits = '0' * 14
    animal_bit    = '1' if animal else '0'

    id_bits_lsb = national_bits + country_bits + extra_bit + reserved_bits + animal_bit  # 64 bits (LSB-first chunks)
    assert len(id_bits_lsb) == 64

    # ID bytes as values, interpreting each 8-bit chunk as LSB-first
    id_chunks = [id_bits_lsb[i:i+8] for i in range(0, 64, 8)]
    id_bytes  = [lsb_chunk_to_byte(c) for c in id_chunks]  # 8 bytes

    # CRC over the 8 ID bytes (Kermit). On-wire order is low byte, then high byte.
    crc = crc16_kermit(id_bytes)
    crc_lo, crc_hi = crc & 0xFF, (crc >> 8) & 0xFF

    # Build the framed bitstream:
    # header (11) + 8*(1+8) for ID + 2*(1+8) for CRC + 3*(1+8) for trailer = 11 + 13*9 = 128 bits
    parts = [HEADER_BITS]

    # Append ID bytes: each as '1' + 8 bits LSB-first
    for b in id_bytes:
        parts.append('1' + bits_lsb_from_byte(b))

    # Append CRC bytes (low first), each LSB-first with leading '1'
    parts.append('1' + bits_lsb_from_byte(crc_lo))
    parts.append('1' + bits_lsb_from_byte(crc_hi))

    # Append three extra data block bytes (zeros) which are unused.
    for _ in range(3):
        parts.append('1' + '0'*8)

    frame128 = ''.join(parts)
    assert len(frame128) == 128

    return frame128


def main():
    ap = argparse.ArgumentParser(description="FDX-B 128-bit telegram generator (with CRC and parity)")
    ap.add_argument("--country", type=int, help="Country code 0..999 (decimal). 10-bit field in frame.")
    ap.add_argument("--national", type=int, help="National ID 0..999999999999 (decimal). 38-bit field in frame.")
    ap.add_argument("--animal", type=int, default=1, choices=[0,1], help="Animal bit (default 1).")
    ap.add_argument("--seed", type=int, help="Random seed for reproducibility.")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    country = args.country if args.country is not None else random.randint(0, 999)

    # Choose or validate national (0..MAX_NATIONAL)
    if args.national is None:
        national = random.randint(0, MAX_NATIONAL)
    else:
        if not (0 <= args.national <= MAX_NATIONAL):
            raise SystemExit(
                f"national must be in 0..{MAX_NATIONAL} "
                f"(got {args.national}). FDX-B national is 38 bits."
            )
        national = args.national


    if not (0 <= country <= 999):
        raise SystemExit("country must be in 0..999")
    if not (0 <= national <= 999_999_999_999):
        raise SystemExit("national must be in 0..999999999999")

    frame = make_fdxb_frame(country=country, national=national, animal=args.animal)

    # Line 1: 128-bit frame
    print(f"128 bit telegram: {frame}")
    # Line 2: combined 15-digit decimal code
    print(f"Encoded ID: {country:03d}{national:012d}")

if __name__ == "__main__":
    main()
