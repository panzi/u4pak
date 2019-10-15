u4pak
=====

Unpack, pack, list, test and mount Unreal Engine 4 .pak archives.

Basic usage:

    u4pak.py list <archive>                 - list contens of .pak archive
    u4pak.py test <archive>                 - test archive integrity
    u4pak.py unpack <archive>               - extract .pak archive
    u4pak.py pack <archive> <files>         - create .pak archive
    u4pak.py mount <archive> <mount-point>  - mount archive as read-only file system

Only unencryped and uncompressed archives of version 1, 2, 3 and 4 are supported.
Note that only version 2 and 3 are tested and version 4 is read-only.

The `mount` command depends on the [llfuse](https://code.google.com/p/python-llfuse/)
Python package. If it's not available the rest is still working.

This script is compatible with Python 2.7 and 3 (tested with 2.7.5 and 3.3.2).

If you get errors saying anything about `'utf8' codec can't decode byte [...]` try to
use another encoding by passing `--encoding=iso-8859-1` or similar.

If you get an error message about an illegal file magic try to pass `--ignore-magic`.
If you get an error message about the archive version being 0 try to pass
`--force-version=1` (or a higher number).

File Format
-----------

Only what is absolutely necesarry to read archives is reverse engineered.

Byte order is little endian and the character encoding of file names seems to be
ASCII (or ISO-8859-1/UTF-8 that coincidentally only uses ASCII compatiple
characters).

Offsets and sizes seem to be 64bit or at least unsigned 32bit integers. If
interpreted as 32bit integers all sizes (except the size of file names) and offsets
are followed by another 32bit integer of the value 0, which makes me guess these
are 64bit values. Also some values exceed the range of signed 32bit integers, so
they have to be at least unsigned 32bit integers. This information was reverse
engineered from the Elemental [Demo](https://wiki.unrealengine.com/Linux_Demos)
for Linux (which contains a 2.5 GB .pak file).

Basic layout:

* Data Records
* Index
  * Index Header
  * Index Records
* Footer

In order to parse a file you need to read the footer first. The footer contains
an offset pointer to the start of the index records. The index records then
contain offset pointers to the data records.

### Record

    Offset  Size  Type         Description
         0     8  uint64_t     offset
         8     8  uint64_t     size (N)
        16     8  uint64_t     uncompressed size
        24     4  uint32_t     compression method:
                                  0x00 ... none
                                  0x01 ... zlib
                                  0x10 ... bias memory
                                  0x20 ... bias speed
    if version <= 1
        28     8  uint64_t     timestamp
    end
         ?    20  uint8_t[20]  data sha1 hash
    if version >= 3
     if compression method != 0x00
      ?+20     4  uint32_t     block count (M)
      ?+24  M*16  CB[M]        compression blocks
     end
         ?     1  uint8_t      is encrypted
       ?+1     4  uint32_t     compression block size
    end
    if version >= 4
         ?     1  uint32_t     unknown
    end

### Compression Block (CB)

Size: 16 bytes

    Offset  Size  Type         Description
         0     8  uint64_t     start offset:
                               Absolute offset of the start of the compression block.
         8     8  uint64_t     end offset:
                               Absolute offset of the end of the compression block.
                               This may not align completely with the start of the
                               next block.

### Data Record

    Offset  Size  Type            Description
         0     ?  Record          file metadata (offset field is 0, N = compressed_size)
         ?     N  uint8_t[N]      file data

### Index Record

    Offset  Size  Type            Description
         0     4  uint32_t        file name size (S)
         4     S  char[S]         file name
       4+S     ?  Record          file metadata

### Index

    Offset  Size  Type            Description
         0     4  uint32_t        mount point size (S)
         4     S  char[S]         mount point
       S+4     4  uint32_t        record count (N)
       S+8     ?  IndexRecord[N]  records

### Footer

Size: 44 bytes

    Offset  Size  Type         Description
         0     4  uint32_t     magic: 0x5A6F12E1
         4     4  uint32_t     version: 1, 2, or 3
         8     8  uint64_t     index offset
        16     8  uint64_t     index size
        24    20  uint8_t[20]  index sha1 hash

Related Projects
----------------

* [fezpak](https://github.com/panzi/fezpak): pack, unpack, list and mount FEZ .pak archives
* [psypkg](https://github.com/panzi/psypkg): pack, unpack, list and mount Psychonauts .pkg archives
* [bgebf](https://github.com/panzi/bgebf): unpack, list and mount Beyond Good and Evil .bf archives
* [unvpk](https://bitbucket.org/panzi/unvpk): extract, list, check and mount Valve .vpk archives
* [t2fbq](https://github.com/panzi/t2fbq): unpack, list and mount Trine 2 .fbq archives

BSD License
-----------
Copyright (c) 2014-2019 Mathias Panzenböck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
