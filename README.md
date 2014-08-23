u4pak
=====

Unpack, list and mount Unreal Engine 4 .pak archives.

Basic usage:

	u4pak.py list <archive>                 - list contens of .pak archive
	u4pak.py unpack <archive>               - extract .pak archive
	u4pak.py mount <archive> <mount-point>  - mount archive as read-only file system

The `mount` command depends on the [llfuse](https://code.google.com/p/python-llfuse/)
Python package. If it's not available the rest is still working.

This script is compatible with Python 2.7 and 3 (tested with 2.7.5 and 3.3.2).

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
 * Index Records
 * Footer

In order to parse a file you need to read the footer first. The footer contains
an offset pointer to the start of the index records. The index records then
contain offset pointers to the data records.

### Entry

There are two fields that give the size of the data. My guess is that the pak
format supports optional compression and one size is the compressed size and
the other the uncompressed. If that is true then all archive files I have access
to don't use compression, because for all these archives the sizes match exactly.

    Offset  Size  Type      Description
         0     8  int64     offset
         8     8  int64     size (N)
        16     8  int64     uncompressed size
        24     4  int32     compression method - 0x00 = none, 0x01 = zlib, 0x10 bias memory, 0x20 bias speed
if version is 1 or smaller
        28     8  int64     timestamp
end
        36    20  uint8[20] sha1 hash
if version is 3 or bigger
  if compression method is not 0x00
        56     4  uint32_t  block count (M)
        60  M*16  CB[M]     compression blocks
  end
         ?     1  uint8     is encrypted
       ?+1     8  uint32    compression block size
       ?+9     N  uint8[N]  file data

### compression block (CB)

    Offset  Size  Type      Description
         0     8  int64     start offset - Offset of the start of a compression block. Offset is absolute.
         8     8  int64     end offset   - Offset of the end of a compression block. This may not align completely with the start of the next block. Offset is absolute.
		
### Index Record

    Offset  Size  Type      Description
         0     4  int32     mount point size (N)
		 4     N  char[N]   mount point
	   4+N     4  int32     entries count
for entries count
    8+N+ce     4  int32     filename size (M)
   12+N+ce     M  char[M]   filename
 12+N+ce+M   ...  Entry     Entry

### Footer

    Offset  Size  Type      Description
         0     4  uint32    magic - 0x5A6F12E1
         4     4  int32     version - can be 1, 2, or 3
         8     8  int64     index offset
        16     8  int64     index size
        24    20  uint8[20] index sha1 hash

Related Projects
----------------

 * [fezpak](https://github.com/panzi/fezpak): pack, unpack, list and mount FEZ .pak archives
 * [psypkg](https://github.com/panzi/psypkg): pack, unpack, list and mount Psychonauts .pkg archives
 * [bgebf](https://github.com/panzi/bgebf): unpack, list and mount Beyond Good and Evil .bf archives
 * [unvpk](https://bitbucket.org/panzi/unvpk): extract, list, check and mount Valve .vpk archives
 * [t2fbq](https://github.com/panzi/t2fbq): unpack, list and mount Trine 2 .fbq archives

BSD License
-----------
Copyright (c) 2014 Mathias Panzenböck

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
