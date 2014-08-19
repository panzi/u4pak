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

### Data Record

Maybe one of the two sizes is a relative offset to the next data record so that
in future versions there could be more fields after the data?

    Offset  Size  Type      Description
         0     8  ?         ? (always 0)
         8     8  uint64_t  data size (N)
        16     8  uint64_t  data size again
        24    29  ?         ? (first 4 and last 5 bytes are always 0)
        53     N  byte[N]   file data

### Index Record

    Offset  Size  Type      Description
         0    18  ?         ?
        18     4  uint32_t  name size including terminating nil (N)
        22     N  char[N]   file name (path seperator is '/', name does NOT start with '/')
      N+22     8  uint64_t  data record offset
      N+28     8  uint64_t  data size
      N+36     8  uint64_t  data size again
      N+44    11  ?         ? (first 4 bytes are always 0)

### Footer

Size: 62 bytes

    Offset  Size  Type      Description
         0    26  ?         ?
        26     8  uint64_t  offset of index
        34    28  ?         ?

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
