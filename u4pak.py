#!/usr/bin/env python
# coding=UTF-8
#
# Copyright (c) 2014 Mathias Panzenböck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations, with_statement, division, print_function

import os
import io
import sys
import hashlib
import zlib
import math
import argparse

from struct import unpack as st_unpack, pack as st_pack
from collections import OrderedDict
from io import DEFAULT_BUFFER_SIZE
from binascii import hexlify
from typing import NamedTuple, Optional, Tuple, List, Dict, Set, Iterable, Iterator, Callable, IO, Any, Union

try:
	import llfuse # type: ignore
except ImportError:
	HAS_LLFUSE = False
else:
	HAS_LLFUSE = True

HAS_STAT_NS = hasattr(os.stat_result, 'st_atime_ns')

__all__ = 'read_index', 'pack'

# for Python < 3.3 and Windows
def highlevel_sendfile(outfile: io.BufferedWriter, infile: io.BufferedReader, offset: int, size: int) -> None:
	infile.seek(offset,0)
	buf_size = DEFAULT_BUFFER_SIZE
	buf = bytearray(buf_size)
	while size > 0:
		if size >= buf_size:
			n = infile.readinto(buf) or 0
			if n < buf_size:
				raise IOError("unexpected end of file")
			outfile.write(buf)
			size -= buf_size
		else:
			data = infile.read(size) or b''
			if len(data) < size:
				raise IOError("unexpected end of file")
			outfile.write(data)
			size = 0

if hasattr(os, 'sendfile'):
	def os_sendfile(outfile: io.BufferedWriter, infile: io.BufferedReader, offset: int, size: int) -> None:
		try:
			out_fd = outfile.fileno()
			in_fd  = infile.fileno()
		except:
			highlevel_sendfile(outfile, infile, offset, size)
		else:
			# size == 0 has special meaning for some sendfile implentations
			if size > 0:
				os.sendfile(out_fd, in_fd, offset, size)
	sendfile = os_sendfile
else:
	sendfile = highlevel_sendfile

def raise_check_error(ctx: Optional[Record], message: str) -> None:
	if ctx is None:
		raise ValueError(message)

	elif isinstance(ctx, Record):
		raise ValueError("%s: %s" % (ctx.filename, message))

	else:
		raise ValueError("%s: %s" % (ctx, message))

class FragInfo(object):
	__slots__ = '__frags', '__size'

	__size: int
	__frags: List[Tuple[int, int]]

	def __init__(self, size: int, frags: Optional[List[Tuple[int, int]]] = None) -> None:
		self.__size  = size
		self.__frags = []
		if frags:
			for start, end in frags:
				self.add(start, end)

	@property
	def size(self) -> int:
		return self.__size

	def __iter__(self) -> Iterator[Tuple[int, int]]:
		return iter(self.__frags)

	def __len__(self) -> int:
		return len(self.__frags)

	def __repr__(self) -> str:
		return 'FragInfo(%r,%r)' % (self.__size, self.__frags)

	def add(self, new_start: int, new_end: int) -> None:
		if new_start >= new_end:
			return

		elif new_start >= self.__size or new_end > self.__size:
			raise IndexError("range out of bounds: (%r, %r]" % (new_start, new_end))

		frags = self.__frags
		for i, (start, end) in enumerate(frags):
			if new_end < start:
				frags.insert(i, (new_start, new_end))
				return

			elif new_start <= start:
				if new_end <= end:
					frags[i] = (new_start, end)
					return

			elif new_start <= end:
				if new_end > end:
					new_start = start
			else:
				continue

			j = i+1
			n = len(frags)
			while j < n:
				next_start, next_end = frags[j]
				if next_start <= new_end:
					j += 1
					if next_end > new_end:
						new_end = next_end
						break
				else:
					break

			frags[i:j] = [(new_start, new_end)]
			return

		frags.append((new_start, new_end))

	def invert(self) -> FragInfo:
		inverted = FragInfo(self.__size)
		append   = inverted.__frags.append
		prev_end = 0

		for start, end in self.__frags:
			if start > prev_end:
				append((prev_end, start))
			prev_end = end

		if self.__size > prev_end:
			append((prev_end, self.__size))

		return inverted

	def free(self) -> int:
		free     = 0
		prev_end = 0

		for start, end in self.__frags:
			free += start - prev_end
			prev_end = end

		free += self.__size - prev_end

		return free

class Pak(object):
	__slots__ = ('version', 'index_offset', 'index_size', 'footer_offset', 'index_sha1', 'mount_point', 'records')

	version: int
	index_offset: int
	index_size: int
	footer_offset: int
	index_sha1: bytes
	mount_point: Optional[str]
	records: List[Record]

	def __init__(self, version: int, index_offset: int, index_size: int, footer_offset: int, index_sha1: bytes, mount_point: Optional[str] = None, records: Optional[List[Record]] = None) -> None:
		self.version       = version
		self.index_offset  = index_offset
		self.index_size    = index_size
		self.footer_offset = footer_offset
		self.index_sha1    = index_sha1
		self.mount_point   = mount_point
		self.records       = records or []

	def __len__(self) -> int:
		return len(self.records)

	def __iter__(self) -> Iterator[Record]:
		return iter(self.records)

	def __repr__(self) -> str:
		return 'Pak(version=%r, index_offset=%r, index_size=%r, footer_offset=%r, index_sha1=%r, mount_point=%r, records=%r)' % (
			self.version, self.index_offset, self.index_size, self.footer_offset, self.index_sha1, self.mount_point, self.records)

	def check_integrity(self, stream: io.BufferedReader, callback: Callable[[Optional[Record], str], None] = raise_check_error, ignore_null_checksums: bool = False) -> None:
		index_offset = self.index_offset
		buf = bytearray(DEFAULT_BUFFER_SIZE)

		read_record: Callable[[io.BufferedReader, str], Record]
		if self.version == 1:
			read_record = read_record_v1

		elif self.version == 2:
			read_record = read_record_v2

		elif self.version == 3:
			read_record = read_record_v3

		elif self.version == 4:
			read_record = read_record_v4

		elif self.version == 7:
			read_record = read_record_v7

		else:
			raise ValueError(f'unsupported version: {self.version}')

		def check_data(ctx, offset, size, sha1):
			if ignore_null_checksums and sha1 == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
				return

			hasher = hashlib.sha1()
			stream.seek(offset, 0)

			while size > 0:
				if size >= DEFAULT_BUFFER_SIZE:
					size -= stream.readinto(buf)
					hasher.update(buf)
				else:
					rest = stream.read(size)
					assert rest is not None
					hasher.update(rest)
					size = 0

			if hasher.digest() != sha1:
				callback(ctx,
						 'checksum missmatch:\n'
						 '\tgot:      %s\n'
						 '\texpected: %s' % (
							 hasher.hexdigest(),
							 hexlify(sha1).decode('latin1')))

		# test index sha1 sum
		check_data("<archive index>", index_offset, self.index_size, self.index_sha1)

		for r1 in self:
			stream.seek(r1.offset, 0)
			r2 = read_record(stream, r1.filename)

			# test index metadata
			if r2.offset != 0:
				callback(r2, 'data record offset field is not 0 but %d' % r2.offset)

			if not same_metadata(r1, r2):
				callback(r1, 'metadata missmatch:\n%s' % metadata_diff(r1, r2))

			if r1.compression_method not in COMPR_METHODS:
				callback(r1, 'unknown compression method: 0x%02x' % r1.compression_method)

			if r1.compression_method == COMPR_NONE and r1.compressed_size != r1.uncompressed_size:
				callback(r1, 'file is not compressed but compressed size (%d) differes from uncompressed size (%d)' %
						 (r1.compressed_size, r1.uncompressed_size))

			if r1.data_offset + r1.compressed_size > index_offset:
				callback(None, 'data bleeds into index')

			# test file sha1 sum
			if ignore_null_checksums and r1.sha1 == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
				pass
			elif r1.compression_blocks is None:
				check_data(r1, r1.data_offset, r1.compressed_size, r1.sha1)
			else:
				hasher = hashlib.sha1()
				base_offset = r1.base_offset
				for start_offset, end_offset in r1.compression_blocks:
					block_size = end_offset - start_offset
					stream.seek(base_offset + start_offset, 0)
					data = stream.read(block_size)
					hasher.update(data)
				
				if hasher.digest() != r1.sha1:
					callback(r1,
							'checksum missmatch:\n'
							'\tgot:      %s\n'
							'\texpected: %s' % (
								hasher.hexdigest(),
								hexlify(r1.sha1).decode('latin1')))

	def unpack(self, stream: io.BufferedReader, outdir: str=".", callback: Callable[[str], None] = lambda name: None) -> None:
		for record in self:
			record.unpack(stream, outdir, callback)

	def unpack_only(self, stream: io.BufferedReader, files: Iterable[str], outdir: str = ".", callback: Callable[[str], None] = lambda name: None) -> None:
		for record in self:
			if shall_unpack(files, record.filename):
				record.unpack(stream, outdir, callback)

	def frag_info(self) -> FragInfo:
		frags = FragInfo(self.footer_offset + 44)
		frags.add(self.index_offset, self.index_offset + self.index_size)
		frags.add(self.footer_offset, frags.size)

		for record in self.records:
			frags.add(record.offset, record.data_offset + record.compressed_size)

		return frags

	def print_list(self, details: bool = False, human: bool = False, delim: str = "\n", sort_key_func: Optional[Callable[[Record], Any]] = None, out: IO[str] = sys.stdout) -> None:
		records = self.records

		if sort_key_func:
			records = sorted(records, key=sort_key_func)

		if details:
			size_to_str: Callable[[int], str]
			if human:
				size_to_str = human_size
			else:
				size_to_str = str

			count = 0
			sum_size = 0
			out.write("    Offset        Size  Compr-Method  Compr-Size  SHA1                                      Name%s" % delim)
			for record in records:
				size  = size_to_str(record.uncompressed_size)
				sha1  = hexlify(record.sha1).decode('latin1')
				cmeth = record.compression_method

				if cmeth == COMPR_NONE:
					out.write("%10u  %10s             -           -  %s  %s%s" % (
						record.data_offset, size, sha1, record.filename, delim))
				else:
					out.write("%10u  %10s  %12s  %10s  %s  %s%s" % (
						record.data_offset, size, COMPR_METHOD_NAMES[cmeth],
						size_to_str(record.compressed_size), sha1,
						record.filename, delim))
				count += 1
				sum_size += record.uncompressed_size
			out.write("%d file(s) (%s) %s" % (count, size_to_str(sum_size), delim))
		else:
			for record in records:
				out.write("%s%s" % (record.filename, delim))

	def print_info(self, human: bool = False, out: IO[str] = sys.stdout) -> None:
		size_to_str: Callable[[int], str]
		if human:
			size_to_str = human_size
		else:
			size_to_str = str

		csize = 0
		size  = 0
		for record in self.records:
			csize += record.compressed_size
			size  += record.uncompressed_size

		frags = self.frag_info()

		out.write("Pak Version: %d\n" % self.version)
		out.write("Index SHA1:  %s\n" % hexlify(self.index_sha1).decode('latin1'))
		out.write("Mount Point: %s\n" % self.mount_point)
		out.write("File Count:  %d\n" % len(self.records))
		out.write("Archive Size:            %10s\n" % size_to_str(frags.size))
		out.write("Unallocated Bytes:       %10s\n" % size_to_str(frags.free()))
		out.write("Sum Compr. Files Size:   %10s\n" % size_to_str(csize))
		out.write("Sum Uncompr. Files Size: %10s\n" % size_to_str(size))
		out.write("\n")
		out.write("Fragments (%d):\n" % len(frags))

		for start, end in frags:
			out.write("\t%10s ... %10s (%10s)\n" % (start, end, size_to_str(end - start)))

	def mount(self, stream: io.BufferedReader, mountpt: str, foreground: bool = False, debug: bool = False) -> None:
		mountpt = os.path.abspath(mountpt)
		ops     = Operations(stream, self)
		args    = ['fsname=u4pak', 'subtype=u4pak', 'ro']

		if debug:
			foreground = True
			args.append('debug')

		if not foreground:
			deamonize()

		llfuse.init(ops, mountpt, args)
		try:
			llfuse.main()
		finally:
			llfuse.close()

# compare all metadata except for the filename
def same_metadata(r1: Record, r2: Record) -> bool:
	# data records always have offset == 0 it seems, so skip that
	return \
		r1.compressed_size        == r2.compressed_size    and \
		r1.uncompressed_size      == r2.uncompressed_size  and \
		r1.compression_method     == r2.compression_method and \
		r1.timestamp              == r2.timestamp          and \
		r1.sha1                   == r2.sha1               and \
		r1.compression_blocks     == r2.compression_blocks and \
		r1.encrypted              == r2.encrypted          and \
		r1.compression_block_size == r2.compression_block_size

def metadata_diff(r1: Record, r2: Record) -> str:
	diff = []

	for attr in ['compressed_size', 'uncompressed_size', 'timestamp', 'encrypted', 'compression_block_size']:
		v1 = getattr(r1,attr)
		v2 = getattr(r2,attr)
		if v1 != v2:
			diff.append('\t%s: %r != %r' % (attr, v1, v2))

	if r1.sha1 != r2.sha1:
		diff.append('\tsha1: %s != %s' % (hexlify(r1.sha1).decode('latin1'), hexlify(r2.sha1).decode('latin1')))

	if r1.compression_blocks != r2.compression_blocks:
		diff.append('\tcompression_blocks:\n\t\t%r\n\t\t\t!=\n\t\t%r' % (r1.compression_blocks, r2.compression_blocks))

	return '\n'.join(diff)

COMPR_NONE        = 0x00
COMPR_ZLIB        = 0x01
COMPR_BIAS_MEMORY = 0x10
COMPR_BIAS_SPEED  = 0x20

COMPR_METHODS: Set[int] = {COMPR_NONE, COMPR_ZLIB, COMPR_BIAS_MEMORY, COMPR_BIAS_SPEED}

COMPR_METHOD_NAMES: Dict[int, str] = {
	COMPR_NONE: 'none',
	COMPR_ZLIB: 'zlib',
	COMPR_BIAS_MEMORY: 'bias memory',
	COMPR_BIAS_SPEED:  'bias speed'
}

class Record(NamedTuple):
	filename:               str
	offset:                 int
	compressed_size:        int
	uncompressed_size:      int
	compression_method:     int
	timestamp:              Optional[int]
	sha1:                   bytes
	compression_blocks:     Optional[List[Tuple[int, int]]]
	encrypted:              bool
	compression_block_size: Optional[int]

	def sendfile(self, outfile: io.BufferedWriter, infile: io.BufferedReader) -> None:
		if self.compression_method == COMPR_NONE:
			sendfile(outfile, infile, self.data_offset, self.uncompressed_size)
		elif self.compression_method == COMPR_ZLIB:
			if self.encrypted:
				raise NotImplementedError('zlib decompression with encryption is not implemented yet')
			assert self.compression_blocks is not None
			base_offset = self.base_offset
			for start_offset, end_offset in self.compression_blocks:
				block_size = end_offset - start_offset
				infile.seek(base_offset + start_offset)
				block_content = infile.read(block_size)
				assert block_content is not None
				block_decompress = zlib.decompress(block_content)
				outfile.write(block_decompress)
		else:
			raise NotImplementedError('decompression is not implemented yet')

	@property
	def base_offset(self):
		return 0

	def read(self, data: Union[memoryview, bytes, mmap.mmap], offset: int, size: int) -> Union[bytes, bytearray]:
		if self.encrypted:
			raise NotImplementedError('decryption is not supported')

		if self.compression_method == COMPR_NONE:
			uncompressed_size = self.uncompressed_size

			if offset >= uncompressed_size:
				return b''

			i = self.data_offset + offset
			j = i + min(uncompressed_size - offset, size)
			return data[i:j]
		elif self.compression_method == COMPR_ZLIB:
			assert self.compression_blocks is not None
			base_offset = self.base_offset
			buffer = bytearray()
			end_offset = offset + size

			compression_block_size = self.compression_block_size
			assert compression_block_size
			start_block_index = offset // compression_block_size
			end_block_index   = end_offset // compression_block_size

			current_offset = compression_block_size * start_block_index
			for block_start_offset, block_end_offset in self.compression_blocks[start_block_index:end_block_index + 1]:
				block_size = block_end_offset - block_start_offset

				block_content = data[base_offset + block_start_offset:base_offset + block_end_offset]
				block_decompress = zlib.decompress(block_content)

				next_offset = current_offset + len(block_decompress)
				if current_offset >= offset:
					buffer.extend(block_decompress[:end_offset - current_offset])
				else:
					buffer.extend(block_decompress[offset - current_offset:end_offset - current_offset])

				current_offset = next_offset
			return buffer
		else:
			raise NotImplementedError(f'decompression method {self.compression_method} is not supported')

	def unpack(self, stream: io.BufferedReader, outdir: str = ".", callback: Callable[[str], None] = lambda name: None) -> None:
		prefix, name = os.path.split(self.filename)
		prefix = os.path.join(outdir,prefix)
		if not os.path.exists(prefix):
			os.makedirs(prefix)
		name = os.path.join(prefix,name)
		callback(name)
		fp: io.BufferedWriter
		with open(name, "wb") as fp: # type: ignore
			self.sendfile(fp, stream)

	@property
	def data_offset(self) -> int:
		return self.offset + self.header_size

	@property
	def alloc_size(self) -> int:
		return self.header_size + self.compressed_size

	@property
	def index_size(self) -> int:
		name_size = 4 + len(self.filename.replace(os.path.sep,'/').encode('utf-8')) + 1
		return name_size + self.header_size

	@property
	def header_size(self) -> int:
		raise NotImplementedError

class RecordV1(Record):
	__slots__ = ()

	def __new__(cls, filename: str, offset: int, compressed_size: int, uncompressed_size: int, compression_method: int, timestamp: Optional[int], sha1: bytes) -> RecordV1:
		return Record.__new__(cls, filename, offset, compressed_size, uncompressed_size,
							  compression_method, timestamp, sha1, None, False, None) # type: ignore

	@property
	def header_size(self) -> int:
		return 56

class RecordV2(Record):
	__slots__ = ()

	def __new__(cls, filename: str, offset: int, compressed_size: int, uncompressed_size: int, compression_method: int, sha1: bytes) -> RecordV2:
		return Record.__new__(cls, filename, offset, compressed_size, uncompressed_size,
							  compression_method, None, sha1, None, False, None) # type: ignore

	@property
	def header_size(self):
		return 48

class RecordV3(Record):
	__slots__ = ()

	def __new__(cls, filename: str, offset: int, compressed_size: int, uncompressed_size: int, compression_method: int, sha1: bytes,
				compression_blocks: Optional[List[Tuple[int, int]]], encrypted: bool, compression_block_size: Optional[int]) -> RecordV3:
		return Record.__new__(cls, filename, offset, compressed_size, uncompressed_size,
							  compression_method, None, sha1, compression_blocks, encrypted,
							  compression_block_size) # type: ignore

	@property
	def header_size(self) -> int:
		size = 53
		if self.compression_method != COMPR_NONE:
			assert self.compression_blocks is not None
			size += len(self.compression_blocks) * 16
		return size

# XXX: Don't know at which version exactly the change happens.
#      Only know 4 is relative, 7 is absolute.
class RecordV7(RecordV3):
	@property
	def base_offset(self):
		return self.offset

def read_path(stream: io.BufferedReader, encoding: str = 'utf-8') -> str:
	path_len, = st_unpack('<i',stream.read(4))
	if path_len < 0:
		# in at least some format versions, this indicates a UTF-16 path
		path_len = -2 * path_len
		encoding = 'utf-16le'
	return stream.read(path_len).decode(encoding).rstrip('\0').replace('/',os.path.sep)

def pack_path(path: str, encoding: str = 'utf-8') -> bytes:
	encoded_path = path.replace(os.path.sep, '/').encode('utf-8') + b'\0'
	return st_pack('<I', len(encoded_path)) + encoded_path

def write_path(stream: io.BufferedWriter, path: str, encoding: str = 'utf-8') -> bytes:
	data = pack_path(path,encoding)
	stream.write(data)
	return data

def read_record_v1(stream: io.BufferedReader, filename: str) -> RecordV1:
	return RecordV1(filename, *st_unpack('<QQQIQ20s',stream.read(56)))

def read_record_v2(stream: io.BufferedReader, filename: str) -> RecordV2:
	return RecordV2(filename, *st_unpack('<QQQI20s',stream.read(48)))

def read_record_v3(stream: io.BufferedReader, filename: str) -> RecordV3:
	offset, compressed_size, uncompressed_size, compression_method, sha1 = \
		st_unpack('<QQQI20s',stream.read(48))

	blocks: Optional[List[Tuple[int, int]]]
	if compression_method != COMPR_NONE:
		block_count, = st_unpack('<I',stream.read(4))
		blocks_bin = st_unpack('<%dQ' % (block_count * 2), stream.read(16 * block_count))
		blocks = [(blocks_bin[i], blocks_bin[i+1]) for i in range(0, block_count * 2, 2)]
	else:
		blocks = None

	encrypted, compression_block_size = st_unpack('<BI',stream.read(5))

	return RecordV3(filename, offset, compressed_size, uncompressed_size, compression_method,
					sha1, blocks, encrypted != 0, compression_block_size) # type: ignore

read_record_v4 = read_record_v3

def read_record_v7(stream: io.BufferedReader, filename: str) -> RecordV3:
	offset, compressed_size, uncompressed_size, compression_method, sha1 = \
		st_unpack('<QQQI20s',stream.read(48))

	blocks: Optional[List[Tuple[int, int]]]
	if compression_method != COMPR_NONE:
		block_count, = st_unpack('<I',stream.read(4))
		blocks_bin = st_unpack('<%dQ' % (block_count * 2), stream.read(16 * block_count))
		blocks = [(blocks_bin[i], blocks_bin[i+1]) for i in range(0, block_count * 2, 2)]
	else:
		blocks = None

	encrypted, compression_block_size = st_unpack('<BI',stream.read(5))

	return RecordV7(filename, offset, compressed_size, uncompressed_size, compression_method,
					sha1, blocks, encrypted != 0, compression_block_size) # type: ignore

def write_data(
		archive: io.BufferedWriter,
		fh: io.BufferedReader,
		size: int,
		compression_method: int = COMPR_NONE,
		encrypted: bool = False,
		compression_block_size: int = 0
) -> Tuple[int, bytes]:
	if compression_method != COMPR_NONE:
		raise NotImplementedError("compression is not implemented")

	if encrypted:
		raise NotImplementedError("encryption is not implemented")

	buf_size = DEFAULT_BUFFER_SIZE
	buf = bytearray(buf_size)
	bytes_left = size
	hasher = hashlib.sha1()
	while bytes_left > 0:
		data: Union[bytes, bytearray]
		if bytes_left >= buf_size:
			n = fh.readinto(buf)
			data = buf
			if n is None or n < buf_size:
				raise IOError('unexpected end of file')
		else:
			opt_data = fh.read(bytes_left)
			assert opt_data is not None
			n = len(opt_data)
			if n < bytes_left:
				raise IOError('unexpected end of file')
			data = opt_data
		bytes_left -= n
		hasher.update(data)
		archive.write(data)

	return size, hasher.digest()

def write_data_zlib(
		archive: io.BufferedWriter,
		fh: io.BufferedReader,
		size: int,
		compression_method: int = COMPR_NONE,
		encrypted: bool = False,
		compression_block_size: int = 65536
) -> Tuple[int, bytes, int, List[int]]:
	if encrypted:
		raise NotImplementedError("encryption is not implemented")

	buf_size = compression_block_size
	block_count = int(math.ceil(size / compression_block_size))
	base_offset = archive.tell()

	archive.write(st_pack('<I',block_count))

	# Seek Skip Offset
	archive.seek(block_count * 8 * 2, 1)

	record = st_pack('<BI', int(encrypted), compression_block_size)
	archive.write(record)

	cur_offset = base_offset + 4 + block_count * 8 * 2 + 5

	compress_blocks = [0] * block_count * 2
	compressed_size = 0
	compress_block_no = 0

	buf = bytearray(buf_size)
	bytes_left: int = size
	hasher = hashlib.sha1()
	while bytes_left > 0:
		n: int
		if bytes_left >= buf_size:
			n = fh.readinto(buf) or 0
			data = zlib.compress(memoryview(buf))

			compressed_size += len(data)
			compress_blocks[compress_block_no * 2] = cur_offset
			cur_offset += len(data)
			compress_blocks[compress_block_no * 2 + 1] = cur_offset
			compress_block_no += 1

			if n < buf_size:
				raise IOError('unexpected end of file')
		else:
			data = fh.read(bytes_left) or b''
			n = len(data)

			data = zlib.compress(data)
			compressed_size += len(data)
			compress_blocks[compress_block_no * 2] = cur_offset
			cur_offset += len(data)
			compress_blocks[compress_block_no * 2 + 1] = cur_offset
			compress_block_no += 1

			if n < bytes_left:
				raise IOError('unexpected end of file')
		bytes_left -= n
		hasher.update(data)
		archive.write(data)

	cur_offset = archive.tell()

	archive.seek(base_offset + 4, 0)
	archive.write(st_pack('<%dQ' % (block_count * 2), *compress_blocks))
	archive.seek(cur_offset, 0)

	return compressed_size, hasher.digest(), block_count, compress_blocks

def write_record_v1(
		archive: io.BufferedWriter,
		fh: io.BufferedReader,
		compression_method: int = COMPR_NONE,
		encrypted: bool = False,
		compression_block_size: int = 0) -> bytes:
	if encrypted:
		raise ValueError('version 1 does not support encryption')

	record_offset = archive.tell()

	st = os.fstat(fh.fileno())
	size = st.st_size
	# XXX: timestamp probably needs multiplication with some factor?
	record = st_pack('<16xQIQ20x',size,compression_method,int(st.st_mtime))
	archive.write(record)

	compressed_size, sha1 = write_data(archive,fh,size,compression_method,encrypted,compression_block_size)
	data_end = archive.tell()

	archive.seek(record_offset+8, 0)
	archive.write(st_pack('<Q',compressed_size))

	archive.seek(record_offset+36, 0)
	archive.write(sha1)

	archive.seek(data_end, 0)

	return st_pack('<QQQIQ20s',record_offset,compressed_size,size,compression_method,int(st.st_mtime),sha1)

def write_record_v2(
		archive: io.BufferedWriter,
		fh: io.BufferedReader,
		compression_method: int = COMPR_NONE,
		encrypted: bool = False,
		compression_block_size: int = 0) -> bytes:
	if encrypted:
		raise ValueError('version 2 does not support encryption')

	record_offset = archive.tell()

	st = os.fstat(fh.fileno())
	size = st.st_size
	record = st_pack('<16xQI20x',size,compression_method)
	archive.write(record)

	compressed_size, sha1 = write_data(archive,fh,size,compression_method,encrypted,compression_block_size)
	data_end = archive.tell()

	archive.seek(record_offset+8, 0)
	archive.write(st_pack('<Q',compressed_size))

	archive.seek(record_offset+28, 0)
	archive.write(sha1)

	archive.seek(data_end, 0)

	return st_pack('<QQQI20s',record_offset,compressed_size,size,compression_method,sha1)

def write_record_v3(
		archive: io.BufferedWriter,
		fh: io.BufferedReader,
		compression_method: int = COMPR_NONE,
		encrypted: bool = False,
		compression_block_size: int = 0) -> bytes:
	if compression_method != COMPR_NONE and compression_method != COMPR_ZLIB:
		raise NotImplementedError("compression is not implemented")

	record_offset = archive.tell()

	if compression_block_size == 0 and compression_method == COMPR_ZLIB:
		compression_block_size = 65536

	st = os.fstat(fh.fileno())
	size = st.st_size
	record = st_pack('<16xQI20x',size,compression_method)
	archive.write(record)

	if compression_method == COMPR_ZLIB:
		compressed_size, sha1, block_count, blocks = write_data_zlib(archive,fh,size,compression_method,encrypted,compression_block_size)
	else:
		record = st_pack('<BI',int(encrypted),compression_block_size)
		archive.write(record)
		compressed_size, sha1 = write_data(archive,fh,size,compression_method,encrypted,compression_block_size)
	data_end = archive.tell()

	archive.seek(record_offset+8, 0)
	archive.write(st_pack('<Q',compressed_size))

	archive.seek(record_offset+28, 0)
	archive.write(sha1)

	archive.seek(data_end, 0)

	if compression_method == COMPR_ZLIB:
		return st_pack('<QQQI20s',record_offset,compressed_size,size,compression_method,sha1) + st_pack('<I%dQ' % (block_count * 2), block_count, *blocks) + st_pack('<BI',int(encrypted),compression_block_size)
	else:
		return st_pack('<QQQI20sBI',record_offset,compressed_size,size,compression_method,sha1,int(encrypted),compression_block_size)

def read_index(
		stream: io.BufferedReader,
		check_integrity: bool = False,
		ignore_magic: bool = False,
		encoding: str = 'utf-8',
		force_version: Optional[int] = None,
		ignore_null_checksums: bool = False) -> Pak:
	stream.seek(-44, 2)
	footer_offset = stream.tell()
	footer = stream.read(44)
	magic, version, index_offset, index_size, index_sha1 = st_unpack('<IIQQ20s',footer)

	if not ignore_magic and magic != 0x5A6F12E1:
		raise ValueError('illegal file magic: 0x%08x' % magic)

	if force_version is not None:
		version = force_version

	read_record: Callable[[io.BufferedReader, str], Record]
	if version == 1:
		read_record = read_record_v1

	elif version == 2:
		read_record = read_record_v2

	elif version == 3:
		read_record = read_record_v3

	elif version == 4:
		read_record = read_record_v4

	elif version == 7:
		read_record = read_record_v7

	else:
		raise ValueError('unsupported version: %d' % version)

	if index_offset + index_size > footer_offset:
		raise ValueError('illegal index offset/size')

	stream.seek(index_offset, 0)

	mount_point = read_path(stream, encoding)
	entry_count = st_unpack('<I',stream.read(4))[0]

	pak = Pak(version, index_offset, index_size, footer_offset, index_sha1, mount_point)

	for i in range(entry_count):
		filename = read_path(stream, encoding)
		record   = read_record(stream, filename)
		pak.records.append(record)

	if stream.tell() > footer_offset:
		raise ValueError('index bleeds into footer')

	if check_integrity:
		pak.check_integrity(stream, ignore_null_checksums=ignore_null_checksums)

	return pak

def _pack_callback(name: str, files: List[str]) -> None:
	pass

def pack(stream: io.BufferedWriter, files_or_dirs: List[str], mount_point: str, version: int = 3, compression_method: int = COMPR_NONE,
		 encrypted: bool = False, compression_block_size: int = 0, callback: Callable[[str, List[str]], None] = _pack_callback,
		 encoding: str='utf-8') -> None:
	if version == 1:
		write_record = write_record_v1

	elif version == 2:
		write_record = write_record_v2

	elif version == 3:
		write_record = write_record_v3

	else:
		raise ValueError('version not supported: %d' % version)

	files: List[str] = []
	for name in files_or_dirs:
		if os.path.isdir(name):
			for dirpath, dirnames, filenames in os.walk(name):
				for filename in filenames:
					files.append(os.path.join(dirpath,filename))
		else:
			files.append(name)

	files.sort()

	records: List[Tuple[str, bytes]] = []
	for filename in files:
		callback(filename, files)
		fh: io.BufferedReader
		with open(filename, "rb") as fh: # type: ignore
			record = write_record(stream, fh, compression_method, encrypted, compression_block_size)
			records.append((filename, record))

	write_index(stream,version,mount_point,records,encoding)

def write_index(stream: IO[bytes], version: int, mount_point: str, records: List[Tuple[str, bytes]], encoding: str = 'utf-8') -> None:
	hasher = hashlib.sha1()
	index_offset = stream.tell()

	index_header = pack_path(mount_point, encoding) + st_pack('<I',len(records))
	index_size   = len(index_header)
	hasher.update(index_header)
	stream.write(index_header)

	for filename, record in records:
		encoded_filename = pack_path(filename, encoding)
		hasher.update(encoded_filename)
		stream.write(encoded_filename)
		index_size += len(encoded_filename)

		hasher.update(record)
		stream.write(record)
		index_size += len(record)

	index_sha1 = hasher.digest()
	stream.write(st_pack('<IIQQ20s', 0x5A6F12E1, version, index_offset, index_size, index_sha1))

def make_record_v1(filename: str) -> RecordV1:
	st   = os.stat(filename)
	size = st.st_size
	return RecordV1(filename, -1, size, size, COMPR_NONE, int(st.st_mtime), b'') # type: ignore

def make_record_v2(filename: str) -> RecordV2:
	size = os.path.getsize(filename)
	return RecordV2(filename, -1, size, size, COMPR_NONE, b'') # type: ignore

def make_record_v3(filename: str) -> RecordV3:
	size = os.path.getsize(filename)
	return RecordV3(filename, -1, size, size, COMPR_NONE, b'', None, False, 0) # type: ignore

# TODO: untested!
# removes, inserts and updates files, rewrites index, truncates archive if neccesarry
def update(stream: io.BufferedRandom, mount_point: str, insert: Optional[List[str]] = None, remove: Optional[List[str]] = None, compression_method: int = COMPR_NONE,
		   encrypted: bool = False, compression_block_size: int = 0, callback: Callable[[str], None] = lambda name: None,
		   ignore_magic: bool = False, encoding: str = 'utf-8', force_version: Optional[int] = None):
	if compression_method != COMPR_NONE:
		raise NotImplementedError("compression is not implemented")

	if encrypted:
		raise NotImplementedError("encryption is not implemented")

	pak = read_index(stream, False, ignore_magic, encoding, force_version)

	make_record: Callable[[str], Record]
	if pak.version == 1:
		write_record = write_record_v1
		make_record  = make_record_v1

	elif pak.version == 2:
		write_record = write_record_v2
		make_record  = make_record_v2

	elif pak.version == 3:
		write_record = write_record_v3
		make_record  = make_record_v3

	else:
		raise ValueError('version not supported: %d' % pak.version)

	# build directory tree of existing files
	root = Dir(-1)
	root.parent = root
	for record in pak:
		path = record.filename.split(os.path.sep)
		path, name = path[:-1], path[-1]

		parent = root
		for i, comp in enumerate(path):
			comp_encoded = comp.encode(encoding)
			try:
				entry = parent.children[comp_encoded]
			except KeyError:
				entry = parent.children[comp_encoded] = Dir(-1, parent=parent)

			if not isinstance(entry, Dir):
				raise ValueError("name conflict in archive: %r is not a directory" % os.path.join(*path[:i+1]))

			parent = entry

		if name in parent.children:
			raise ValueError("doubled name in archive: %s" % record.filename)

		parent.children[name.encode(encoding)] = File(-1, record, parent)

	# find files to remove
	if remove:
		for filename in remove:
			path = filename.split(os.path.sep)
			path, name = path[:-1], path[-1]

			parent = root
			for i, comp in enumerate(path):
				comp_encoded = comp.encode(encoding)
				try:
					entry = parent.children[comp_encoded]
				except KeyError:
					entry = parent.children[comp_encoded] = Dir(-1, parent=parent)

				if not isinstance(entry, Dir):
					# TODO: maybe option to ignore this?
					raise ValueError("file not in archive: %s" % filename)

				parent = entry

			if name not in parent.children:
				raise ValueError("file not in archive: %s" % filename)

			name_encoded = name.encode(encoding)
			entry = parent.children[name_encoded]
			del parent.children[name_encoded]

	# find files to insert
	if insert:
		files = []
		for name in insert:
			if os.path.isdir(name):
				for dirpath, dirnames, filenames in os.walk(name):
					for filename in filenames:
						files.append(os.path.join(dirpath,filename))
			else:
				files.append(name)

		for filename in files:
			path = filename.split(os.path.sep)
			path, name = path[:-1], path[-1]

			parent = root
			for i, comp in enumerate(path):
				comp_encoded = comp.encode(encoding)
				try:
					entry = parent.children[comp_encoded]
				except KeyError:
					entry = parent.children[comp_encoded] = Dir(-1, parent=parent)

				if not isinstance(entry, Dir):
					raise ValueError("name conflict in archive: %r is not a directory" % os.path.join(*path[:i+1]))

				parent = entry

			if name in parent.children:
				raise ValueError("doubled name in archive: %s" % filename)

			parent.children[name.encode(encoding)] = File(-1, make_record(filename), parent)

	# build new allocations
	existing_records: List[Record] = []
	new_records:      List[Record] = []

	for record in root.allrecords():
		if record.offset == -1:
			new_records.append(record)
		else:
			existing_records.append(record)

	# try to build new allocations in a way that needs a minimal amount of reads/writes
	allocations = []
	new_records.sort(key=lambda r: (r.compressed_size, r.filename),reverse=True)
	arch_size = 0
	for record in existing_records:
		size = record.alloc_size
		offset = record.offset
		if offset > arch_size:
			# find new records that fit the hole in order to reduce shifts
			# but never cause a shift torwards the end of the file
			# this is done so the rewriting/shifting code below is simpler
			i = 0
			while i < len(new_records) and arch_size < offset:
				new_record = new_records[i]
				new_size = new_record.alloc_size
				if arch_size + new_size <= offset:
					allocations.append((arch_size, new_record))
					del new_records[i]
					arch_size += new_size
				else:
					i += 1

		allocations.append((arch_size, record))
		arch_size += size

	# add remaining records at the end
	new_records.sort(key=lambda r: r.filename)
	for record in new_records:
		allocations.append((arch_size,record))
		arch_size += record.alloc_size

	index_offset = arch_size
	for offset, record in allocations:
		arch_size += record.index_size

	footer_offset = arch_size
	arch_size += 44

	current_size = os.fstat(stream.fileno()).st_size
	diff_size = arch_size - current_size
	# minimize chance of corrupting archive
	if diff_size > 0 and hasattr(os,'statvfs'):
		st = os.statvfs(stream.name)
		free = st.f_frsize * st.f_bfree
		if free - diff_size < DEFAULT_BUFFER_SIZE:
			raise ValueError("filesystem not big enough")

	index_records = []
	for offset, record in reversed(allocations):
		if record.offset == -1:
			# new record
			filename = record.filename
			callback("+" + filename)
			fh: io.BufferedReader
			with open(filename, "rb") as fh: # type: ignore
				record_bytes = write_record(stream, fh, record.compression_method, record.encrypted, record.compression_block_size or 0)
		elif offset != record.offset:
			assert offset > record.offset
			callback(" "+filename)
			fshift(stream, record.offset, offset, record.alloc_size)
			stream.seek(offset, 0)
			record_bytes = stream.read(record.header_size)
		index_records.append((filename, record_bytes))

	write_index(stream,pak.version,mount_point,index_records,encoding)

	if diff_size < 0:
		stream.truncate(arch_size)

def fshift(stream: io.BufferedRandom, src: int, dst: int, size: int) -> None:
	assert src < dst
	buf_size = DEFAULT_BUFFER_SIZE
	buf      = bytearray(buf_size)

	while size > 0:
		data: Union[bytes, bytearray]
		if size >= buf_size:
			stream.seek(src + size - buf_size, 0)
			stream.readinto(buf)
			data = buf
			size -= buf_size
		else:
			stream.seek(src, 0)
			data = stream.read(size) or b''
			size = 0

		stream.seek(dst + size, 0)
		stream.write(data)

def shall_unpack(paths: Iterable[str], name: str) -> bool:
	path = name.split(os.path.sep)
	for i in range(1, len(path) + 1):
		prefix = os.path.join(*path[0:i])
		if prefix in paths:
			return True
	return False

def human_size(size: int) -> str:
	if size < 2 ** 10:
		return str(size)

	elif size < 2 ** 20:
		str_size = "%.1f" % (size / 2 ** 10)
		unit = "K"

	elif size < 2 ** 30:
		str_size = "%.1f" % (size / 2 ** 20)
		unit = "M"

	elif size < 2 ** 40:
		str_size = "%.1f" % (size / 2 ** 30)
		unit = "G"

	elif size < 2 ** 50:
		str_size = "%.1f" % (size / 2 ** 40)
		unit = "T"

	elif size < 2 ** 60:
		str_size = "%.1f" % (size / 2 ** 50)
		unit = "P"

	elif size < 2 ** 70:
		str_size = "%.1f" % (size / 2 ** 60)
		unit = "E"

	elif size < 2 ** 80:
		str_size = "%.1f" % (size / 2 ** 70)
		unit = "Z"

	else:
		str_size = "%.1f" % (size / 2 ** 80)
		unit = "Y"

	if str_size.endswith(".0"):
		str_size = str_size[:-2]

	return str_size + unit

SORT_ALIASES: Dict[str, str] = {
	"s": "size",
	"S": "-size",
	"z": "zsize",
	"Z": "-zsize",
	"o": "offset",
	"O": "-offset",
	"n": "name"
}

KEY_FUNCS: Dict[str, Callable[[Record], Union[str, int]]] = {
	"size":  lambda rec: rec.uncompressed_size,
	"-size": lambda rec: -rec.uncompressed_size,

	"zsize":  lambda rec: rec.compressed_size,
	"-zsize": lambda rec: -rec.compressed_size,

	"offset":  lambda rec: rec.offset,
	"-offset": lambda rec: -rec.offset,

	"name": lambda rec: rec.filename.lower(),
}

def sort_key_func(sort: str) -> Callable[[Record], Tuple[Union[str, int], ...]]:
	key_funcs = []
	for key in sort.split(","):
		key = SORT_ALIASES.get(key,key)
		try:
			func = KEY_FUNCS[key]
		except KeyError:
			raise ValueError("unknown sort key: "+key)
		key_funcs.append(func)

	return lambda rec: tuple(key_func(rec) for key_func in key_funcs)

class Entry(object):
	__slots__ = 'inode', '_parent', 'stat', '__weakref__'

	inode: int
	_parent: Optional[weakref.ref[Dir]]
	stat: Optional[os.stat_result]

	def __init__(self, inode: int, parent: Optional[Dir] = None) -> None:
		self.inode  = inode
		self.parent = parent
		self.stat   = None

	@property
	def parent(self) -> Optional[Dir]:
		return self._parent() if self._parent is not None else None

	@parent.setter
	def parent(self, parent: Optional[Dir]) -> None:
		self._parent = weakref.ref(parent) if parent is not None else None

class Dir(Entry):
	__slots__ = 'children',

	children: OrderedDict[bytes, Union[Dir, File]]

	def __init__(self, inode: int, children: Optional[OrderedDict[bytes, Union[Dir, File]]] = None, parent: Optional[Dir] = None) -> None:
		Entry.__init__(self,inode,parent)
		if children is None:
			self.children = OrderedDict()
		else:
			self.children = children
			for child in children.values():
				child.parent = self

	def __repr__(self) -> str:
		return 'Dir(%r, %r)' % (self.inode, self.children)

	def allrecords(self) -> Iterable[Record]:
		for child in self.children.values():
			if isinstance(child, Dir):
				for record in child.allrecords():
					yield record
			else:
				yield child.record

class File(Entry):
	__slots__ = 'record',

	record: Record

	def __init__(self, inode: int, record: Record, parent: Optional[Dir] = None) -> None:
		Entry.__init__(self, inode, parent)
		self.record = record

	def __repr__(self) -> str:
		return 'File(%r, %r)' % (self.inode, self.record)

if HAS_LLFUSE:
	import errno
	import weakref
	import stat
	import mmap

	DIR_SELF   = '.'.encode(sys.getfilesystemencoding())
	DIR_PARENT = '..'.encode(sys.getfilesystemencoding())

	class Operations(llfuse.Operations):
		__slots__ = 'archive', 'root', 'inodes', 'arch_st', 'data'

		archive: io.BufferedReader
		inodes: Dict[int, Union[Dir, File]]
		root: Dir
		arch_st: os.stat_result
		data: mmap.mmap

		def __init__(self, archive: io.BufferedReader, pak: Pak) -> None:
			llfuse.Operations.__init__(self)
			self.archive = archive
			self.arch_st = os.fstat(archive.fileno())
			self.root    = Dir(llfuse.ROOT_INODE)
			self.inodes  = {self.root.inode: self.root}
			self.root.parent = self.root

			encoding = sys.getfilesystemencoding()
			inode = self.root.inode + 1
			for record in pak:
				path = record.filename.split(os.path.sep)
				path, name = path[:-1], path[-1]
				enc_name = name.encode(encoding)
				name, ext = os.path.splitext(name)

				parent = self.root
				for i, comp in enumerate(path):
					comp_encoded = comp.encode(encoding)
					try:
						entry = parent.children[comp_encoded]
					except KeyError:
						entry = parent.children[comp_encoded] = self.inodes[inode] = Dir(inode, parent=parent)
						inode += 1

					if not isinstance(entry, Dir):
						raise ValueError("name conflict in archive: %r is not a directory" % os.path.join(*path[:i+1]))

					parent = entry

				i = 0
				while enc_name in parent.children:
					sys.stderr.write("Warning: doubled name in archive: %s\n" % record.filename)
					i += 1
					enc_name = ("%s~%d%s" % (name, i, ext)).encode(encoding)

				parent.children[enc_name] = self.inodes[inode] = File(inode, record, parent)
				inode += 1

			archive.seek(0, 0)
			self.data = mmap.mmap(archive.fileno(), 0, access=mmap.ACCESS_READ)

			# cache entry attributes
			for inode in self.inodes:
				entry = self.inodes[inode]
				entry.stat = self._getattr(entry)

		def destroy(self) -> None:
			self.data.close()
			self.archive.close()

		def lookup(self, parent_inode: int, name: bytes, ctx) -> os.stat_result:
			try:
				entry = self.inodes[parent_inode]
				if name == DIR_SELF:
					pass

				elif name == DIR_PARENT:
					parent = entry.parent
					if parent is not None:
						entry = parent

				else:
					if not isinstance(entry, Dir):
						raise llfuse.FUSEError(errno.ENOTDIR)

					entry = entry.children[name]

			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				stat = entry.stat
				assert stat is not None
				return stat

		def _getattr(self, entry: Union[Dir, File]) -> llfuse.EntryAttributes:
			attrs = llfuse.EntryAttributes()

			attrs.st_ino        = entry.inode
			attrs.st_rdev       = 0
			attrs.generation    = 0
			attrs.entry_timeout = 300
			attrs.attr_timeout  = 300

			if isinstance(entry, Dir):
				nlink = 2 if entry is not self.root else 1
				size  = 5

				for name, child in entry.children.items():
					size += len(name) + 1
					if type(child) is Dir:
						nlink += 1

				attrs.st_mode  = stat.S_IFDIR | 0o555
				attrs.st_nlink = nlink
				attrs.st_size  = size
			else:
				attrs.st_nlink = 1
				attrs.st_mode  = stat.S_IFREG | 0o444
				attrs.st_size  = entry.record.uncompressed_size

			arch_st = self.arch_st
			attrs.st_uid     = arch_st.st_uid
			attrs.st_gid     = arch_st.st_gid
			attrs.st_blksize = arch_st.st_blksize
			attrs.st_blocks  = 1 + ((attrs.st_size - 1) // attrs.st_blksize) if attrs.st_size != 0 else 0
			if HAS_STAT_NS:
				attrs.st_atime_ns = arch_st.st_atime_ns
				attrs.st_mtime_ns = arch_st.st_mtime_ns
				attrs.st_ctime_ns = arch_st.st_ctime_ns
			else:
				attrs.st_atime_ns = int(arch_st.st_atime * 1000)
				attrs.st_mtime_ns = int(arch_st.st_mtime * 1000)
				attrs.st_ctime_ns = int(arch_st.st_ctime * 1000)

			return attrs

		def getattr(self, inode: int, ctx) -> os.stat_result:
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				stat = entry.stat
				assert stat is not None
				return stat

		def getxattr(self, inode: int, name: bytes, ctx) -> bytes:
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if not isinstance(entry, File):
					raise llfuse.FUSEError(errno.ENODATA)

				if name == b'user.u4pak.sha1':
					return hexlify(entry.record.sha1)

				elif name == b'user.u4pak.compressed_size':
					return str(entry.record.compressed_size).encode('ascii')

				elif name == b'user.u4pak.compression_method':
					return COMPR_METHOD_NAMES[entry.record.compression_method].encode('ascii')

				elif name == b'user.u4pak.compression_block_size':
					return str(entry.record.compression_block_size).encode('ascii')

				elif name == b'user.u4pak.encrypted':
					return str(entry.record.encrypted).encode('ascii')

				else:
					raise llfuse.FUSEError(errno.ENODATA)

		def listxattr(self, inode: int, ctx) -> List[bytes]:
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if type(entry) is Dir:
					return []

				else:
					return [b'user.u4pak.sha1', b'user.u4pak.compressed_size',
							b'user.u4pak.compression_method', b'user.u4pak.compression_block_size',
							b'user.u4pak.encrypted']

		def access(self, inode: int, mode: int, ctx) -> bool:
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				st_mode = 0o555 if type(entry) is Dir else 0o444
				return (st_mode & mode) == mode

		def opendir(self, inode: int, ctx):
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if type(entry) is not Dir:
					raise llfuse.FUSEError(errno.ENOTDIR)

				return inode

		def readdir(self, inode: int, offset: int) -> Iterable[Tuple[bytes, os.stat_result, int]]:
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if not isinstance(entry, Dir):
					raise llfuse.FUSEError(errno.ENOTDIR)

				names = list(entry.children)[offset:] if offset > 0 else entry.children
				for name in names:
					child = entry.children[name]
					stat = child.stat
					assert stat is not None
					yield name, stat, child.inode

		def releasedir(self, fh: int) -> None:
			pass

		def statfs(self, ctx) -> os.stat_result:
			attrs = llfuse.StatvfsData()

			arch_st = self.arch_st
			attrs.f_bsize  = arch_st.st_blksize
			attrs.f_frsize = arch_st.st_blksize
			attrs.f_blocks = arch_st.st_blocks
			attrs.f_bfree  = 0
			attrs.f_bavail = 0

			attrs.f_files  = len(self.inodes)
			attrs.f_ffree  = 0
			attrs.f_favail = 0

			return attrs

		def open(self, inode: int, flags: int, ctx) -> int:
			try:
				entry = self.inodes[inode]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)
			else:
				if type(entry) is Dir:
					raise llfuse.FUSEError(errno.EISDIR)

				if flags & 3 != os.O_RDONLY:
					raise llfuse.FUSEError(errno.EACCES)

				return inode

		def read(self, fh: int, offset: int, length: int) -> bytes:
			try:
				entry = self.inodes[fh]
			except KeyError:
				raise llfuse.FUSEError(errno.ENOENT)

			if not isinstance(entry, File):
				raise llfuse.FUSEError(errno.EISDIR)

			try:
				return entry.record.read(self.data, offset, length)
			except NotImplementedError:
				raise llfuse.FUSEError(errno.ENOSYS)

		def release(self, fh):
			pass

# based on http://code.activestate.com/recipes/66012/
def deamonize(stdout: str = '/dev/null', stderr: Optional[str] = None, stdin: str = '/dev/null') -> None:
	# Do first fork.
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0) # Exit first parent.
	except OSError as e:
		sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
		sys.exit(1)

	# Decouple from parent environment.
	os.chdir("/")
	os.umask(0)
	os.setsid()

	# Do second fork.
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0) # Exit second parent.
	except OSError as e:
		sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
		sys.exit(1)

	# Open file descriptors
	if not stderr:
		stderr = stdout

	si = open(stdin, 'r')
	so = open(stdout, 'a+')
	se = open(stderr, 'a+')

	# Redirect standard file descriptors.
	sys.stdout.flush()
	sys.stderr.flush()

	os.close(sys.stdin.fileno())
	os.close(sys.stdout.fileno())
	os.close(sys.stderr.fileno())

	os.dup2(si.fileno(), sys.stdin.fileno())
	os.dup2(so.fileno(), sys.stdout.fileno())
	os.dup2(se.fileno(), sys.stderr.fileno())

def main(argv: List[str]) -> None:
	parser = argparse.ArgumentParser(description='unpack, list and mount Unreal Engine 4 .pak archives')
	parser.set_defaults(print0=False,verbose=False,progress=False,zlib=False,command=None,no_sendfile=False,global_debug=False)
	add_debug_arg(parser)

	subparsers = parser.add_subparsers(metavar='command')

	unpack_parser = subparsers.add_parser('unpack',aliases=('x',),help='unpack archive')
	unpack_parser.set_defaults(command='unpack',check_integrity=False,ignore_null_checksums=False)
	unpack_parser.add_argument('-C','--dir',type=str,default='.',
							   help='directory to write unpacked files')
	unpack_parser.add_argument('-p','--progress',action='store_true',default=False,
							   help='show progress')
	add_hack_args(unpack_parser)
	add_common_args(unpack_parser)
	add_no_sendfile_arg(unpack_parser)
	unpack_parser.add_argument('files', metavar='file', nargs='*', help='files and directories to unpack')

	pack_parser = subparsers.add_parser('pack',aliases=('c',),help="pack archive")
	pack_parser.set_defaults(command='pack')
	pack_parser.add_argument('--archive-version',type=int,choices=[1,2,3],default=3,help='archive file format version')
	pack_parser.add_argument('--mount-point',type=str,default=os.path.join('..','..','..',''),help='archive mount point relative to its path')
	pack_parser.add_argument('-z', '--zlib',action='store_true',default=False,help='use zlib compress')
	pack_parser.add_argument('-p', '--progress',action='store_true',default=False,
							 help='show progress')
	add_print0_arg(pack_parser)
	add_verbose_arg(pack_parser)
	add_archive_arg(pack_parser)
	add_encoding_arg(pack_parser)
	pack_parser.add_argument('files', metavar='file', nargs='+', help='files and directories to pack')

	list_parser = subparsers.add_parser('list',aliases=('l',),help='list archive contens')
	list_parser.set_defaults(command='list',check_integrity=False,ignore_null_checksums=False)
	add_human_arg(list_parser)
	list_parser.add_argument('-d','--details',action='store_true',default=False,
							 help='print file offsets and sizes')
	list_parser.add_argument('-s','--sort',dest='sort_key_func',metavar='KEYS',type=sort_key_func,default=None,
							 help='sort file list. Comma seperated list of sort keys. Keys are "size", "zsize", "offset", and "name". '
								  'Prepend "-" to a key name to sort in descending order (descending order not supported for name).')
	add_hack_args(list_parser)
	add_common_args(list_parser)

	info_parser = subparsers.add_parser('info',aliases=('i',),help='print archive summary info')
	info_parser.set_defaults(command='info',check_integrity=False,ignore_null_checksums=False)
	add_human_arg(info_parser)
	add_integrity_arg(info_parser)
	add_archive_arg(info_parser)
	add_hack_args(info_parser)

	check_parser = subparsers.add_parser('test',aliases=('t',),help='test archive integrity')
	check_parser.set_defaults(command='test',ignore_null_checksums=False)
	add_print0_arg(check_parser)
	add_archive_arg(check_parser)
	add_hack_args(check_parser)

	mount_parser = subparsers.add_parser('mount',aliases=('m',),help='fuse mount archive')
	mount_parser.set_defaults(command='mount',check_integrity=False,ignore_null_checksums=False)
	mount_parser.add_argument('-d','--debug',action='store_true',default=False,
							  help='print debug output (implies -f)')
	mount_parser.add_argument('-f','--foreground',action='store_true',default=False,
							  help='foreground operation')
	mount_parser.add_argument('archive', help='Unreal Engine 4 .pak archive')
	mount_parser.add_argument('mountpt', help='mount point')
	add_integrity_arg(mount_parser)
	add_hack_args(mount_parser)

	args = parser.parse_args(argv)

	if args.command is None:
		parser.print_help()

	elif args.global_debug:
		_main(args)

	else:
		try:
			_main(args)
		except (ValueError, NotImplementedError, IOError) as exc:
			sys.stderr.write("%s\n" % exc)
			sys.exit(1)

def _main(args: argparse.Namespace) -> None:
	delim = '\0' if args.print0 else '\n'

	stream:  io.BufferedReader
	wstream: io.BufferedWriter

	if args.command == 'list':
		with open(args.archive, "rb") as stream: # type: ignore
			pak = read_index(stream, args.check_integrity, args.ignore_magic, args.encoding, args.force_version, args.ignore_null_checksums)
			pak.print_list(args.details,args.human,delim,args.sort_key_func,sys.stdout)

	elif args.command == 'info':
		with open(args.archive, "rb") as stream: # type: ignore
			pak = read_index(stream, args.check_integrity, args.ignore_magic, args.encoding, args.force_version, args.ignore_null_checksums)
			pak.print_info(args.human,sys.stdout)

	elif args.command == 'test':
		error_count = 0

		def check_callback(ctx: Optional[Record], message: str) -> None:
			nonlocal error_count
			error_count += 1

			if ctx is None:
				sys.stdout.write("%s%s" % (message, delim))

			elif isinstance(ctx, Record):
				sys.stdout.write("%s: %s%s" % (ctx.filename, message, delim))

			else:
				sys.stdout.write("%s: %s%s" % (ctx, message, delim))

		with open(args.archive, "rb") as stream: # type: ignore
			pak = read_index(stream, False, args.ignore_magic, args.encoding, args.force_version, args.ignore_null_checksums)
			pak.check_integrity(stream, check_callback, args.ignore_null_checksums)

		if error_count == 0:
			sys.stdout.write('All ok%s' % delim)
		else:
			sys.stdout.write('Found %d error(s)%s' % (error_count, delim))
			sys.exit(1)

	elif args.command == 'unpack':
		if args.no_sendfile:
			global sendfile
			sendfile = highlevel_sendfile

		if args.verbose:
			def unpack_callback(name: str) -> None:
				sys.stdout.write("%s%s" % (name, delim))

		elif args.progress:
			nDecompOffset = 0
			def unpack_callback(name: str) -> None:
				nonlocal nDecompOffset
				nDecompOffset = nDecompOffset + 1
				if nDecompOffset % 10 == 0:
					print("Decompressing %3.02f%%" % (round(nDecompOffset/len(pak)*100,2)), end="\r")
		else:
			def unpack_callback(name: str) -> None:
				pass

		with open(args.archive, "rb") as stream: # type: ignore
			pak = read_index(stream, args.check_integrity, args.ignore_magic, args.encoding, args.force_version, args.ignore_null_checksums)
			if args.files:
				pak.unpack_only(stream, set(name.strip(os.path.sep) for name in args.files), args.dir, unpack_callback)
			else:
				pak.unpack(stream, args.dir, unpack_callback)

	elif args.command == 'pack':
		if args.verbose:
			def pack_callback(name: str, files: List[str]) -> None:
				sys.stdout.write("%s%s" % (name, delim))
		elif args.progress:
			nCompOffset = 0
			def pack_callback(name: str, files: List[str]) -> None:
				nonlocal nCompOffset
				nCompOffset = nCompOffset + 1
				print("Compressing %3.02f%%" % (round(nCompOffset/len(files)*100,2)), end="\r")
		else:
			def pack_callback(name: str, files: List[str]) -> None:
				pass

		compFmt = COMPR_NONE
		if args.zlib == True: compFmt = COMPR_ZLIB

		with open(args.archive, "wb") as wstream: # type: ignore
			pack(wstream, args.files, args.mount_point, args.archive_version, compFmt,
			     callback=pack_callback, encoding=args.encoding)

	elif args.command == 'mount':
		if not HAS_LLFUSE:
			raise ValueError('the llfuse python module is needed for this feature')

		with open(args.archive, "rb") as stream: # type: ignore
			pak = read_index(stream, args.check_integrity, args.ignore_magic, args.encoding, args.force_version, args.ignore_null_checksums)
			pak.mount(stream, args.mountpt, args.foreground, args.debug)

	else:
		raise ValueError('unknown command: %s' % args.command)

def add_integrity_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('-i','--check-integrity',action='store_true',default=False,
						help='meta-data sanity check and verify checksums')
	parser.add_argument('--ignore-null-checksums',action='store_true',default=False,
						help='ignore checksums that are all nulls')

def add_archive_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('archive', help='Unreal Engine 4 .pak archive')

def add_print0_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('-0','--print0',action='store_true',default=False,
						help='seperate file names with nil bytes')

def add_verbose_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('-v','--verbose',action='store_true',default=False,
						help='print verbose output')

def add_human_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('-u','--human-readable',dest='human',action='store_true',default=False,
						help='print human readable file sizes')

def add_encoding_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('--encoding',type=str,default='UTF-8',
						help='charcter encoding of file names to use (default: UTF-8)')

def add_hack_args(parser: argparse.ArgumentParser) -> None:
	add_encoding_arg(parser)
	parser.add_argument('--ignore-magic',action='store_true',default=False,
						help="don't error out if file magic missmatches")
	parser.add_argument('--force-version',type=int,default=None,
						help='use this format version when parsing the file instead of the version read from the archive')

def add_no_sendfile_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('--no-sendfile',action='store_true',default=False,
						help="don't use sendfile system call. Try this if you get an IOError during unpacking.")

def add_debug_arg(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('-d', '--debug',action='store_true',default=False,dest='global_debug',
						help="print stacktrace on error")

def add_common_args(parser: argparse.ArgumentParser) -> None:
	add_print0_arg(parser)
	add_verbose_arg(parser)
	add_integrity_arg(parser)
	add_archive_arg(parser)

if __name__ == '__main__':
	main(sys.argv[1:])
