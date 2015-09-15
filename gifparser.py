#!/usr/bin/env python
"""
Copyright (c) 2015, Geir Skjotskift <geir@underworld.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import struct
import sys
import hashlib
import collections
import math

GLOBAL_COLOR_TABLE_SIZE = "Global Color Table Size"
COLOR_RESOLUTION = "Color Resolution"
GLOBAL_COLOR_TABLE_PRESENT = "Global Color Table Present"
GLOBAL_COLOR_TABLE_SORTED = "Global Color Table Sorted"

EXTENSION_INTRODUCER = 0x21
IMAGE_BLOCK_LABEL = 0x2c

GRAPHICAL_CONTROL_LABEL = 0xf9
BLOCK_TERMINATOR = 0x00


def parse_graphics_control_extension(content, offset):
    e = collections.OrderedDict()
    e["Type"] = "Graphics Control Extension"
    e["Offset"] = offset
    e["Size"] = struct.unpack("=B", content[2])[0]
    packed_fields = struct.unpack("=B", content[3])[0]
    e["Reserved Field"] = bits(7, 5, packed_fields)
    e["Disposal Method"] = bits(4, 2, packed_fields)
    e["User Input"] = bits(1, 1, packed_fields) == 1
    e["Transparent Color"] = bits(0, 0, packed_fields) == 1
    e["Delay Time"] = struct.unpack("=H", content[4:6])[0]
    e["Transparent Color Index"] = struct.unpack("=B", content[6])[0]
    e["Terminator"] = struct.unpack("=B", content[7])[0]
    if e["Terminator"] != 0:
        print bcolor.WARNING + "WARNING: Non null terminator of block" + bcolor.ENDC
    return e, content[8:], offset + 8

def parse_application_extension(content, offset):
    e = collections.OrderedDict()
    e["Type"] = "Application Extension"
    e["Offset"] = offset
    e["Size"] = struct.unpack("=B", content[2])[0]
    e["AppBlock"] = struct.unpack("{0}s".format(e["Size"]), content[3:3+e["Size"]])[0]
    content = content[e["Size"]+3:]
    offset += e["Size"] + 3
    block_size = struct.unpack("=B", content[0])[0]
    app_data = ""
    while True:
        content = content[1:]
        offset += 1
        app_data += content[:block_size]
        content = content[block_size:]
        offset += block_size
        block_size = struct.unpack("=B", content[0])[0]
        if block_size == 0x00:
            e["AppData"] = "\n" + hexprint(app_data)
            e["Entropy"] = entropy2(app_data)
            return e, content[1:], offset + 1


def parse_image_descriptor(content, offset):
    e = collections.OrderedDict()
    e["Type"] = "Image Descriptor"
    e["Offset"] = offset
    e["Image Left"] = struct.unpack("=H", content[1:3])[0]
    e["Image Top"] = struct.unpack("=H", content[3:5])[0]
    e["Image Width"] = struct.unpack("=H", content[5:7])[0]
    e["Image Heigth"] = struct.unpack("=H", content[7:9])[0]
    packed_field = struct.unpack("=B", content[9])[0]
    e["Local Color Table Flag"] = bits(7, 7, packed_field) == 1
    e["Interlace Flag"] = bits(6, 6, packed_field) == 1
    e["Sort Flag"] = bits(5, 5, packed_field) == 1
    e["Reserved"] = bits(4, 3, packed_field)
    lctValue = bits(2, 0, packed_field)
    lctSize = 2**(lctValue + 1)
    e["Size of Local Color Table"] = lctSize
    content = content[10:]
    offset += 10
    if e["Local Color Table Flag"]:
        ct, content, offset = get_color_table("Local", content, lctSize, offset)
    else:
        if lctValue > 0:
            print bcolor.WARNING + "WARNING: Local Color Table Size > 0 but LCT Present == False" + bcolor.ENDC
            e["Size of Local Color Table"] = bcolor.FAIL + str(lctSize) + bcolor.ENDC
        ct = None
    blocks, count, offset = get_image_blocks(content, offset)
    e["Image Blocks"] = LocalImage(blocks, ct)
    e["Entropy"] = e["Image Blocks"].entropy
    return e, content[count:], offset


def get_image_blocks(content, offset):
    blocks = []
    count = 0
    lzw_min = struct.unpack("=B", content[count])[0]
    count += 1
    while True:
        num_bytes = struct.unpack("=B", content[count])[0]
        count += 1
        imagebytes = struct.unpack("={0}B".format(num_bytes), content[count:count+num_bytes])
        blocks.append(ImageBlock(offset+count, lzw_min, imagebytes))
        count += num_bytes
        if ord(content[count]) == 0x00:
            count += 1
            break
    return blocks, count, offset + count


def hexprint(mybuffer):
    lines = []
    while True:
        line = mybuffer[:16]
        mybuffer = mybuffer[16:]
        if not line:
            break
        lines.append("{0:50}".format(" ".join("{0:02x}".format(ord(x)) for x in line)) + "  " + printable(line))
    return "\n".join(lines)


def printable(mybuffer):
    ret = ""
    for bc in mybuffer:
        val = ord(bc)
        if val > 31 and val < 127:
            ret += chr(val)
        else:
            ret += "."
    return ret


def parse_comment_extension(content, offset):
    e = collections.OrderedDict()
    e["Type"] = "Comment Extension"
    e["Offset"] = offset
    ascii_data = ""
    bytecount = struct.unpack("=B", content[2])[0]
    if bytecount == 0:
        return "", content[3:]
    content = content[3:]
    offset += 3
    while True:
        ascii_data += content[:bytecount]
        content = content[bytecount:]
        offset += bytecount
        bytecount = struct.unpack("=B", content[0])[0]
        content = content[1:]
        offset += 1
        if bytecount == 0:
            e["Comment"] = ascii_data
            e["Entropy"] = entropy2(ascii_data)
            print bcolor.WARNING + "INFO: File contains a comment" + bcolor.OKGREEN
            md5sum = hashlib.md5(ascii_data).hexdigest()
            fname = "{1}_{0}_comment.dat".format(sys.argv[1], md5sum)
            print "Writing comment to {0}".format(fname) + bcolor.ENDC
            open(fname, "wb").write(ascii_data)
            return e, content, offset

def parse_plain_text_extension(content, offset):
    e = collections.OrderedDict()
    e["Type"] = "Plain Text Extension"
    e["Offset"] = offset
    ascii_data = ""
    bytecount = struct.unpack("=B", content[2])[0]
    if bytecount == 0:
        return "", content[3:]
    content = content[3:]
    offset += 3
    while True:
        ascii_data += content[:bytecount]
        content = content[bytecount:]
        offset += bytecount
        bytecount = struct.unpack("=B", content[0])[0]
        content = content[1:]
        offset += 1
        if bytecount == 0:
            e["Comment"] = ascii_data
            e["Entropy"] = entropy2(ascii_data)
            print bcolor.WARNING + "INFO: File contains plain text section" + bcolor.OKGREEN
            md5sum = hashlib.md5(ascii_data).hexdigest()
            fname = "{1}_{0}_plaintext.dat".format(sys.argv[1], md5sum)
            print "Writing plaintext to {0}".format(fname) + bcolor.ENDC
            open(fname, "wb").write(ascii_data)
            return e, content, offset

extension = {
    0xf9: parse_graphics_control_extension,
    0x01: parse_plain_text_extension,
    0xff: parse_application_extension,
    0xfe: parse_comment_extension,
    }


def get_signature(content, offset):
    sig = content[:3]
    if sig != "GIF":
        raise BadFileFormat("No GIF signature")
    return sig, content[3:], offset + 3


def get_version(content, offset):
    ver = content[:3]
    if ver not in ["87a", "89a"]:
        raise BadFileFormat("Incorrect version signature ({0})".format(ver))
    return ver, content[3:], offset + 3


def get_logical_screen(content, offset):
    width = struct.unpack("=H", content[:2])[0]
    height = struct.unpack("=H", content[2:4])[0]
    return width, height, content[4:], offset + 4

def get_packed_fields(content, offset):
    """
    <Packed Fields>  =      Global Color Table Flag       1 Bit
                            Color Resolution              3 Bits
                            Sort Flag                     1 Bit
                            Size of Global Color Table    3 Bits
    """
    packed_fields = struct.unpack("=B", content[0])[0]

    fields = {}
    fields[GLOBAL_COLOR_TABLE_PRESENT] = (bits(7, 7, packed_fields) == 1)
    # Number of bits per primary color available
    # to the original image, minus 1. This value represents the size of
    # the entire palette from which the colors in the graphic were
    # selected, not the number of colors actually used in the graphic.
    # For example, if the value in this field is 3, then the palette of
    # the original image had 4 bits per primary color available to create
    # the image.
    fields[COLOR_RESOLUTION] = bits(6, 4, packed_fields) + 1
    fields[GLOBAL_COLOR_TABLE_SORTED] = (bits(3, 3, packed_fields) == 1)
    # To determine that actual size of the color table,
    # raise 2 to [the value of the field
    fields[GLOBAL_COLOR_TABLE_SIZE] = 2**(bits(2, 0, packed_fields)+1)

    return fields, content[1:], offset + 1

def get_background_color_index(content, offset):
    return struct.unpack("=B", content[0])[0], content[1:], offset + 1

def get_pixel_asepct_ratio(content, offset):
    pixel_aspect_ratio = struct.unpack("=B", content[0])[0]
    # If the value of the field is not 0, this approximation of the aspect ratio
    # is computed based on the formula:
    # Aspect Ratio = (Pixel Aspect Ratio + 15) / 64
    # The Pixel Aspect Ratio is defined to be the quotient of the pixel's
    # width over its height.
    if pixel_aspect_ratio != 0:
        pixel_aspect_ratio = (pixel_aspect_ratio + 15) / 64
    return pixel_aspect_ratio, content[1:], offset + 1

def pp(h):
    for k, v in h.items():
        if isinstance(v, dict):
            pp(v)
        else:
            maxout = 1025 * 5
            if type(v) in [list, str] and len(v) > maxout:
                print "{0}: {1}...[trunkated output (total bytes: {2})]".format(k, v[:maxout], len(v))
            else:
                print "{0}: {1}".format(k, v)


def get_color_table(table_type, content, size, offset):
    tbl = []
    for i in range(size):
        tbl.append(struct.unpack("=BBB", content[(i*3):(i*3)+3]))
    ct = ColorTable(table_type, tbl)
    return ct, content[(size*3):], offset + (size*3)


class ColorTable(object):
    def __init__(self, table_type, table):
        self.type = table_type
        self.table = table

    def __str__(self):
        if len(self.table) > 3:
            snip = ", ...]"
        else:
            snip = "]"
        return "".join(["{0} Color Table: [".format(self.type),
                        ", ".join([str(n) for n in self.table[:3]]),
                        snip])


def is_extension(content):
    return ord(content[0]) == EXTENSION_INTRODUCER


def is_image_descriptor(content):
    return ord(content[0]) == IMAGE_BLOCK_LABEL


def parse_extension(content, offset):

    ext = {}
    type_value = ord(content[1])
    fun = extension.get(type_value, None)
    if fun is None:
        ext["Type"] = "UNKNOWN ({0})".format(hex(type_value))
        print bcolor.FAIL + "UNKNOWN EXTENSION!!" + bcolor.ENDC
        print hexprint(content[:512])
        sys.exit(1)
    else:
        ext, content, offset = fun(content, offset)

    return ext, content, offset

def bits(s, e, byte):
    """
    Extract bits start, end, byte
    Ex. bits(4,2,27) == 0b110 (extracting bits 4, 3 and 2)
    """
    byte = byte>>e
    return byte & [1, 3, 7, 15, 31, 63, 127, 255][s-e]


def parse_gif_header(data, offset):
    signature, data, offset = get_signature(data, offset)
    version, data, offset = get_version(data, offset)
    w, h, data, offset = get_logical_screen(data, offset)
    fields, data, offset = get_packed_fields(data, offset)
    background_color_index, data, offset = get_background_color_index(data, offset)
    pixel_aspect_ratio, data, offset = get_pixel_asepct_ratio(data, offset)
    if fields[GLOBAL_COLOR_TABLE_PRESENT] == False and background_color_index != 0:
        background_color_index = bcolor.FAIL + str(background_color_index) + bcolor.ENDC
        print bcolor.WARNING + "WARNING: No color table, but color index is set" + bcolor.ENDC

    if fields[GLOBAL_COLOR_TABLE_PRESENT]:
        color_table, data, offset = get_color_table("Global", data, fields[GLOBAL_COLOR_TABLE_SIZE], offset)
    else:
        color_table = ColorTable("Global", [])
    if background_color_index >= len(color_table.table):
        print bcolor.WARNING + "WARNING: Background Color Index is outside of colortable" + bcolor.ENDC
        background_color = bcolor.FAIL + "Out of Range" + bcolor.ENDC
    else:
        background_color = str(color_table.table[background_color_index])

    header_data = collections.OrderedDict()
    header_data["Offset"] = offset
    header_data["File Entropy"] = entropy2(data)
    header_data["Signature"] = signature
    header_data["Version"] = version
    header_data["Width"] = w
    header_data["Height"] = h
    header_data["Fields"] = fields
    header_data["Background Color Index"] = background_color_index
    header_data["Background Color"] = background_color
    header_data["Pixel Aspect Ratio"] = pixel_aspect_ratio
    header_data["Global Color Table"] = color_table
    return header_data, data, offset

def is_endmarker(content):
    if ord(content[0]) == 0x3b:
        if len(content) > 1:
            fname = "{0}_trailing.dat".format(sys.argv[1])
            print bcolor.WARNING + "WARNING: End marker reached with trailing data." + bcolor.ENDC
            print bcolor.OKGREEN + "Trailing data written to {0}".format(fname) + bcolor.ENDC
            open(fname, "wb").write(content[1:])
        return True
    return False


class LocalImage(object):
    def __init__(self, blocks, ct=None):
        self.blocks = blocks
        self.color_table = ct
        tmpdata = ""
        for block in self.blocks:
            tmpdata += "".join(chr(db) for db in block.data)
        self.entropy = entropy2(tmpdata)

    def __str__(self):
        a = "with" if self.color_table else "without"
        small_count = 0
        for block in self.blocks:
            if len(block.data) < 0xfe:
                small_count += 1
        if small_count > 1:
            print bcolor.WARNING + "WARNING: Image contains small blocks" + bcolor.ENDC
        return "{0} image blocks {1} local color table".format(
            len(self.blocks),
            a)

class ImageBlock(object):
    def __init__(self, offset, min_code_size, data):
        self.offset = offset
        self.min_code_size = min_code_size
        self.data = data
    def __str__(self):
        return "{0} byte Image block [{1}] at {2:#08x}".format(
            len(self.data),
            self.min_code_size,
            self.offset)

class BadFileFormat(Exception):
    def __init__(self, value):
        Exception.__init__(self, value)
        self.value = value

    def __str__(self):
        return repr(self.value)

class ParseError(Exception):
    def __init__(self, value):
        Exception.__init__(self, value)
        self.value = value

    def __str__(self):
        return repr(self.value)

class bcolor(object):
    def __init__(self):
        pass

    HEADER = '\033[95m'
    OKBLUE = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def entropy2(data):
    entropy = 0
    total = len(data)

    def get_bytes_count(data):
        bc = [0] * 256
        for dc in data:
            bc[ord(dc)] += 1
        return bc
    for count in get_bytes_count(data):
        if count == 0:
            continue
        p = 1.0 * count / total
        entropy -= p * math.log(p, 2)
    return entropy


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print
        print "gifparser copyright Geir Skjotskift <geir@underworld.no> (c) 2015"
        print
        print "Usage: {0} [FILENAME]".format(sys.argv[0])
        print
        sys.exit(1)

    phys_offset = 0
    file_content = open(sys.argv[1]).read()
    header, file_content, phys_offset = parse_gif_header(file_content, phys_offset)
    print "-----------------------------"
    print bcolor.OKBLUE + "GIF Header Section" + bcolor.ENDC
    pp(header)
    fieldcount = 0
    while True:
        print "-----------------------------"
        fieldcount += 1
        print bcolor.OKBLUE + "Field Count: " + bcolor.OKGREEN + " " + str(fieldcount) + bcolor.ENDC
        if is_extension(file_content):
            print bcolor.OKGREEN + "Offset: {0:#08x}".format(phys_offset)  + bcolor.ENDC
            myextension, file_content, phys_offset = parse_extension(file_content, phys_offset)
            pp(myextension)
            continue
        if is_image_descriptor(file_content):
            print bcolor.OKGREEN + "Offset: {0:#08x}".format(phys_offset)  + bcolor.ENDC
            image_descriptor, file_content, phys_offset = parse_image_descriptor(file_content, phys_offset)
            pp(image_descriptor)
            continue
        if is_endmarker(file_content):
            print bcolor.OKGREEN + "Offset: {0:#08x}".format(phys_offset)  + bcolor.ENDC
            print "<<EOF"
            break
        print bcolor.OKGREEN + "Offset: {0:#08x}".format(phys_offset)  + bcolor.ENDC
        raise ParseError("Unknown filepart: {0} ...".format(
            [hex(b) for b in [ord(c) for c in file_content[:5]]]))


