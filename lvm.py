#!/usr/bin/python3

import io
import os
import re
import struct
import sys

from typing import BinaryIO, Dict, Union

# https://github.com/lvmteam/lvm2/blob/8801a86a3e0c87d92b250a6477f86ef9efdb2ba0/lib/format_text/format-text.c

PathLike = Union[str, bytes, os.PathLike]

INITIAL_CRC = 0xf597a6cf
MDA_HEADER_SIZE = 512


def _calc_crc(buf, crc=INITIAL_CRC):
    crctab = [0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
              0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
              0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
              0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c]

    for b in buf:
        crc ^= b  # crc ^= *buf++;
        crc = (crc >> 4) ^ crctab[crc & 0xf]
        crc = (crc >> 4) ^ crctab[crc & 0xf]

    return crc


class CStruct:
    class Field:
        def __init__(self, name: str, ctype: str, position: int):
            self.name = name
            self.type = ctype
            self.pos = position

    def __init__(self, mapping: Dict, byte_order="<"):
        format = byte_order
        self.fields = []
        for pos, name in enumerate(mapping):
            ctype = mapping[name]
            format += ctype
            field = self.Field(name, ctype, pos)
            self.fields.append(field)
        self.struct = struct.Struct(format)

    @property
    def size(self):
        return self.struct.size

    def unpack(self, data):
        up = self.struct.unpack_from(data)
        res = {
            field.name: up[idx]
            for idx, field in enumerate(self.fields)
        }
        return res

    def read(self, fp):
        pos = fp.tell()
        data = fp.read(self.size)

        if len(data) < self.size:
            return None

        res = self.unpack(data)
        res["_position"] = pos
        return res

    def pack(self, data):
        values = [
            data[field.name] for field in self.fields
        ]
        data = self.struct.pack(*values)
        return data

    def write(self, fp, data: Dict, *, offset=None):
        packed = self.pack(data)

        save = None
        if offset:
            save = fp.tell()
            fp.seek(offset)

        fp.write(packed)

        if save:
            fp.seek(save)

    def __getitem__(self, name):
        for f in self.fields:
            if f.name == f:
                return f
        raise KeyError(f"Unknown field '{name}'")

    def __contains__(self, name):
        return any(field.name == name for field in self.fields)


class LabelHeader:

    # /* On disk - 32 bytes */
    # struct label_header {
    #     int8_t id[8];		     /* LABELONE */
    #     uint64_t sector_xl;	 /* Sector number of this label */
    #     uint32_t crc_xl;	     /* From next field to end of sector */
    #     uint32_t offset_xl;	 /* Offset from start of struct to contents */
    #     int8_t type[8];		 /* LVM2 001 */
    # } __attribute__ ((packed));

    struct = CStruct({
        "id": "8s",
        "sector": "Q",
        "crc": "L",
        "offset": "L",
        "type": "8s"
    })

    LABELID = b"LABELONE"

    # scan sector 0 to 3 inclusive
    LABEL_SCAN_SECTORS = 4

    def __init__(self, data):
        up = self.struct.unpack(data)

        self.sector_size = 512

        self.sector = up["sector"]
        self.crc = up["crc"]
        self.offset = up["offset"]
        self.type = up["type"]

    @ classmethod
    def search(cls, fp, *, sector_size=512):
        fp.seek(0, io.SEEK_SET)
        for i in range(cls.LABEL_SCAN_SECTORS):
            data = fp.read(sector_size)
            if data[0:len(cls.LABELID)] == cls.LABELID:
                return LabelHeader(data)
        return None

    def read_pv_header(self, fp):
        offset = self.sector * self.sector_size + self.offset
        fp.seek(offset)
        return PVHeader.read(fp)

    def __str__(self):
        return f"LabelHeader: {self.sector}, {self.crc}, {self.offset}, {self.type}"


class DiskLocN:
    """
    struct disk_locn {
        uint64_t offset;	/* Offset in bytes to start sector */
        uint64_t size;		/* Bytes */
    } __attribute__ ((packed));
    """
    struct = CStruct({
        "offset": "Q",
        "size": "Q"
    })

    def __init__(self, offset, size):
        self.offset = offset
        self.size = size

    def __str__(self):
        return f"DiskLocN: {self.offset}, {self.size}"

    def read_data(self, fp: BinaryIO):
        fp.seek(self.offset)
        data = fp.read(self.size)
        return io.BytesIO(data)

    @classmethod
    def read_array(cls, fp):
        while True:
            data = cls.struct.read(fp)

            if not data or data["offset"] == 0:
                break

            yield DiskLocN(data["offset"], data["size"])


class PVHeader:
    """
    struct pv_header {
        int8_t pv_uuid[ID_LEN];

        /* This size can be overridden if PV belongs to a VG */
        uint64_t device_size_xl;	/* Bytes */

        /* NULL-terminated list of data areas followed by */
        /* NULL-terminated list of metadata area headers */
        struct disk_locn disk_areas_xl[];	/* Two lists */
    } __attribute__ ((packed));
    """
    struct = CStruct({
        "uuid": "32s",
        "disk_size": "Q"
    })

    def __init__(self, data, data_areas, meta_areas):
        self.uuid = data["uuid"]
        self.disk_size = data["disk_size"]

        self.data_areas = data_areas
        self.meta_areas = meta_areas

    @classmethod
    def read(cls, fp):
        data = cls.struct.read(fp)

        data_areas = list(DiskLocN.read_array(fp))
        meta_areas = list(DiskLocN.read_array(fp))

        return cls(data, data_areas, meta_areas)

    def __str__(self):
        msg = f"PVHeader(uuid: {self.uuid}, {self.disk_size})"
        if self.data_areas:
            msg += "\nData: \n\t" + "\n\t".join(map(str, self.data_areas))
        if self.meta_areas:
            msg += "\nMeta: \n\t" + "\n\t".join(map(str, self.meta_areas))
        return msg


class RawLocN:
    struct = CStruct({
        "offset": "Q",
        "size": "Q",
        "checksum": "L",
        "flags": "L",
    })

    IGNORED = 0x00000001

    def __init__(self, data) -> None:
        self.data = data

    def __getitem__(self, name):
        assert name in self.struct
        return self.data[name]

    def __setitem__(self, name, value):
        assert name in self.struct
        self.data[name] = value

    def write(self, fp):
        raw = self.struct.pack(self.data)
        n = fp.write(raw)
        return n

    @classmethod
    def read_array(cls, fp: BinaryIO):
        while True:
            loc = cls.struct.read(fp)

            if not loc or loc["offset"] == 0:
                break

            yield cls(loc)

    def __str__(self):
        s, o = self["size"], self["offset"]
        return f"RawLocN ({s} bytes @ {o}) ({id(self.data)})"


class MDAHeader:
    struct = CStruct({
        "checksum": "L",
        "magic": "16s",
        "version": "L",
        "start": "Q",
        "size":  "Q"
    })

    LOC_COMMITTED = 0
    LOC_PRECOMMITTED = 1

    HEADER_SIZE = MDA_HEADER_SIZE

    def __init__(self, data, raw_locns):
        self.data = data
        self.raw_locns = raw_locns

    @property
    def checksum(self):
        return self.data["checksum"]

    @property
    def magic(self):
        return self.data["magic"]

    @property
    def version(self):
        return self.data["version"]

    @property
    def start(self):
        return self.data["start"]

    @property
    def size(self):
        return self.data["size"]

    @classmethod
    def read(cls, fp):
        data = cls.struct.read(fp)
        raw_locns = list(RawLocN.read_array(fp))
        return cls(data, raw_locns)

    def read_metadata(self, fp):
        loc = self.raw_locns[self.LOC_COMMITTED]
        offset = self.start + loc["offset"]
        fp.seek(offset)
        data = fp.read(loc["size"])
        print(data)
        data = data.decode("utf-8")
        md = Metadata.parse(data)
        return md

    def write_metadata(self, fp, data):
        strdata = Metadata.encode(data) + "\0"
        raw = strdata.encode("utf-8")

        loc = self.raw_locns[self.LOC_COMMITTED]
        offset = self.start + loc["offset"]
        fp.seek(offset)

        n = fp.write(raw)
        loc["size"] = n
        loc["checksum"] = _calc_crc(raw)
        self.write(fp)

    def write(self, fp):
        data = self.struct.pack(self.data)

        fr = io.BytesIO()
        fr.write(data)

        for loc in self.raw_locns:
            loc.write(fr)

        l = fr.tell()
        fr.write(b"\0" * (self.HEADER_SIZE - l))

        raw = fr.getvalue()

        cs = struct.Struct("<L")
        checksum = _calc_crc(raw[cs.size:])
        self.data["checksum"] = checksum
        data = self.struct.pack(self.data)
        fr.seek(0)
        fr.write(data)

        fp.seek(self.start)
        n = fp.write(fr.getvalue())
        print(n)
        return n

    def __str__(self):
        msg = f"MDA: crc: {self.checksum}, {self.size} bytes @ {self.start}"
        if self.raw_locns:
            msg += "\n\t" + "\n\t".join(map(str, self.raw_locns))
        return msg


class Metadata:
    def __init__(self, header: MDAHeader, data: Dict) -> None:
        self.header = header
        self.data = data

    @staticmethod
    def parse(raw):
        substitutions = {
            r"#.*\n": "",
            r"\[": "[ ",
            r"\]": " ]",
            r'"': ' " ',
            r"[=,]": "",
            r"\s+":  " ",
            r"\0$": "",
        }

        data = raw
        for pattern, repl in substitutions.items():
            data = re.sub(pattern, repl, data)

        data = data.split()
        print(data)

        DICT_START = '{'
        DICT_END = '}'
        ARRAY_START = '['
        ARRAY_END = ']'
        STRING_START = '"'
        STRING_END = '"'

        def parse_str(val):
            result = ""

            while val != STRING_END:
                result = f"{result} {val}"
                val = data.pop(0)

            return result.strip()

        def parse_val(val):
            if val == STRING_START:
                return parse_str(data.pop(0))
            return int(val)

        def parse_array(val):
            result = []

            while val != ARRAY_END:
                val = parse_val(val)
                result.append(val)
                val = data.pop(0)

            return result

        def parse_dict(val):
            result = {}
            while val != DICT_END:
                result[val] = parse_obj()
                if not data:
                    return result
                val = data.pop(0)
            return result

        def parse_obj():

            val = data.pop(0)

            if val == DICT_START:
                return parse_dict(data.pop(0))
            elif val == ARRAY_START:
                return parse_array(data.pop(0))
            else:
                val = parse_val(val)

            return val

        name = data.pop(0)
        obj = parse_dict(name)

        return obj

    @staticmethod
    def encode(data):

        b = ""

        def encode_dict(d):
            s = ""
            for k, v in d.items():
                s += k
                if not isinstance(v, dict):
                    s += " = "
                else:
                    s += " "
                s += encode_val(v) + "\n"
            return s

        def encode_val(v):
            if isinstance(v, int):
                s = str(v)
            elif isinstance(v, str):
                s = f'"{v}"'
            elif isinstance(v, list):
                s = "[" + ", ".join(encode_val(x) for x in v) + "]"
            elif isinstance(v, dict):
                s = '{\n'
                s += encode_dict(v)
                s += '}\n'
            return s

        return encode_dict(data)


class Disk:
    def __init__(self, fp, path: PathLike, lbl: LabelHeader) -> None:
        self.fp = fp
        self.path = path

        self.lbl_hdr = lbl
        self.pv_hdr = lbl.read_pv_header(fp)

    @ classmethod
    def open(cls, path: PathLike) -> None:
        fp = open(path, "rb+")
        hdr = LabelHeader.search(fp)

        if not hdr:
            raise RuntimeError("Could not find label header")

        return cls(fp, path, hdr)

    def read_metadata(self):
        pv = self.pv_hdr

        for ma in pv.meta_areas:
            data = ma.read_data(self.fp)
            hdr = MDAHeader.read(data)
            md = hdr.read_metadata(self.fp)
            print(hdr)
            print(md)

            hdr.write_metadata(self.fp, md)
            md = hdr.read_metadata(self.fp)
            print(hdr)

    def dump(self):
        print(self.path)
        print(self.lbl_hdr)
        print(self.pv_hdr)

    def __enter__(self):
        assert self.fp, "Disk not open"
        return self

    def __exit__(self, *exc_details):
        if self.fp:
            self.fp.flush()
            self.fp.close()
            self.fp = None


def main():

    with Disk.open(sys.argv[1]) as disk:
        disk.dump()
        disk.read_metadata()


if __name__ == "__main__":
    main()
