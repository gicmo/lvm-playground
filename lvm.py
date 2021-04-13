#!/usr/bin/python3

import binascii
import io
import struct

from typing import Dict, BinaryIO

# https://github.com/lvmteam/lvm2/blob/8801a86a3e0c87d92b250a6477f86ef9efdb2ba0/lib/format_text/format-text.c

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

    def read(self, fp: BinaryIO):
        pos = fp.tell()
        data = fp.read(self.size)
        up = self.struct.unpack_from(data)
        res = {
            field.name: up[idx]
            for idx, field in enumerate(self.fields)
        }
        res["_position"] = pos
        return res

    def write(self, fp: BinaryIO, data: Dict):
        values = [
            data[field.name] for field in self.fields
        ]
        data = self.struct.pack(*values)
        fp.write(data)

    def iter(self, fp):
        while True:
            yield self.read(fp)


# /* On disk - 32 bytes */
# struct label_header {
#     int8_t id[8];		/* LABELONE */
#     uint64_t sector_xl;	/* Sector number of this label */
#     uint32_t crc_xl;	/* From next field to end of sector */
#     uint32_t offset_xl;	/* Offset from start of struct to contents */
#     int8_t type[8];		/* LVM2 001 */
# } __attribute__ ((packed));
HeaderStruct = CStruct({
    "id": "8s",
    "sector": "Q",
    "crc": "L",
    "offset": "L",
    "type": "8s"
})

DiskLocNStruct = CStruct({
    "offset": "Q",
    "size": "Q"
})

RawLocnStruct = CStruct({
    "offset": "Q",
    "size": "Q",
    "checksum": "L",
    "filler": "L"
})

MDAHeaderStruct = CStruct({
    "checksum": "L",
    "magic": "16s",
    "version": "L",
    "start": "Q",
    "size": "Q"
})


class LabelHeader:

    LABELID = b"LABELONE"
    binary = struct.Struct("<8sQLL8s")

    def __init__(self, data, position):
        self.position = position

        unpacked = self.binary.unpack_from(data)
        self.sector = unpacked[1]
        self.crc = unpacked[2]
        self.offset = unpacked[3]
        self.type = unpacked[4]

    @classmethod
    def search(cls, fp):
        fp.seek(0, io.SEEK_SET)
        for i in range(3):
            data = fp.read(512)
            if data[0:8] == cls.LABELID:
                return LabelHeader(data, i*512)
        return None

    def __str__(self):
        return f"LabelHeader: {self.sector}, {self.crc}, {self.offset}, {self.type}"


class DiskLocN:
    """
    struct disk_locn {
        uint64_t offset;	/* Offset in bytes to start sector */
        uint64_t size;		/* Bytes */
    } __attribute__ ((packed));
    """
    binary = struct.Struct("<QQ")

    def __init__(self, offset, size):
        self.offset = offset
        self.size = size

    def __str__(self):
        return f"DiskLocN: {self.offset}, {self.size}"

    @classmethod
    def read(cls, fp):
        while True:
            data = fp.read(cls.binary.size)

            if len(data) < cls.binary.size:
                break

            offset, size = cls.binary.unpack_from(data)
            if offset == 0:
                break

            yield DiskLocN(offset, size)


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

    ID_LEN = 32
    binary = struct.Struct("<32sQ")

    def __init__(self, fp, lbl: LabelHeader):
        offset = lbl.position + lbl.offset
        fp.seek(offset, io.SEEK_SET)
        data = fp.read(self.binary.size)
        up = self.binary.unpack_from(data)
        self.uuid = up[0]

        self.data_areas = list(DiskLocN.read(fp))
        self.metadata_areas = list(DiskLocN.read(fp))

    def __str__(self):
        msg = f"PVHeader: {self.uuid} "
        msg += "\nData: \n\t" + "\n\t".join(map(str, self.data_areas))
        msg += "\nMeta: \n\t" + "\n\t".join(map(str, self.metadata_areas))
        return msg

    def metadata_headers(self, fp):
        for ma in self.metadata_areas:
            fp.seek(ma.offset)
            md = MDAHeaderStruct.read(fp)
            print("Metadata", md["version"], md["start"], md["size"])

            raw = []
            for loc in RawLocnStruct.iter(fp):
                if loc["offset"] == 0:
                    break
                raw.append(loc)

            r = raw[0]
            offset = md["start"] + r["offset"]
            fp.seek(offset)
            data = fp.read(r["size"])
            print(data)
            print(r["checksum"])
            print(_calc_crc(data))
            data = b"ck" + data[2:]
            # print(data)
            fp.seek(offset)
            fp.write(data)

            r["checksum"] = _calc_crc(data)
            print(r["checksum"])
            fp.seek(r["_position"])
            RawLocnStruct.write(fp, r)

            cdata = struct.Struct("<L")
            fp.seek(ma.offset + cdata.size)
            data = fp.read(MDA_HEADER_SIZE - cdata.size)
            checksum = cdata.pack(_calc_crc(data))
            fp.seek(ma.offset)
            fp.write(checksum)
            fp.write(data)


def main():

    with open("image.img", "rb+") as img:
        hdr = LabelHeader.search(img)
        print(hdr)
        pv = PVHeader(img, hdr)
        print(pv)
        pv.metadata_headers(img)


if __name__ == "__main__":
    main()
