import struct


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def make_pe(sections, entry=0x1000, imports=(0x3000, 60), reloc=(0x4000, 12),
            base=0x14000000, dll=True, image_size=None, timestamp=0):
    header = bytearray(0x400)
    header[:2] = b'MZ'
    struct.pack_into('<I', header, 0x3c, 0x80)
    header[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', header, 0x84, 0x14c, len(sections), timestamp, 0, 0,
                     224, 0x2102 if dll else 0x102)
    opt = 0x98
    struct.pack_into('<HBBIIIIII', header, opt, 0x10b, 1, 0, 0x1000, 0x2000, 0,
                     entry, 0x1000, 0x2000)
    struct.pack_into('<IIIHHHHHH', header, opt + 28, base, 0x1000, 0x200, 4,
                     0, 0, 0, 4, 0)
    size = image_size or align(max(rva + len(data) for _, rva, data, _ in sections), 0x1000)
    struct.pack_into('<IIIIHHIIIIII', header, opt + 52, 0, size, 0x400, 0, 3,
                     0x140, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into('<II', header, opt + 96 + 8, *imports)
    struct.pack_into('<II', header, opt + 96 + 5 * 8, *reloc)
    output = bytearray(header)
    for index, (name, rva, data, flags) in enumerate(sections):
        raw_position = len(output)
        raw_size = align(len(data), 0x200)
        struct.pack_into('<8sIIIIIIHHI', output, 0x178 + index * 40, name.encode(),
                         len(data), rva, raw_size, raw_position, 0, 0, 0, 0, flags)
        output.extend(data)
        output.extend(bytes(raw_size - len(data)))
    return bytes(output)
