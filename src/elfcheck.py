import lief

ELF_MAGIC = bytes([0x7F, 0x45, 0x4C, 0x46])


def validate_binary(path):
    """Validate that a patched binary is a valid ELF with intact structure."""
    print("\n[*] validating patched binary at: " + path)

    with open(path, "rb") as f:
        magic = f.read(4)
    if magic != ELF_MAGIC:
        raise Exception("ELF magic mismatch — binary is corrupted: " + path)
    print("[*] ELF magic: OK")

    binary = lief.parse(path)
    if binary is None:
        raise Exception("lief failed to parse binary: " + path)

    header = binary.header
    segments = len(binary.segments)
    sections = len(binary.sections)

    if segments != header.numberof_segments:
        raise Exception(
            "segment count mismatch: header=%d actual=%d"
            % (header.numberof_segments, segments)
        )
    print("[*] segments: %d OK" % segments)

    if sections != header.numberof_sections:
        raise Exception(
            "section count mismatch: header=%d actual=%d"
            % (header.numberof_sections, sections)
        )
    print("[*] sections: %d OK" % sections)

    print("[*] binary verification successful")
