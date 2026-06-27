"""Small QR Code renderer for local pairing URLs.

This intentionally supports the common case this app needs: byte-mode QR codes
with low error correction for short LAN URLs. It avoids a runtime dependency on
external QR packages.
"""

from __future__ import annotations

from io import BytesIO


QR_SPECS = {
    # version: (alignment positions, error-correction codewords per block, data codewords per block)
    1: ([], 7, [19]),
    2: ([6, 18], 10, [34]),
    3: ([6, 22], 15, [55]),
    4: ([6, 26], 20, [80]),
    5: ([6, 30], 26, [108]),
    6: ([6, 34], 18, [68, 68]),
    7: ([6, 22, 38], 20, [78, 78]),
    8: ([6, 24, 42], 24, [97, 97]),
    9: ([6, 26, 46], 30, [116, 116]),
}

FORMAT_MASK = 0x5412
FORMAT_POLY = 0x537
MASK_PATTERN = 0


class QrError(ValueError):
    pass


def make_qr_matrix(text: str) -> list[list[bool]]:
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    alignment, ecc_len, block_sizes = QR_SPECS[version]
    size = 17 + version * 4

    data_codewords = _make_data_codewords(data, sum(block_sizes))
    final_codewords = _add_error_correction(data_codewords, block_sizes, ecc_len)

    modules: list[list[bool]] = [[False] * size for _ in range(size)]
    is_function = [[False] * size for _ in range(size)]

    def set_function(row: int, col: int, dark: bool) -> None:
        modules[row][col] = dark
        is_function[row][col] = True

    _draw_function_patterns(modules, is_function, set_function, version, alignment)
    _draw_format_bits(modules, is_function, set_function, MASK_PATTERN)
    _draw_codewords(modules, is_function, final_codewords)
    _apply_mask(modules, is_function, MASK_PATTERN)
    _draw_format_bits(modules, is_function, set_function, MASK_PATTERN)
    return modules


def make_qr_ascii(text: str, border: int = 4) -> str:
    modules = make_qr_matrix(text)
    lines: list[str] = []
    width = len(modules) + border * 2
    blank = "  " * width
    lines.extend(blank for _ in range(border))
    for row in modules:
        line = "  " * border
        line += "".join("██" if item else "  " for item in row)
        line += "  " * border
        lines.append(line)
    lines.extend(blank for _ in range(border))
    return "\n".join(lines)


def make_qr_png_bytes(text: str, scale: int = 12, border: int = 4) -> bytes:
    try:
        from PIL import Image
    except Exception as exc:
        raise QrError(f"Pillow is required for PNG QR output: {exc}") from exc

    modules = make_qr_matrix(text)
    size = len(modules)
    outer = (size + border * 2) * scale
    image = Image.new("RGB", (outer, outer), "white")
    pixels = image.load()
    for row_index, row in enumerate(modules):
        for col_index, dark in enumerate(row):
            if not dark:
                continue
            x0 = (col_index + border) * scale
            y0 = (row_index + border) * scale
            for y in range(y0, y0 + scale):
                for x in range(x0, x0 + scale):
                    pixels[x, y] = (0, 0, 0)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def make_qr_svg(text: str, scale: int = 8, border: int = 4) -> str:
    modules = make_qr_matrix(text)
    size = len(modules)
    outer = (size + border * 2) * scale
    rects: list[str] = []
    for row_index, row in enumerate(modules):
        for col_index, dark in enumerate(row):
            if dark:
                x = (col_index + border) * scale
                y = (row_index + border) * scale
                rects.append(f'<rect x="{x}" y="{y}" width="{scale}" height="{scale}"/>')
    rect_text = "".join(rects)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {outer} {outer}" '
        f'width="{outer}" height="{outer}" role="img" aria-label="Pairing QR code">'
        f'<rect width="100%" height="100%" fill="#fff"/>'
        f'<g fill="#111">{rect_text}</g>'
        f"</svg>"
    )


def _choose_version(byte_len: int) -> int:
    for version, (_, _, block_sizes) in QR_SPECS.items():
        capacity_bits = sum(block_sizes) * 8
        needed_bits = 4 + 8 + byte_len * 8
        if needed_bits <= capacity_bits:
            return version
    raise QrError("Pairing URL is too long for the built-in QR renderer.")


def _make_data_codewords(data: bytes, data_capacity: int) -> list[int]:
    capacity_bits = data_capacity * 8
    bits: list[int] = []
    _append_bits(bits, 0b0100, 4)  # byte mode
    _append_bits(bits, len(data), 8)
    for byte in data:
        _append_bits(bits, byte, 8)

    terminator = min(4, capacity_bits - len(bits))
    bits.extend([0] * terminator)
    while len(bits) % 8:
        bits.append(0)

    codewords = [_bits_to_int(bits[index : index + 8]) for index in range(0, len(bits), 8)]
    pad = 0xEC
    while len(codewords) < data_capacity:
        codewords.append(pad)
        pad = 0x11 if pad == 0xEC else 0xEC
    return codewords


def _add_error_correction(data_codewords: list[int], block_sizes: list[int], ecc_len: int) -> list[int]:
    blocks: list[list[int]] = []
    offset = 0
    for size in block_sizes:
        block = data_codewords[offset : offset + size]
        offset += size
        blocks.append(block)

    ecc_blocks = [_reed_solomon_remainder(block, ecc_len) for block in blocks]
    result: list[int] = []
    for index in range(max(len(block) for block in blocks)):
        for block in blocks:
            if index < len(block):
                result.append(block[index])
    for index in range(ecc_len):
        for ecc in ecc_blocks:
            result.append(ecc[index])
    return result


def _draw_function_patterns(
    modules: list[list[bool]],
    is_function: list[list[bool]],
    set_function,
    version: int,
    alignment: list[int],
) -> None:
    size = len(modules)
    _draw_finder(set_function, 0, 0, size)
    _draw_finder(set_function, size - 7, 0, size)
    _draw_finder(set_function, 0, size - 7, size)

    for index in range(8, size - 8):
        dark = index % 2 == 0
        if not is_function[6][index]:
            set_function(6, index, dark)
        if not is_function[index][6]:
            set_function(index, 6, dark)

    for row in alignment:
        for col in alignment:
            if is_function[row][col]:
                continue
            _draw_alignment(set_function, row, col)

    set_function(4 * version + 9, 8, True)


def _draw_finder(set_function, top: int, left: int, size: int) -> None:
    for dy in range(-1, 8):
        for dx in range(-1, 8):
            row = top + dy
            col = left + dx
            if not (0 <= row < size and 0 <= col < size):
                continue
            dark = (
                0 <= dx <= 6
                and 0 <= dy <= 6
                and (dx in (0, 6) or dy in (0, 6) or (2 <= dx <= 4 and 2 <= dy <= 4))
            )
            set_function(row, col, dark)


def _draw_alignment(set_function, center_row: int, center_col: int) -> None:
    for dy in range(-2, 3):
        for dx in range(-2, 3):
            dark = max(abs(dx), abs(dy)) != 1
            set_function(center_row + dy, center_col + dx, dark)


def _draw_format_bits(modules: list[list[bool]], is_function: list[list[bool]], set_function, mask: int) -> None:
    size = len(modules)
    bits = _format_bits(mask)

    for index in range(6):
        set_function(index, 8, _get_bit(bits, index))
    set_function(7, 8, _get_bit(bits, 6))
    set_function(8, 8, _get_bit(bits, 7))
    set_function(8, 7, _get_bit(bits, 8))
    for index in range(9, 15):
        set_function(8, 14 - index, _get_bit(bits, index))

    for index in range(8):
        set_function(8, size - 1 - index, _get_bit(bits, index))
    for index in range(8, 15):
        set_function(size - 15 + index, 8, _get_bit(bits, index))
    set_function(size - 8, 8, True)


def _draw_codewords(modules: list[list[bool]], is_function: list[list[bool]], codewords: list[int]) -> None:
    size = len(modules)
    bits: list[int] = []
    for codeword in codewords:
        _append_bits(bits, codeword, 8)

    bit_index = 0
    upward = True
    right = size - 1
    while right >= 1:
        if right == 6:
            right -= 1
        for vert in range(size):
            row = size - 1 - vert if upward else vert
            for col in (right, right - 1):
                if is_function[row][col]:
                    continue
                modules[row][col] = bool(bits[bit_index]) if bit_index < len(bits) else False
                bit_index += 1
        upward = not upward
        right -= 2


def _apply_mask(modules: list[list[bool]], is_function: list[list[bool]], mask: int) -> None:
    for row_index, row in enumerate(modules):
        for col_index, _ in enumerate(row):
            if is_function[row_index][col_index]:
                continue
            if _mask_condition(mask, row_index, col_index):
                modules[row_index][col_index] = not modules[row_index][col_index]


def _mask_condition(mask: int, row: int, col: int) -> bool:
    if mask == 0:
        return (row + col) % 2 == 0
    raise QrError(f"Unsupported mask pattern: {mask}")


def _format_bits(mask: int) -> int:
    data = (0b01 << 3) | mask  # low error correction
    rem = data << 10
    for shift in range(14, 9, -1):
        if (rem >> shift) & 1:
            rem ^= FORMAT_POLY << (shift - 10)
    return ((data << 10) | rem) ^ FORMAT_MASK


def _append_bits(bits: list[int], value: int, count: int) -> None:
    for shift in range(count - 1, -1, -1):
        bits.append((value >> shift) & 1)


def _bits_to_int(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _get_bit(value: int, index: int) -> bool:
    return ((value >> index) & 1) != 0


def _reed_solomon_remainder(data: list[int], degree: int) -> list[int]:
    generator = _reed_solomon_generator(degree)
    remainder = [0] * degree
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        for index in range(degree):
            remainder[index] ^= _gf_multiply(generator[index + 1], factor)
    return remainder


def _reed_solomon_generator(degree: int) -> list[int]:
    result = [1]
    for index in range(degree):
        result = _poly_multiply(result, [1, _gf_pow(2, index)])
    return result


def _poly_multiply(left: list[int], right: list[int]) -> list[int]:
    result = [0] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            result[left_index + right_index] ^= _gf_multiply(left_value, right_value)
    return result


def _gf_pow(value: int, power: int) -> int:
    result = 1
    for _ in range(power):
        result = _gf_multiply(result, value)
    return result


def _gf_multiply(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 0x100:
            left ^= 0x11D
    return result & 0xFF
