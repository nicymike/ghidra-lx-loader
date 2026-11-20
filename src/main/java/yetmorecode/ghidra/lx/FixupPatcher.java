package yetmorecode.ghidra.lx;

import yetmorecode.file.format.lx.LinearFixupRecord;

/**
 * Writes the value of a fixup into the data of a page.
 * 
 * The source offset of a fixup can range from -(size-1) to the end of the page. If it is negative, or if the
 * fixup reaches over the end of the page, only the bytes that are actually on the page are written (the rest
 * belongs to the fixup record of the neighbouring page). A 32-bit fixup can therefore change 1, 2, 3 or
 * 4 bytes depending on its position.
 */
public final class FixupPatcher {

	private FixupPatcher() {
	}

	/**
	 * @return true if the loader can apply fixups of this source type (byte fixups are not implemented)
	 */
	public static boolean isSupportedType(int type) {
		return type == LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP
			|| type == LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP
			|| type == LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP
			|| type == LinearFixupRecord.SOURCE_1616PTR_FIXUP
			|| type == LinearFixupRecord.SOURCE_1632PTR_FIXUP
			|| type == LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP;
	}

	/**
	 * @return the number of bytes a fixup of this (supported) source type writes
	 */
	public static int sizeOf(int type) {
		if (type == LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP
			|| type == LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP
			|| type == LinearFixupRecord.SOURCE_1616PTR_FIXUP) {
			return 4;
		}
		if (type == LinearFixupRecord.SOURCE_1632PTR_FIXUP) {
			return 6;
		}
		if (type == LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP || type == LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP) {
			return 2;
		}
		throw new IllegalArgumentException("Unsupported fixup type " + type);
	}

	/**
	 * Calculates the bytes a fixup writes (little endian, see {@link #sizeOf(int)} for the number of bytes used).
	 * 
	 * @param type source type of the fixup
	 * @param targetBase address the target object is mapped at
	 * @param targetOffset offset of the target inside the target object
	 * @param selector segment selector of the target object (only used by pointer and selector fixups)
	 * @param sourceAddress address of the first byte the fixup writes (only used by self-relative fixups)
	 */
	public static long computeValue(int type, int targetBase, int targetOffset, int selector, long sourceAddress) {
		int address = targetBase + targetOffset;
		if (type == LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP) {
			return address & 0xffffffffL;
		}
		if (type == LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP) {
			return address & 0xffffL;
		}
		if (type == LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP) {
			// relative to the end of the 4 byte fixup
			return (int) (address - sourceAddress - 4) & 0xffffffffL;
		}
		if (type == LinearFixupRecord.SOURCE_1616PTR_FIXUP) {
			return (targetOffset & 0xffffL) | ((selector & 0xffffL) << 16);
		}
		if (type == LinearFixupRecord.SOURCE_1632PTR_FIXUP) {
			return (targetOffset & 0xffffffffL) | ((selector & 0xffffL) << 32);
		}
		if (type == LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP) {
			return selector & 0xffffL;
		}
		throw new IllegalArgumentException("Unsupported fixup type " + type);
	}

	/**
	 * @param page the data of the page
	 * @param sourceOffset offset of the fixup on the page (can be negative)
	 * @param value the value to write (little endian, only the lowest <code>size</code> bytes are used)
	 * @param size size of the fixup in bytes (1 to 8)
	 * @param write false to only count the affected bytes without changing the page
	 * @return the number of bytes of the fixup that are on the page
	 */
	public static int patch(byte[] page, int sourceOffset, long value, int size, boolean write) {
		int length = 0;
		for (int i = 0; i < size; i++) {
			int position = sourceOffset + i;
			if (position >= 0 && position < page.length) {
				if (write) {
					page[position] = (byte) (value >>> (8 * i));
				}
				length++;
			}
		}
		return length;
	}
}
