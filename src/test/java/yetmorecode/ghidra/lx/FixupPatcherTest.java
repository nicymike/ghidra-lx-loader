package yetmorecode.ghidra.lx;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import yetmorecode.file.format.lx.LinearFixupRecord;

public class FixupPatcherTest {

	@Test
	public void writesLittleEndian() {
		var page = new byte[16];
		int length = FixupPatcher.patch(page, 4, 0x11223344L, 4, true);
		assertEquals(4, length);
		assertArrayEquals(new byte[] { 0, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0, 0, 0, 0, 0 }, page);
	}

	@Test
	public void fixupStartingBeforeThePageOnlyWritesTheUpperBytes() {
		// Source offset -2: the lower two bytes are on the previous page
		var page = new byte[8];
		int length = FixupPatcher.patch(page, -2, 0x11223344L, 4, true);
		assertEquals(2, length);
		assertArrayEquals(new byte[] { 0x22, 0x11, 0, 0, 0, 0, 0, 0 }, page);
	}

	@Test
	public void fixupReachingOverTheEndOfThePageOnlyWritesTheLowerBytes() {
		var page = new byte[8];
		int length = FixupPatcher.patch(page, 6, 0x11223344L, 4, true);
		assertEquals(2, length);
		assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0x44, 0x33 }, page);
	}

	@Test
	public void fixupOutsideOfThePageChangesNothing() {
		var page = new byte[8];
		assertEquals(0, FixupPatcher.patch(page, -4, 0x11223344L, 4, true));
		assertEquals(0, FixupPatcher.patch(page, 8, 0x11223344L, 4, true));
		assertArrayEquals(new byte[8], page);
	}

	@Test
	public void disabledFixupOnlyCountsTheBytes() {
		var page = new byte[8];
		assertEquals(4, FixupPatcher.patch(page, 2, 0xFFFFFFFFL, 4, false));
		assertArrayEquals(new byte[8], page);
	}

	@Test
	public void offsetFixupsAddTargetBaseAndOffset() {
		assertEquals(0x10004L, FixupPatcher.computeValue(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP, 0x10000, 4, 0, 0));
		// addresses above 0x7fffffff must not be sign extended into the 64-bit value
		assertEquals(0x80000010L, FixupPatcher.computeValue(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP, 0x80000000, 0x10, 0, 0));
		// the 16-bit fixup keeps the low word only
		assertEquals(0x2345L, FixupPatcher.computeValue(LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP, 0x11000, 0x1345, 0, 0));
	}

	@Test
	public void selfRelativeFixupIsRelativeToTheEndOfTheFixup() {
		// call at 0x10000 (fixup at 0x10001) to 0x10100: displacement = target - (source + 4)
		long value = FixupPatcher.computeValue(LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP, 0x10000, 0x100, 0, 0x10001);
		assertEquals(0x10100 - 0x10005, value);
		// backwards: negative displacement as unsigned 32-bit value
		value = FixupPatcher.computeValue(LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP, 0x10000, 0, 0, 0x10100);
		assertEquals((0x10000 - 0x10104) & 0xffffffffL, value);
	}

	@Test
	public void pointerAndSelectorFixupsCombineOffsetAndSelector() {
		assertEquals(0x00081234L, FixupPatcher.computeValue(LinearFixupRecord.SOURCE_1616PTR_FIXUP, 0x20000, 0x1234, 8, 0));
		assertEquals(0x0008_0000_1234L, FixupPatcher.computeValue(LinearFixupRecord.SOURCE_1632PTR_FIXUP, 0x20000, 0x1234, 8, 0));
		assertEquals(8L, FixupPatcher.computeValue(LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP, 0x20000, 0x1234, 8, 0));
	}

	@Test
	public void sizesMatchTheFixupTypes() {
		assertEquals(4, FixupPatcher.sizeOf(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP));
		assertEquals(2, FixupPatcher.sizeOf(LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP));
		assertEquals(4, FixupPatcher.sizeOf(LinearFixupRecord.SOURCE_1616PTR_FIXUP));
		assertEquals(6, FixupPatcher.sizeOf(LinearFixupRecord.SOURCE_1632PTR_FIXUP));
		assertEquals(2, FixupPatcher.sizeOf(LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP));
	}

	@Test
	public void byteFixupsAreNotSupported() {
		assertFalse(FixupPatcher.isSupportedType(LinearFixupRecord.SOURCE_BYTE_FIXUP));
		assertTrue(FixupPatcher.isSupportedType(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP));
	}

	@Test
	public void farPointerWithOffsetAndSelector() {
		// 16:32 pointer: 32-bit offset followed by the 16-bit selector
		var page = new byte[8];
		long value = 0x11223344L | (0x5566L << 32);
		assertEquals(6, FixupPatcher.patch(page, 1, value, 6, true));
		assertArrayEquals(new byte[] { 0, 0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0 }, page);
	}
}
