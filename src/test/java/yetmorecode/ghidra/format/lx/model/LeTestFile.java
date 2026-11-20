package yetmorecode.ghidra.format.lx.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Builds a small synthetic LE file (without MZ stub) for tests.
 * 
 * Layout:
 * - Object 1: code (r-x), 32 bit, page 1, base 0x10000
 * - Object 2: data (rw-), 16 bit (big bit not set), page 2 (data) and page 3 (zero-filled,
 * not in the file), base 0x20000
 * - Fixups page 1: 32-bit offset (-> object 2 + 0x20 at 0x10), 16-bit selector (-> object 2 at 0x24)
 * - Fixups page 2: 32-bit self-relative (-> object 1 + 4 at 0), 32-bit offset across the page boundary
 *   (source offset -2, only the upper two bytes are on this page)
 */
public class LeTestFile {

	public static final int PAGE_SIZE = 0x1000;
	public static final int LAST_PAGE_SIZE = 16;
	public static final int HEADER_SIZE = 0xC4;
	public static final int OBJECT_TABLE = 0xC4;
	public static final int PAGE_TABLE = 0xF4;
	public static final int FIXUP_PAGE_TABLE = 0x100;
	public static final int FIXUP_RECORDS = 0x110;
	public static final int DATA_PAGES = 0x200;
	
	private static final byte[] PAGE1_FIXUPS = {
		// 32-bit offset, internal, 32-bit target offset, source 0x10, object 2, target 0x20
		0x07, 0x10, 0x10, 0x00, 0x02, 0x20, 0x00, 0x00, 0x00,
		// 16-bit selector, internal, source 0x24, object 2 (no target offset)
		0x02, 0x00, 0x24, 0x00, 0x02
	};
	
	private static final byte[] PAGE2_FIXUPS = {
		// 32-bit self-relative, internal, source 0, object 1, target 4
		0x08, 0x10, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
		// 32-bit offset, source -2 (page boundary), object 1, target 0x100
		0x07, 0x10, (byte) 0xFE, (byte) 0xFF, 0x01, 0x00, 0x01, 0x00, 0x00
	};
	
	public static byte[] create() {
		var b = ByteBuffer.allocate(DATA_PAGES + PAGE_SIZE + LAST_PAGE_SIZE).order(ByteOrder.LITTLE_ENDIAN);
		int fixupSize = PAGE1_FIXUPS.length + PAGE2_FIXUPS.length;
		
		// Header
		b.put(0, (byte) 'L').put(1, (byte) 'E');
		b.putShort(0x08, (short) 2); // cpu: 386
		b.putShort(0x0A, (short) 1); // os: OS/2 (as usual for DOS extenders)
		b.putInt(0x10, 0x200);       // module flags
		b.putInt(0x14, 2);           // pages
		b.putInt(0x18, 1);           // eip object
		b.putInt(0x1C, 0x40);        // eip
		b.putInt(0x20, 2);           // esp object
		b.putInt(0x24, 0x800);       // esp
		b.putInt(0x28, PAGE_SIZE);
		b.putInt(0x2C, LAST_PAGE_SIZE);
		b.putInt(0x30, fixupSize);
		b.putInt(0x40, OBJECT_TABLE);
		b.putInt(0x44, 2);           // object count
		b.putInt(0x48, PAGE_TABLE);
		b.putInt(0x68, FIXUP_PAGE_TABLE);
		b.putInt(0x6C, FIXUP_RECORDS);
		b.putInt(0x70, FIXUP_RECORDS + fixupSize);
		b.putInt(0x78, FIXUP_RECORDS + fixupSize);
		b.putInt(0x80, DATA_PAGES);
		
		// Object table: size, base, flags, page table index, page count, reserved
		putObject(b, 0, 0x1000, 0x10000, 0x2045, 1, 1);
		putObject(b, 1, 0x2000, 0x20000, 0x0003, 2, 2);
		
		// Page table (LE): 3 bytes page number (big endian) + 1 byte flags
		b.position(PAGE_TABLE);
		b.put(new byte[] { 0x00, 0x00, 0x01, 0x00 });
		b.put(new byte[] { 0x00, 0x00, 0x02, 0x00 });
		// Logical page 3: zero-filled (flag 3), no data in the file
		b.put(new byte[] { 0x00, 0x00, 0x00, 0x03 });
		
		// Fixup page table (logical pages + 1 entries) and fixup records
		b.position(FIXUP_PAGE_TABLE);
		b.putInt(0);
		b.putInt(PAGE1_FIXUPS.length);
		b.putInt(PAGE1_FIXUPS.length + PAGE2_FIXUPS.length);
		b.putInt(PAGE1_FIXUPS.length + PAGE2_FIXUPS.length);
		b.position(FIXUP_RECORDS);
		b.put(PAGE1_FIXUPS);
		b.put(PAGE2_FIXUPS);
		
		// Page data
		b.position(DATA_PAGES);
		for (int i = 0; i < PAGE_SIZE; i++) {
			b.put((byte) 0x90);
		}
		for (int i = 0; i < LAST_PAGE_SIZE; i++) {
			b.put((byte) 0xAA);
		}
		return b.array();
	}
	
	private static void putObject(ByteBuffer b, int index, int size, int base, int flags, int pageIndex, int pageCount) {
		int offset = OBJECT_TABLE + index * 24;
		b.putInt(offset, size);
		b.putInt(offset + 4, base);
		b.putInt(offset + 8, flags);
		b.putInt(offset + 12, pageIndex);
		b.putInt(offset + 16, pageCount);
	}
}
