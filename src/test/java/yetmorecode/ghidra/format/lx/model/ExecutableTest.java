package yetmorecode.ghidra.format.lx.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import yetmorecode.file.format.lx.LinearFixupRecord;
import yetmorecode.ghidra.lx.InvalidHeaderException;
import yetmorecode.ghidra.lx.Options;
import yetmorecode.ghidra.lx.loader.LeLoader;
import yetmorecode.ghidra.lx.loader.LxLoader;

public class ExecutableTest {

	private Executable parse() throws Exception {
		// The options come from the Java preferences: no overrides, so that the tests are reproducible
		var options = new Options();
		options.baseAddresses = new int[0];
		options.selectors = new int[0];
		return new Executable(new ByteArrayProvider(LeTestFile.create()), options);
	}
	
	@Test
	public void objectFlagsDescribePermissionsAndBitness() throws Exception {
		var exe = parse();
		assertEquals(2, exe.objects.size());
		
		var code = (ObjectTableEntry) exe.objects.get(0);
		assertTrue(code.isReadable());
		assertFalse(code.isWritable());
		assertTrue(code.isExecutable());
		assertTrue(code.isBig());
		
		var data = (ObjectTableEntry) exe.objects.get(1);
		assertTrue(data.isReadable());
		assertTrue(data.isWritable());
		assertFalse(data.isExecutable());
		assertFalse("Big bit not set -> 16 bit object", data.isBig());
	}
	
	@Test
	public void pageTableHasOneEntryPerLogicalPage() throws Exception {
		var exe = parse();
		assertEquals("Header: 2 physical pages", 2, exe.header.pageCount);
		assertEquals(3, exe.logicalPageCount);
		assertEquals(3, exe.pageRecords.size());
		assertEquals(1, exe.pageRecords.get(0).getOffset());
		assertEquals(2, exe.pageRecords.get(1).getOffset());
		assertFalse("zero-filled page has no data in the file", exe.isPhysicalPage(exe.pageRecords.get(2)));
		assertTrue(exe.isPhysicalPage(exe.pageRecords.get(1)));
	}
	
	@Test
	public void pagePositionsAndSizesInFile() throws Exception {
		var exe = parse();
		assertEquals(LeTestFile.DATA_PAGES, exe.getPageFileOffset(exe.pageRecords.get(0)));
		assertEquals(LeTestFile.DATA_PAGES + LeTestFile.PAGE_SIZE, exe.getPageFileOffset(exe.pageRecords.get(1)));
		assertEquals(LeTestFile.PAGE_SIZE, exe.getPageDataSize(exe.pageRecords.get(0)));
		assertEquals("only the last physical page is shorter", LeTestFile.LAST_PAGE_SIZE, exe.getPageDataSize(exe.pageRecords.get(1)));
	}
	
	@Test
	public void pageWithoutFixupsHasEmptyFixupList() throws Exception {
		var exe = parse();
		assertTrue(exe.getFixups(3).isEmpty());
		assertEquals(4, exe.totalFixups());
	}
	
	@Test
	public void sourceListFixupIsSplitIntoOneFixupPerSource() throws Exception {
		// Type 32-bit offset with source list flag (0x07 | 0x20), internal, 32-bit target offset, 2 sources
		var bytes = new byte[] {
			0x27, 0x10, 0x02,                 // type, target flags, source count
			0x01,                             // object 1
			0x34, 0x12, 0x00, 0x00,           // target offset 0x1234
			0x10, 0x00, 0x20, 0x01            // sources 0x0010 and 0x0120
		};
		var reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		var raw = new FixupRecord(reader, 0, 1, 0x10000, 2, 0x1000);
		
		assertEquals("record size in the file includes the source list", bytes.length, raw.size);
		assertTrue(raw.hasSourceList());
		
		var single = raw.getSourceRecords();
		assertEquals(2, single.size());
		assertEquals(0x10, single.get(0).sourceOffset);
		assertEquals(0x120, single.get(1).sourceOffset);
		assertEquals(0x1234, single.get(1).targetOffset);
		assertEquals(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP, single.get(1).getSourceType());
		assertFalse("the copies are single fixups", single.get(0).hasSourceList());
		// page 2 with base 0x10000: 0x10000 + 2*0x1000 + 0x120
		assertEquals(0x12120, single.get(1).getSourceAddress());
	}
	
	@Test
	public void sourceListWithMoreThan127Entries() throws Exception {
		// The source count is an unsigned byte: 200 entries must not be read as a negative count
		int count = 200;
		var bytes = new byte[2 + 1 + 1 + 4 + count * 2];
		bytes[0] = 0x27;            // 32-bit offset with source list
		bytes[1] = 0x10;            // internal, 32-bit target offset
		bytes[2] = (byte) count;
		bytes[3] = 0x01;            // object 1
		for (int i = 0; i < count; i++) {
			bytes[8 + i * 2] = (byte) (i * 4);   // source offsets 0, 4, 8, ...
			bytes[9 + i * 2] = (byte) ((i * 4) >> 8);
		}
		var reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		var fixup = new FixupRecord(reader, 0, 1, 0x10000, 0, 0x1000);
		
		assertEquals(bytes.length, fixup.size);
		var sources = fixup.getSourceRecords();
		assertEquals(count, sources.size());
		assertEquals(199 * 4, sources.get(199).sourceOffset);
	}
	
	@Test
	public void importFixupHasNoObjectTarget() throws Exception {
		// 32-bit offset, import by ordinal (flag 1), module 3, ordinal 5 (8 bit), source 0x0008
		var bytes = new byte[] { 0x07, 0x01 | (byte) 0x80, 0x08, 0x00, 0x03, 0x05 };
		var reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		var fixup = new FixupRecord(reader, 0, 1, 0x10000, 0, 0x1000);
		assertFalse(fixup.hasInternalObjectTarget());
		assertEquals("module ordinal is stored in objectNumber", 3, fixup.objectNumber);
		assertEquals(bytes.length, fixup.size);
	}
	
	@Test
	public void fixupsAreAssignedToTheirPages() throws Exception {
		var exe = parse();
		assertEquals(4, exe.totalFixups());
		assertEquals(2, exe.fixups.get(1).size());
		assertEquals(2, exe.fixups.get(2).size());
		
		var offset32 = (FixupRecord) exe.fixups.get(1).get(0);
		assertEquals(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP, offset32.getSourceType());
		assertEquals(0x10, offset32.sourceOffset);
		assertEquals(2, offset32.objectNumber);
		assertEquals(0x20, offset32.targetOffset);
		assertEquals(9, offset32.size);
		
		var selector = (FixupRecord) exe.fixups.get(1).get(1);
		assertEquals(LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP, selector.getSourceType());
		assertEquals(0x24, selector.sourceOffset);
		assertEquals(2, selector.objectNumber);
		assertEquals("selector fixup has no target offset", 5, selector.size);
		
		var selfRelative = (FixupRecord) exe.fixups.get(2).get(0);
		assertEquals(LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP, selfRelative.getSourceType());
		assertEquals(1, selfRelative.objectNumber);
		assertEquals(4, selfRelative.targetOffset);
	}
	
	@Test
	public void fixupCrossingPageBoundaryHasNegativeSourceOffset() throws Exception {
		var exe = parse();
		var crossing = (FixupRecord) exe.fixups.get(2).get(1);
		assertEquals(LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP, crossing.getSourceType());
		assertEquals(-2, crossing.sourceOffset);
		assertEquals(0x100, crossing.targetOffset);
	}
	
	@Test
	public void leLoaderAcceptsLeAndRejectsLx() throws Exception {
		var reader = new BinaryReader(new ByteArrayProvider(LeTestFile.create()), true);
		new LeLoader().checkFormat(reader);
		try {
			new LxLoader().checkFormat(reader);
			fail("LX loader must not accept an LE file");
		} catch (InvalidHeaderException expected) {
			// ok
		}
	}
}
