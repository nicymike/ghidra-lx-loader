package yetmorecode.ghidra.lx;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import yetmorecode.file.format.lx.LinearObjectTableEntry;

public class OptionsTest {

	@Test
	public void parsesHexListsWithAndWithoutPrefix() {
		assertArrayEquals(new int[] { 0x10000, 0x20000, 0, 0x30000 }, Options.parseHexList("10000, 0x20000,,30000"));
	}

	@Test
	public void emptyInputIsOneEmptyEntry() {
		assertArrayEquals(new int[] { 0 }, Options.parseHexList(""));
	}

	@Test
	public void acceptsAddressesAboveTheSignedIntRange() {
		// Objects can be mapped at 0x80000000 and above (e.g. in DOS32A); this must not be rejected
		assertArrayEquals(new int[] { 0x80000000, 0xFFFFFFFF }, Options.parseHexList("80000000,0xFFFFFFFF"));
	}

	@Test
	public void baseOverrideAboveTheSignedIntRangeIsUsed() {
		var options = new Options();
		options.baseAddresses = new int[] { 0x80000000, 0, 0x12340000 };
		var object = new LinearObjectTableEntry();
		object.base = 0x10000;

		object.number = 1;
		assertEquals(0x80000000, options.getBaseAddress(object));
		// no override for object 2: original base, object 3: override
		object.number = 2;
		assertEquals(0x10000, options.getBaseAddress(object));
		object.number = 3;
		assertEquals(0x12340000, options.getBaseAddress(object));
	}

	@Test
	public void objectWithoutBaseIsMappedAlongTheObjectNumber() {
		var options = new Options();
		options.baseAddresses = new int[0];
		var object = new LinearObjectTableEntry();
		object.number = 3;
		object.base = 0;
		assertEquals(0x300000, options.getBaseAddress(object));
	}

	@Test
	public void rejectsInvalidInputInsteadOfStoringIt() {
		for (var value : new String[] { "zz", "10000,xyz", "1ffffffff" }) {
			try {
				Options.parseHexList(value);
				fail("Expected NumberFormatException for: " + value);
			} catch (NumberFormatException expected) {
				// ok
			}
		}
	}
}
