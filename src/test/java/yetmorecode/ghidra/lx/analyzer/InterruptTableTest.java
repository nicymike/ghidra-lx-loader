package yetmorecode.ghidra.lx.analyzer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;

import org.junit.Test;

public class InterruptTableTest {

	private InterruptTable parse(String content) throws IOException {
		return InterruptTable.parse(new BufferedReader(new StringReader(content)));
	}
	
	@Test
	public void axEntryTakesPrecedenceOverAhEntry() throws IOException {
		var table = parse(
			"10 AH=10 Palette group\n" +
			"10 AX=1010 Set one DAC register\n"
		);
		assertEquals("Set one DAC register", table.getFunctionName(0x10, 0x10, 0x10));
		// Different AL: falls back to the AH entry
		assertEquals("Palette group", table.getFunctionName(0x10, 0x10, 0x12));
		// AL unknown: only AH can be evaluated
		assertEquals("Palette group", table.getFunctionName(0x10, 0x10, -1));
	}
	
	@Test
	public void functionNeedsKnownAh() throws IOException {
		var table = parse("21 AH=3D Open File\n");
		assertNull(table.getFunctionName(0x21, -1, 0x01));
	}
	
	@Test
	public void sameFunctionOnDifferentInterruptsIsNotMixedUp() throws IOException {
		var table = parse(
			"21 AH=3D DOS open\n" +
			"31 AX=003D Other function\n"
		);
		assertEquals("DOS open", table.getFunctionName(0x21, 0x3D, 0x00));
		assertEquals("Other function", table.getFunctionName(0x31, 0x00, 0x3D));
		assertNull(table.getFunctionName(0x31, 0x3D, 0x00));
	}
	
	@Test
	public void commentsAndEmptyLinesAreIgnoredAndInterruptNamesAreKept() throws IOException {
		var table = parse("# comment\n\n31 * DPMI\n");
		assertTrue(table.isKnownInterrupt(0x31));
		assertFalse(table.isKnownInterrupt(0x21));
		assertEquals("DPMI", table.getInterruptName(0x31));
	}
	
	@Test
	public void invalidLinesAreRejected() {
		for (var line : new String[] { "31 AX=02 too short", "ZZ AH=01 Name", "31 BX=0001 Name", "31 AH=01" }) {
			try {
				parse(line);
				fail("Expected IOException for: " + line);
			} catch (IOException expected) {
				// ok
			}
		}
	}
	
	@Test
	public void defaultTableContainsDosExtenderFunctions() throws IOException {
		var table = InterruptTable.loadDefault();
		assertEquals("DPMI: Set Protected Mode Interrupt Vector", table.getFunctionName(0x31, 0x02, 0x05));
		assertEquals("DOS: Open File", table.getFunctionName(0x21, 0x3D, 0x01));
		assertEquals("VESA: Display Window Control (Bank Switching)", table.getFunctionName(0x10, 0x4F, 0x05));
		assertEquals("Video: Palette / DAC Functions", table.getFunctionName(0x10, 0x10, 0x00));
		// DOS/32A specific functions according to the Programmer's Reference
		assertEquals("DOS/4G(W) + DOS/32A: Identification Call", table.getFunctionName(0x21, 0xFF, 0x00));
		assertEquals("DOS/32A: Allocate High Memory Block", table.getFunctionName(0x21, 0xFF, 0x91));
		assertEquals("DPMI: Get DOS Extender Info (PMODE/W compatible)", table.getFunctionName(0x31, 0xEE, 0xFF));
		// Win95 LFN functions are identified by AX and must not be confused with AH=71
		assertEquals("DOS: Win95 LFN Create Directory", table.getFunctionName(0x21, 0x71, 0x39));
		assertNull(table.getFunctionName(0x21, 0x71, 0x00));
		// Not documented, stays unknown
		assertNull(table.getFunctionName(0x21, 0xED, 0x00));
		assertNull(table.getFunctionName(0x2F, 0xFA, 0x1F));
	}
}
