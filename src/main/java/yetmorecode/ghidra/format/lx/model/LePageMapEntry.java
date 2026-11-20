package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import ghidra.util.BigEndianDataConverter;
import yetmorecode.file.format.lx.LePageTableEntry;

public class LePageMapEntry extends LePageTableEntry {
	public LePageMapEntry(Executable exe, int page) throws IOException {
		var reader = exe.getBinaryReader();
		var oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(exe.lfanew + exe.header.pageTableOffset + page * SIZE);
		int data = BigEndianDataConverter.INSTANCE.getInt(reader.readNextByteArray(4));
		// Number of the physical page (1-based) and flags. The size of the page depends on whether it
		// is the last physical page, so it is determined in Executable.
		dataOffset = data >>> 8;
		flags = (short) (data & 0xff);
		dataSize = (short) exe.header.pageSize;
		reader.setPointerIndex(oldIndex);
	}
}
