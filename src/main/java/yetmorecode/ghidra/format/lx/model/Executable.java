package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import yetmorecode.file.format.lx.LinearExecutable;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.ghidra.lx.InvalidHeaderException;
import yetmorecode.ghidra.lx.Options;


public class Executable extends LinearExecutable {
    private BinaryReader reader;
    
    public boolean isUnbound = false;
    
    // MZ header
    public DOSHeader mz;
    
    // DOS/16 headers
    public HashMap<Long, Dos16Header> dos16Headers =  new HashMap<Long, Dos16Header>();
    public DOSHeader mzSecondary;
    
    // VxD version resource (i.e. e32_winresoff)
    public VxDVersionResource vxd;
    
    /**
     * Number of logical pages (entries of the object page table). This is more than the number of
     * physical pages (header.pageCount) if there are zero-filled or invalid pages.
     */
    public int logicalPageCount;
    
    // When there is no MZ header (i.e. unbound LE-Style executables), the new file header starts at 0
    public long lfanew = 0;
    public long lfamz = 0;
    
	public Executable(ByteProvider bp, Options options) throws IOException, InvalidHeaderException {
    	reader = new BinaryReader(bp, true);
    	try {
	    	// Try reading MZ header
	        mz = DOSHeader.createDOSHeader(reader);
	        if (mz.isDosSignature()) {
	        	if (mz.e_lfarlc() == 0x40) {
	        		// New exe style (with e_lfanew)
	        		lfanew = mz.e_lfanew();
	        	} else {
	        		// Old exe style (without e_lfanew)
	        		long secondaryOffset = (mz.e_cp()-1)*512 + mz.e_cblp();
	        		Dos16Header bwHeader;
	        		try {
	        			do {
	        				bwHeader = new Dos16Header(reader, secondaryOffset);
	        				dos16Headers.put(secondaryOffset, bwHeader);
	        				secondaryOffset = bwHeader.next_header_pos;
	        			} while (secondaryOffset > 0);
	        		} catch (InvalidHeaderException exception) {
	        			// Done walking BW headers
	        		}
	        		reader.setPointerIndex(secondaryOffset);
	        		mzSecondary = DOSHeader.createDOSHeader(reader);
	        		lfamz = secondaryOffset;
	        		lfanew = secondaryOffset + mzSecondary.e_lfanew();
	        	}
	        }
    	} catch (Exception e) {}
    	
    	// LX header
    	header = new Header(reader, lfanew);
    	if (header.winresoff > 0 && header.winreslen > 0) {
    		vxd = new VxDVersionResource(reader, lfamz + header.winresoff);
    	}
    	
    	// Object record table
    	for (int object = 0; object < header.objectCount; object++) {
    		objects.add(new ObjectTableEntry(this, object));
    	}
    	
    	// The page table has one entry per logical page, not per physical page
    	logicalPageCount = (int) header.pageCount;
    	for (var object : objects) {
    		logicalPageCount = Math.max(logicalPageCount, object.pageTableIndex + object.pageCount - 1);
    	}
    	
    	// Page record table
    	for (int page = 0; page < logicalPageCount; page++) {
    		if (header.isLe()) {
    			pageRecords.add(new LePageMapEntry(this, page));	
    		} else {
    			pageRecords.add(new LxPageMapEntry(this, page));
    		}
    	}
    	
    	// Read fixup page table
    	fixupTable = new long[logicalPageCount+1];
    	var tableOffset = lfanew + header.fixupPageTableOffset;
    	for (int i = 0; i <= logicalPageCount; i++) {
    		fixupTable[i] = getReader().readInt(tableOffset + i * 4);
    	}
    	
    	// Read fixups
    	var fixupRecordOffset = lfanew + header.fixupRecordTableOffset;
    	fixupCount = 0;
    	for (var object : objects) {
    		for (int i = 0; i < object.pageCount; i++) {
    			var page = object.pageTableIndex + i;
        		fixups.put(page, new ArrayList<>());
        		var fixupBegin = getFixupBegin(page);
        		var fixupEnd = getFixupEnd(page);
        		var fixupDataSize = fixupEnd - fixupBegin;
        		var current = 0;
    			while (current < fixupDataSize) {
    				var fixup = new FixupRecord(
						reader, 
						fixupRecordOffset + fixupBegin + current, 
						++fixupCount, 
						options.getBaseAddress(object),
						i,
						(int) header.pageSize
    				);
    				fixups.get(page).add(fixup);
    				current += fixup.size;
    			}
    		}
    	}
    }
	
    /**
     * Returns the underlying binary reader.
     * @return the underlying binary reader
     */
    public BinaryReader getBinaryReader() {
        return reader;
    }

    public BinaryReader getReader() {
		return reader;
	}

	public long getFixupBegin(int page) {
		return fixupTable[page-1];
	}
	
	public long getFixupEnd(int page) {
		return fixupTable[page];
	}
	
	public int totalFixups() {
		int total = 0;
		for (var i = 1; i <= logicalPageCount; i++) {
			total += getFixups(i).size();
		}
		return total;
	}
	
	/**
	 * The fixup records of a logical page (empty if the page does not belong to any object).
	 */
	public java.util.List<yetmorecode.file.format.lx.LinearFixupRecord> getFixups(int page) {
		var list = fixups.get(page);
		return list != null ? list : java.util.List.of();
	}
	
	/**
	 * The individual fixups of a logical page: source list records are split into one fixup per
	 * source offset. Not suitable for typing the fixup records in the file (there, the records
	 * count as they appear in the file).
	 */
	public java.util.List<FixupRecord> getSourceFixups(int page) {
		var result = new ArrayList<FixupRecord>();
		for (var fixup : getFixups(page)) {
			result.addAll(((FixupRecord) fixup).getSourceRecords());
		}
		return result;
	}
	
	/**
	 * @return true if the page has data in the file (otherwise: zero-filled, invalid, ...)
	 */
	public boolean isPhysicalPage(yetmorecode.file.format.lx.LinearPageTableEntry entry) {
		return entry.getFlags() == yetmorecode.file.format.lx.LinearPageTableEntry.FLAG_LEGAL;
	}
	
	/**
	 * Position of the page data in the file (normal pages only).
	 * 
	 * LE: page number (1-based) times page size.
	 * LX: offset from the page table, shifted by the page offset shift (for LX, the shift is stored in
	 * the field for the last page size).
	 */
	public long getPageFileOffset(yetmorecode.file.format.lx.LinearPageTableEntry entry) {
		if (header.isLe()) {
			return lfamz + header.dataPagesOffset + (long) (entry.getOffset() - 1) * header.pageSize;
		}
		return lfamz + header.dataPagesOffset + ((entry.getOffset() & 0xffffffffL) << header.lastPageSize);
	}
	
	/**
	 * Number of bytes of the page in the file (normal pages only).
	 * 
	 * LE: all pages are full, only the last physical page has the size lastPageSize.
	 * LX: the size is in the page table.
	 */
	public int getPageDataSize(yetmorecode.file.format.lx.LinearPageTableEntry entry) {
		if (header.isLe()) {
			if (entry.getOffset() == header.pageCount) {
				return (int) header.lastPageSize;
			}
			return (int) header.pageSize;
		}
		return entry.getSize() & 0xffff;
	}
	
	public boolean objectHasFixups(LinearObjectTableEntry object) {
		var total = 0;
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			total += getFixupEnd(page) - getFixupBegin(page);
		}
		return total > 0;
	}
}

