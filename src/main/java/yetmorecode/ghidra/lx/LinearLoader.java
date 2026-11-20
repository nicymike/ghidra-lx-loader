package yetmorecode.ghidra.lx;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.MemReferenceImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.ArrayDataType;
import yetmorecode.file.format.lx.LinearFixupRecord;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.file.format.lx.LinearPageTableEntry;
import yetmorecode.ghidra.format.lx.datatype.FixupSectionType;
import yetmorecode.ghidra.format.lx.datatype.LoaderSectionType;
import yetmorecode.ghidra.format.lx.model.FixupRecord;
import yetmorecode.ghidra.format.lx.model.Header;
import yetmorecode.ghidra.format.lx.model.Executable;
import yetmorecode.ghidra.format.lx.model.ObjectTableEntry;

/**
 * LxLoader - LX/LE/LC executable format loader
 * 
 * This loader is able to to load executable files of the LX/LE/LC format.
 * 
 * Linear Executable is an executable file format. 
 * It is used by OS/2, MS-DOS (DOS extender), and by MS Windows VxD files. 
 * It is a successor to NE (New Executable). 
 * There are two main varieties of it: LX (32-bit), and LE (mixed 16/32-bit).
 * LC variety is using compression (hence the C).
 * 
 * @author yetmorecode@posteo.net
 */
public abstract class LinearLoader extends AbstractLibrarySupportLoader {

	protected final static String CHECK = " " + (new String(new int[] { 0x2713 }, 0, 1)) + " ";
	protected final static String CLOCK = " " + (new String(new int[] { 0x231b }, 0, 1)) + " ";
	protected final static String HORSE = " " + (new String(new int[] { 0x2658 }, 0, 1)) + " ";
	protected final static String WARN = " " + (new String(new int[] { 0x26a0 }, 0, 1)) + " ";
	protected final static String ARROW = " " + (new String(new int[] { 0x2794 }, 0, 1)) + " ";
	
	protected MessageLog messageLog;
	protected Options loaderOptions = new Options();
	
	@Override
	public abstract String getName();

	public abstract void checkFormat(BinaryReader reader) throws IOException, InvalidHeaderException;
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < 4) {
			return loadSpecs;
		}
		var reader = new BinaryReader(provider, true);
		try {
			checkFormat(reader);
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("watcom:LE:32:default", "watcom"), true));
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), false));
		} catch (IOException e) {
			// While probing, a read error almost always means a wrong format (e.g. header outside of the file)
			Msg.debug(this, String.format("%s: IOException while probing for %s: %s", provider.getName(), getName(), e.getMessage()));
		} catch (InvalidHeaderException e) {
			// Everything is ok, but the provided data is not a valid LX/LE/LC
		}
		return loadSpecs;
	}
	
	public abstract void onLoadSuccess(Program program);

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		var monitor = settings.monitor();
		var provider = settings.provider();

		if (monitor.isCancelled()) {
			return;
		}
		messageLog = settings.log();
		messageLog.clear();
		
		// Use the options of this import (validateOptions is not necessarily called before, e.g. in headless mode)
		if (settings.options() != null) {
			var optionError = loaderOptions.validateOptions(provider, settings.loadSpec(), settings.options(), program);
			if (optionError != null) {
				throw new IOException(optionError);
			}
		}
		log(CLOCK + "Loading '%s'", program.getDomainFile());
		
		// Try parsing the executable
		int id = program.startTransaction(ARROW + "Loading..");
		monitor.setIndeterminate(true);
		monitor.setMessage(String.format(ARROW + "Loading %s", getName()));
		try {
			// Parse EXE from file
			var executable = new Executable(provider, loaderOptions);
			
			// Map IMAGE data (MZ, LX)
			createImageMappings(executable, program, provider, monitor);
			
			// Map objects
			createObjects(executable, program, monitor);
			
			// Add entrypoint, disassemble, ..
			createEntrypoint(executable, program, monitor);
			
			onLoadSuccess(program);
			program.endTransaction(id, true);
		} catch (CancelledException e) {
			program.endTransaction(id, false);
			throw e;
		} catch (Exception e) {
			program.endTransaction(id, false);
			Msg.error(this, String.format("Exception in `load` while parsing LxExecutable: %s", e.getMessage()), e);
			messageLog.appendException(e);
			// Pass the error on so that Ghidra reports the import as failed (instead of an empty program)
			throw new IOException("Could not load " + getName() + ": " + e.getMessage(), e);
		}
	}
	
	/**
	 * Creates MZ and LE exe image memory block (in OTHER space) and types the data
	 * 
	 * LX/LE have 3 main regions:
	 * - header (aka information section)
	 * - loader section (mostly fixup/relocation data)
	 * - data pages section
	 */
	private void createImageMappings(Executable e, Program program, ByteProvider provider, TaskMonitor monitor) throws CancelledException, IOException, AddressOverflowException, UsrException {
		var header = (Header)e.header;
		var dosHeader = e.mz;
		var fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		Address addr;		
		monitor.setMessage(String.format(ARROW + "Mapping Image data", header.getTypePrefix().toUpperCase()));

		// Map the whole image for inspection
		var b = MemoryBlockUtils.createInitializedBlock(
			program, 
			true, 
			".image", AddressSpace.OTHER_SPACE.getAddress(0), 
			fileBytes, 0, fileBytes.getSize(), 
			"Raw EXE image data", 
			null, 
			false, false, false, 
			null
		);
		
		if (e.mz.isDosSignature()) {
			// MZ image
			addr = b.getStart();
			createData(program, addr, dosHeader.toDataType());
			program.getSymbolTable().createLabel(b.getStart(), String.format("IMG_%08X_MZ_HEADER", 0), SourceType.USER_DEFINED);
			log(CHECK + "MZ Header");			
		}
		for (var s : e.dos16Headers.entrySet()) {
			// BW DOS/16 image
			addr = b.getStart().add(s.getKey());
			createData(program, addr, s.getValue().toDataType());
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_DOS16_HEADER", s.getKey()), SourceType.USER_DEFINED);
			log(CHECK + "BW DOS/16 Header");
		}
		
		if (e.mzSecondary != null) {
			// MZ image
			addr = b.getStart().add(e.lfamz);
			createData(program, addr, e.mzSecondary.toDataType());
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_MZ_HEADER", e.lfamz), SourceType.USER_DEFINED);
			log(CHECK + "MZ Header");			
		}

		// LE header
		addr = b.getStart().add(e.lfanew);
		createData(program, addr, header.toDataType());
		program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_LE_HEADER", e.lfanew), SourceType.USER_DEFINED);
		log(CHECK + "LX Header");
		
		if (loaderOptions.mapExtra) {
			// LE loader section
			addr = b.getStart().add(e.lfanew + header.objectTableOffset);
			monitor.setMessage(String.format(ARROW + "Mapping LX Loader section"));
			createData(
				program, 
				addr,
				new LoaderSectionType(e, header.fixupPageTableOffset - header.objectTableOffset)
			);
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_LE_LOADER", e.lfanew + header.objectTableOffset), SourceType.USER_DEFINED);
			log(CHECK + "LX Loader Section");
		
			// LE fixup section
			var dm = program.getDataTypeManager();
			var cat = dm.createCategory(new CategoryPath("/_le/_fixup"));
			addr = b.getStart().add(e.lfanew + header.fixupPageTableOffset);
			monitor.setMessage(String.format(ARROW + "Mapping Fixups (%d total)", e.fixupCount));
			monitor.setIndeterminate(true);
			monitor.setMaximum(e.fixupCount);
			monitor.setProgress(0);
			var ft = new FixupSectionType(
				e, 
				(int) (e.lfamz + header.dataPagesOffset - e.lfanew - header.fixupPageTableOffset),
				loaderOptions,
				cat,
				program,
				b,
				monitor
			);
			createData(program, addr, ft);
			program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_LE_FIXUP", e.lfanew + header.fixupPageTableOffset), SourceType.USER_DEFINED);
			log(CHECK + "LX Fixups");
		
			// LE Data Section
			addr = b.getStart().add(e.lfamz + header.dataPagesOffset);
			monitor.setMessage(String.format(ARROW + "Mapping data pages (%d total)", e.header.pageCount));
			var all = new StructureDataType("IMG_LE_DATA", 0);
			
			// Full size pages
			for (var i = 0; i < e.header.pageCount-1; i++) {
				var dt = new ArrayDataType(StructConverter.BYTE, header.pageSize, 0); 
				addr = b.getStart().add(e.lfamz + header.dataPagesOffset + i * header.pageSize);
				all.add(dt, "page_" + (i+1), "");
			}
			// Last page
			var dt = new ArrayDataType(StructConverter.BYTE, header.lastPageSize, 0);
			all.add(dt, "page_" + header.pageCount, "");
			
			addr = b.getStart().add(e.lfamz + header.dataPagesOffset);
			createData(program, addr, all);
			log(CHECK + "LX Data Pages");
			
			if (e.vxd != null) {
				// VxD Version Resource
				addr = b.getStart().add(e.lfamz + header.winresoff);
				createData(program, addr, e.vxd.toDataType());
				
				program.getSymbolTable().createLabel(addr, String.format("IMG_%08X_VXD_VERSION", e.lfamz + header.winresoff), SourceType.USER_DEFINED);
				log(CHECK + "VxD Windows VERSIONINFO");
			}
		}
	}
	
	private void createObjects(Executable executable, Program program, TaskMonitor monitor) throws IOException, UsrException {
		// Map each object
		var space = program.getAddressFactory().getDefaultAddressSpace();
		for (var object : executable.objects) {
			monitor.setMessage(String.format(ARROW + "Mapping .object%d", object.number));
			byte[] block = createObjectBlock(program, executable, object, object.number == executable.objects.size());
			var memoryBlock = program.getMemory().createInitializedBlock(
				".object" + object.number, 
				space.getAddress(loaderOptions.getBaseAddress(object)), 
				new ByteArrayInputStream(block), 
				object.size, 
				monitor, false
			);
			applyObjectFlags((ObjectTableEntry) object, memoryBlock, program);
		}
	}
	
	/**
	 * Applies the flags of the object (r/w/x, 16/32 bit) to the memory block.
	 * 
	 * If the object has no permission flags, the default permissions of Ghidra are kept.
	 */
	private void applyObjectFlags(ObjectTableEntry object, MemoryBlock block, Program program) {
		if (object.hasPermissionFlags()) {
			block.setRead(object.isReadable());
			block.setWrite(object.isWritable());
			block.setExecute(object.isExecutable());
		} else {
			log(WARN + ".object%d has no r/w/x flags, keeping default permissions", object.number);
		}
		
		if (!object.isBig()) {
			// 16-bit object: set operand size and address size to 16 bit for the disassembler
			var context = program.getProgramContext();
			var addrsize = context.getRegister("addrsize");
			var opsize = context.getRegister("opsize");
			try {
				if (addrsize != null) {
					context.setValue(addrsize, block.getStart(), block.getEnd(), BigInteger.ZERO);
				}
				if (opsize != null) {
					context.setValue(opsize, block.getStart(), block.getEnd(), BigInteger.ZERO);
				}
				log(CHECK + ".object%d is a 16-bit object (big bit not set)", object.number);
			} catch (ContextChangeException e) {
				log(WARN + "Could not set 16-bit mode for .object%d: %s", object.number, e.getMessage());
			}
		}
	}
	
	private Data createData(Program program, Address address, DataType dt) {
		try {
			Data d = program.getListing().getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				program.getListing().createData(address, dt);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "LX data markup conflict at " + address + ": " + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}
	
	private byte[] createObjectBlock(Program program, Executable le, LinearObjectTableEntry object, boolean isLastObject) throws IOException {
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var relocationTable = program.getRelocationTable();

		var header = (Header)le.header;
		var pageSize = header.pageSize; 
		
		// Temporary memory to assemble all pages to one block
		byte block[] = new byte[object.size+4096];
		var blockIndex = 0;
		
		// Some statistics on fixups
		int fixupsHandled = 0;
		int fixupsUnhandled = 0;
		int fixupsByType[] = new int[16];
		int unresolvedFixups = 0;

		// Loop through all pages for this object, apply fixups per page and add them together
		for (var i = 0; i < object.pageCount; i++) {
			// Page map indices are one-based 
			var index = object.pageTableIndex + i;
			
			var entry = le.pageRecords.get(index-1);
			byte[] pageData = readPage(le, entry, index, pageSize);
			var originalPageData = pageData.clone();
			
			// Apply fixups to page
			for (var f : le.getSourceFixups(index)) {
				var addr = space.getAddress(f.getSourceAddress());
				fixupsByType[Math.min(f.getSourceType(), fixupsByType.length - 1)]++;
				
				if (!hasInternalObjectTarget(le, f)) {
					// Import (other module) or entry table reference: the target is not an object of this
					// module, so the address cannot be calculated. The page data stays unchanged.
					fixupsUnhandled++;
					unresolvedFixups++;
					if (!loaderOptions.relocationTableDisabled) {
						relocationTable.add(
							addr, Relocation.Status.UNSUPPORTED, f.getSourceType(), 
							null, 0, 
							String.format("import_%s_%08x_module%d", f.shortname(), f.getSourceAddress(), f.objectNumber)
						);
					}
					continue;
				}
				
				// Apply the actual fixup
				int base = loaderOptions.getBaseAddress(le.objects.get(f.objectNumber-1));
				
				/*
				 * The sourceOffset for each fixup can range from -3 to pageData.length -1.
				 * If the source offset is negative, only a partial fixup is performed for
				 * the bytes actually on the page. The same holds for the end of the page.
				 * Thus of 32bit fixup can fix 1, 2, 3 or 4 bytes depending on the position
				 * of the fixup on the page. 
				 */
				int length = 0;
				var type = f.getSourceType();
				var enabled = loaderOptions.fixupEnabled(f);
				if (enabled && FixupPatcher.isSupportedType(type)) {
					fixupsHandled++;
				} else {
					fixupsUnhandled++;
				}

				var status = enabled ? Relocation.Status.APPLIED : Relocation.Status.SKIPPED;
				if (type == LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP) {
					length = patchFixup(pageData, f, type, base, 0, 0, enabled);
					addRelocation(relocationTable, addr, status, f, originalPageData, length, base + f.targetOffset);
				} else if (type == LinearFixupRecord.SOURCE_16BIT_OFFSET_FIXUP) {
					length = patchFixup(pageData, f, type, base, 0, 0, enabled);
					addRelocation(relocationTable, addr, status, f, originalPageData, length, (short)(base + f.targetOffset));
				} else if (type == LinearFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP) {
					var sourceAddress = (long) loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset;
					length = patchFixup(pageData, f, type, base, 0, sourceAddress, enabled);
					addRelocation(relocationTable, addr, status, f, originalPageData, length, 
						(int) FixupPatcher.computeValue(type, base, f.targetOffset, 0, sourceAddress));
				} else if (type == LinearFixupRecord.SOURCE_1616PTR_FIXUP) {
					var selector = loaderOptions.getSelector(f.objectNumber);
					length = patchFixup(pageData, f, type, base, selector, 0, enabled);
					addRelocation(relocationTable, addr, status, f, originalPageData, length, selector);
				} else if (type == LinearFixupRecord.SOURCE_1632PTR_FIXUP) {
					var selector = loaderOptions.getSelector(f.objectNumber);
					length = patchFixup(pageData, f, type, base, selector, 0, enabled);
					addRelocation(relocationTable, addr, status, f, originalPageData, length, f.targetOffset, (short)selector);
				} else if (type == LinearFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP) {
					var selector = loaderOptions.getSelector(f.objectNumber);
					length = patchFixup(pageData, f, type, base, selector, 0, enabled);
					addRelocation(relocationTable, addr, status, f, originalPageData, length, (short)selector);
				} else {
					Msg.warn(this, String.format(
						"WARNING: unhandled fixup %s (#%d) at %08x (type %02x): %s -> object#%x:%x",
						f.shortname(), f.index,
						f.getSourceAddress(),
						f.getSourceType(),
						f.hasSourceList() ? "source list " + f.sourceCount : String.format("%x", f.sourceOffset),
						f.objectNumber, f.targetOffset
					));
					relocationTable.add(
						addr, Relocation.Status.UNSUPPORTED, f.getSourceType(), 
						null, 0, 
						String.format("%s_%s_%08x",
							loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
							f.shortname(), 
							f.getSourceAddress() 
						)
					);
				}
				
			}
			
			// Copy page into object block
			System.arraycopy(pageData, 0, block, blockIndex, pageData.length);
			blockIndex += pageSize;
		}
		
		log(CHECK + "Mapped .object%d into memory: %08x - %08x [%08x] (selector %03x)", 
			object.number, 
			loaderOptions.getBaseAddress(object),
			loaderOptions.getBaseAddress(object) + object.size,
			object.size,
			loaderOptions.getSelector(object)
		);
		
		if (unresolvedFixups > 0) {
			log(WARN + ".object%d: %d fixups point to other modules and were not applied", object.number, unresolvedFixups);
		}
		
		// Log fixup statistics
		if (loaderOptions.logFixupStats) {
			ArrayList<String> byType = new ArrayList<>();
			for (int i = 0; i < fixupsByType.length; i++) {
				if (fixupsByType[i] > 0) {
					byType.add(String.format("%s: %d", i < FixupRecord.shortnames.length ? FixupRecord.shortnames[i] : "inv" + i, fixupsByType[i]));
				}
			}
			if (fixupsHandled + fixupsUnhandled > 0) {
				log(
					"  " + HORSE + "%d fixups [%s]",
					fixupsHandled + fixupsUnhandled,
					String.join(", ", byType)
				);
			}
		}
		return block;
	}
	

	
	
	private void addRelocation(RelocationTable relocationTable, Address addr, Status applied, FixupRecord f,
			byte[] originalPageData, int length, int value) {
		if (!loaderOptions.relocationTableDisabled) {
			var originalBytes = new byte[length];
			System.arraycopy(originalPageData, Math.max(0, f.sourceOffset), originalBytes, 0, length);
			relocationTable.add(
				addr, applied, f.getSourceType(), 
				null, originalBytes, 
				String.format("%s_%s_%08x_%08x",
					loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
					f.shortname(), 
					f.getSourceAddress(),
					value
				)
			);	
		}
	}
	
	private void addRelocation(RelocationTable relocationTable, Address addr, Status applied, FixupRecord f,
			byte[] originalPageData, int length, short value) {
		if (!loaderOptions.relocationTableDisabled) {
			var originalBytes = new byte[length];
			System.arraycopy(originalPageData, Math.max(0, f.sourceOffset), originalBytes, 0, length);
			relocationTable.add(
				addr, applied, f.getSourceType(), 
				null, originalBytes, 
				String.format("%s_%s_%08x_%04x",
					loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
					f.shortname(), 
					f.getSourceAddress(),
					value
				)
			);
		}
	}
	
	private void addRelocation(RelocationTable relocationTable, Address addr, Status applied, FixupRecord f,
			byte[] originalPageData, int length, int offset, short selector) {
		if (!loaderOptions.relocationTableDisabled) {
			var originalBytes = new byte[length];
			System.arraycopy(originalPageData, Math.max(0, f.sourceOffset), originalBytes, 0, length);
			relocationTable.add(
				addr, applied, f.getSourceType(), 
				null, originalBytes, 
				String.format("%s_%s_%08x_%04x_%08x",
					loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
					f.shortname(), 
					f.getSourceAddress(),
					selector, offset
				)
			);
		}
	}

	private void createEntrypoint(Executable exe, Program program, TaskMonitor monitor) throws UsrException {
		var s = program.getAddressFactory().getDefaultAddressSpace();
		var header = exe.header;
		
		// Initialization (entry point, disassemble, ...)
		if (loaderOptions.addEntry && (header.eipObject < 0 || header.eipObject > exe.objects.size())) {
			log(WARN + "Entry point is relative to object %d, which does not exist: no entry point set", header.eipObject);
		} else if (loaderOptions.addEntry && header.eipObject > 0) {
			monitor.setMessage(String.format(ARROW + "Setting entrypoint"));
			var api = new FlatProgramAPI(program, monitor);
			int eip = header.eip;
			var eipObject = exe.objects.get(header.eipObject-1);
			eip += loaderOptions.getBaseAddress(eipObject);			
			log(CHECK + "Entrypoint set @ %08x [base %08x + eip %08x]", 
				eip, 
				loaderOptions.getBaseAddress(eipObject), 
				header.eip
			);
			if (loaderOptions.disassembleEntry) {
				api.disassemble(api.toAddr(eip));	
			}
			program.getSymbolTable().createLabel(api.toAddr(eip), "_entry", SourceType.USER_DEFINED);
			api.createFunction(api.toAddr(eip), "_entry");
			api.addEntryPoint(api.toAddr(eip));
		}
		
		monitor.setMessage(String.format(ARROW + "Creating fixup xrefs & labels"));
		monitor.setIndeterminate(true);
		monitor.setProgress(0);
		monitor.setMaximum(exe.totalFixups());
		for (int i = 1; i <= exe.logicalPageCount; i++) {
			for (var f : exe.getSourceFixups(i)) {
				monitor.incrementProgress(1);
				if (!hasInternalObjectTarget(exe, f)) {
					continue;
				}
				var addr = s.getAddress(f.getSourceAddress());
	
				if (loaderOptions.createFixupLabels) {
					// Label at original position
					program.getSymbolTable().createLabel(
						addr, 
						String.format("%s_%s_%08x",
							loaderOptions.fixupEnabled(f) ? "fix" : "nofix",
							f.shortname(), 
							f.getSourceAddress() 
						), 
						SourceType.ANALYSIS
					);
				}
				
				// Next at code unit position
				var unit = program.getListing().getCodeUnitContaining(addr);
				if (unit != null) {
					addr = unit.getAddress();
				}
				
				if (loaderOptions.fixupEnabled(f) && f.is1616PointerFixup()) {
					// 16:16 pointer fixups are weird since they involve segment selectors
					// and Ghidra only knows DOS segmented memory (no protected mode segmentation),
					// so we remove the old ref and place one calculated by ourself
					var to = s.getAddress(getTargetAddress(exe, f));
					program.getReferenceManager().removeAllReferencesFrom(addr);
					var ref = new MemReferenceImpl(addr, to, RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0, true);
					program.getReferenceManager().addReference(ref);	
				}
				
				if (loaderOptions.createFixupLabels) {	
					program.getListing().setComment(
						addr, 
						CommentType.PRE, 
						String.format(
							"fixup to -> %08x",
							getTargetAddress(exe, f)
						)
					);
				}
			}
		}

		// Create a label for each physical page (in the image, not in the memory of the program)
		if (loaderOptions.createPageLabels) {
			var image = program.getMemory().getBlock(".image");
			if (image != null) {
				for (var i = 1; i <= exe.logicalPageCount; i++) {
					var entry = exe.pageRecords.get(i - 1);
					if (exe.isPhysicalPage(entry)) {
						var addr = image.getStart().add(exe.getPageFileOffset(entry));
						program.getSymbolTable().createLabel(addr, "LE_PAGE_" + i, SourceType.USER_DEFINED);
					}
				}
			}
		}
	}
	
	/**
	 * Reads the data of a logical page. The result always has the size of one page, missing data is 0.
	 * 
	 * Pages without data in the file (zero-filled, invalid) and pages in an unsupported format
	 * (iterated/compressed, exepack) stay empty.
	 */
	private byte[] readPage(Executable exe, LinearPageTableEntry entry, int logicalPage, int pageSize) throws IOException {
		var page = new byte[pageSize];
		if (!exe.isPhysicalPage(entry)) {
			switch (entry.getFlags()) {
				case LinearPageTableEntry.FLAG_ZERO:
					break;
				case LinearPageTableEntry.FLAG_ITERATED:
				case LinearPageTableEntry.FLAG_COMPRESSED:
					log(WARN + "Page %d is iterated/compressed (exepack), which is not supported: page stays empty", logicalPage);
					break;
				default:
					log(WARN + "Page %d has flags %d (invalid/range), page stays empty", logicalPage, entry.getFlags());
			}
			return page;
		}
		
		var reader = exe.getReader();
		var offset = exe.getPageFileOffset(entry);
		var available = reader.length() - offset;
		var size = (int) Math.min(Math.min(exe.getPageDataSize(entry), pageSize), available);
		if (size < exe.getPageDataSize(entry)) {
			log(WARN + "Page %d is truncated in the file", logicalPage);
		}
		if (size > 0) {
			System.arraycopy(reader.readByteArray(offset, size), 0, page, 0, size);
		}
		return page;
	}
	
	private boolean hasInternalObjectTarget(Executable exe, FixupRecord f) {
		return f.hasInternalObjectTarget() && f.objectNumber >= 1 && f.objectNumber <= exe.objects.size();
	}
	
	/**
	 * Target address (base address of the target object plus target offset) of a fixup with a target in this module
	 */
	/**
	 * Writes the value of the fixup into the page.
	 * 
	 * @return the number of bytes of the fixup that are on the page
	 */
	private int patchFixup(byte[] pageData, FixupRecord f, int type, int base, int selector, long sourceAddress, boolean write) {
		var value = FixupPatcher.computeValue(type, base, f.targetOffset, selector, sourceAddress);
		return FixupPatcher.patch(pageData, f.sourceOffset, value, FixupPatcher.sizeOf(type), write);
	}
	
	private int getTargetAddress(Executable exe, FixupRecord f) {
		return loaderOptions.getBaseAddress(exe.objects.get(f.objectNumber - 1)) + f.targetOffset;
	}
	
	private void log(String format, Object... args)  {
		messageLog.appendMsg(String.format(format, args));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		return loaderOptions.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		var error = loaderOptions.validateOptions(provider, loadSpec, options, program);
		if (error != null) {
			return error;
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
