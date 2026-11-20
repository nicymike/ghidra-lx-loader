package yetmorecode.ghidra.lx;

import java.util.ArrayList;
import java.util.List;
import java.util.prefs.Preferences;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.ghidra.format.lx.model.FixupRecord;

public class Options {
	public final static String GROUP_OVERRIDES = "Overrides";
	public final static String GROUP_FIXUPS = "Fixups";
	public final static String GROUP_MEMORY_MAPPING = "Memory";
	public final static String GROUP_IMAGE_MAPPING = "Image";
	public final static String GROUP_EXPERIMENTAL = "Experimental";
	
	public final static String OPTION_MAP_EXTRA = "Map LE Loader, Fixup & Data Sections";
	public final static String OPTION_PAGE_LABELS = "Create labels at page beginnings";
	public final static String OPTION_FIXUP_LABELS = "Create labels at fixup positions";
	public final static String OPTION_RELOCATION_TABLE_DISABLE = "Deactivate import of fixup into Ghidra relocation table";
	
	
	public final static String OPTION_FIXUP_ENABLE_2 = "Apply 16-bit selector fixups";
	public final static String OPTION_FIXUP_ENABLE_3 = "Apply pointer 16:16 fixups";
	public final static String OPTION_FIXUP_ENABLE_5 = "Apply 16-bit offset fixups";
	public final static String OPTION_FIXUP_ENABLE_6 = "Apply pointer 16:32 fixups";
	public final static String OPTION_FIXUP_ENABLE_7 = "Apply 32-bit offset fixups";
	public final static String OPTION_FIXUP_ENABLE_8 = "Apply 32-bit offset self-ref fixups";
	public final static String OPTION_LOG_FIXUP_STATS = "Log fixup statistics";
	
	public final static String OPTION_OVERRIDE_ADDRESSES = "Object base addresses";
	public final static String OPTION_EMULATE_DOS32A = "Emulate DOS32A memory";
	public final static String OPTION_OVERRIDE_SELECTORS = "Object segment selectors";
	public final static String OPTION_ADD_ENTRY = "Mark entry point";
	public final static String OPTION_DISASSEMBLE = "Disassemble entry point";
	
	// Default options
	public boolean disassembleEntry = true;
	public boolean addEntry = true;
	public boolean mapExtra = false;
	public boolean[] enableType = new boolean[9];
	
	// More options available through "loader options"
	public boolean emulateDOS32A = false;
	public boolean logFixupStats = false;
	public boolean createPageLabels = false;
	public boolean createFixupLabels = false;
	public boolean relocationTableDisabled = false;
	public int[] baseAddresses;
	public int[] selectors;
	
	public Options() {
		var prefs = Preferences.userRoot().node(this.getClass().getName());
		enableType[2] = prefs.getBoolean(OPTION_FIXUP_ENABLE_2, true);
		enableType[3] = prefs.getBoolean(OPTION_FIXUP_ENABLE_3, true);
		enableType[5] = prefs.getBoolean(OPTION_FIXUP_ENABLE_5, true);
		enableType[6] = prefs.getBoolean(OPTION_FIXUP_ENABLE_6, true);
		enableType[7] = prefs.getBoolean(OPTION_FIXUP_ENABLE_7, true);
		enableType[8] = prefs.getBoolean(OPTION_FIXUP_ENABLE_8, true);
		disassembleEntry = prefs.getBoolean(OPTION_DISASSEMBLE, disassembleEntry);
		addEntry = prefs.getBoolean(OPTION_ADD_ENTRY, addEntry);
		mapExtra = prefs.getBoolean(OPTION_MAP_EXTRA, mapExtra);
		emulateDOS32A = prefs.getBoolean(OPTION_EMULATE_DOS32A, emulateDOS32A);
		logFixupStats = prefs.getBoolean(OPTION_LOG_FIXUP_STATS, logFixupStats);
		createPageLabels = prefs.getBoolean(OPTION_PAGE_LABELS, createPageLabels);
		createFixupLabels = prefs.getBoolean(OPTION_FIXUP_LABELS, createFixupLabels);
		relocationTableDisabled = prefs.getBoolean(OPTION_RELOCATION_TABLE_DISABLE, relocationTableDisabled);
		// The stored values were validated when they were saved, but the preferences can be edited by hand
		baseAddresses = parseHexListOrEmpty(prefs.get(OPTION_OVERRIDE_ADDRESSES, ""));
		selectors = parseHexListOrEmpty(prefs.get(OPTION_OVERRIDE_SELECTORS, ""));
	}
	
	public boolean fixupEnabled(FixupRecord r) {
		var type = r.getSourceType();
		return type < enableType.length && enableType[type];
	}
	
	public int getBaseAddress(LinearObjectTableEntry object) {
		var customBase = getBaseOverride(object.number);
		// base address overridden in options? (0 means "not set"; addresses from 0x80000000 on are negative ints)
		if (customBase != 0) {
			return customBase;
		}
		// no base address? -> map along based on object numbers
		if (object.base == 0) {
			return object.number * 0x100000;
		}
		// original object base
		return object.base;
	}
	
	/**
	 * @return the base address entered in the options for this object number, or 0 if there is none. This is
	 *         not the address the object is mapped at, use {@link #getBaseAddress(LinearObjectTableEntry)} for that.
	 */
	public int getBaseOverride(int number) {
		var index = number - 1;
		if (baseAddresses != null && baseAddresses.length > index) {
			if (baseAddresses[index] != 0) {
				return baseAddresses[index];
			}
		}
		return 0;
	}
	
	public int getSelector(LinearObjectTableEntry object) {
		return getSelector(object.number);
	}
	
	public int getSelector(int number) {
		var index = number - 1;
		if (selectors != null && selectors.length > index) {
			if (selectors[index] != 0) {
				return selectors[index];
			}
		}
		return index;
	}
	
	public int getSelector(short number) {
		var index = number - 1;
		if (selectors != null && selectors.length > index) {
			if (selectors[index] != 0) {
				return selectors[index];
			}
		}
		return index;
	}
	
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		var list = new ArrayList<Option>();
		
		var prefs = Preferences.userRoot().node(this.getClass().getName());
		
		list.add(new Option(GROUP_OVERRIDES, OPTION_ADD_ENTRY, prefs.getBoolean(OPTION_ADD_ENTRY, addEntry)));
		list.add(new Option(GROUP_OVERRIDES, OPTION_DISASSEMBLE, prefs.getBoolean(OPTION_DISASSEMBLE, disassembleEntry)));
		list.add(new Option(GROUP_OVERRIDES, OPTION_OVERRIDE_ADDRESSES, prefs.get(OPTION_OVERRIDE_ADDRESSES, "")));
		list.add(new Option(GROUP_OVERRIDES, OPTION_OVERRIDE_SELECTORS, prefs.get(OPTION_OVERRIDE_SELECTORS, "")));	
		
		//list.add(new Option(GROUP_OVERRIDES, OPTION_EMULATE_DOS32A, emulateDOS32A));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_EXTRA, prefs.getBoolean(OPTION_MAP_EXTRA, mapExtra)));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_PAGE_LABELS, prefs.getBoolean(OPTION_PAGE_LABELS, createPageLabels)));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_FIXUP_LABELS, prefs.getBoolean(OPTION_FIXUP_LABELS, createFixupLabels)));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_2, prefs.getBoolean(OPTION_FIXUP_ENABLE_2, enableType[2])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_3, prefs.getBoolean(OPTION_FIXUP_ENABLE_3, enableType[3])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_5, prefs.getBoolean(OPTION_FIXUP_ENABLE_5, enableType[5])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_6, prefs.getBoolean(OPTION_FIXUP_ENABLE_6, enableType[6])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_7, prefs.getBoolean(OPTION_FIXUP_ENABLE_7, enableType[7])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_8, prefs.getBoolean(OPTION_FIXUP_ENABLE_8, enableType[8])));
		list.add(new Option(GROUP_FIXUPS, OPTION_LOG_FIXUP_STATS, prefs.getBoolean(OPTION_LOG_FIXUP_STATS, logFixupStats)));
		list.add(new Option(GROUP_EXPERIMENTAL, OPTION_RELOCATION_TABLE_DISABLE, prefs.getBoolean(OPTION_RELOCATION_TABLE_DISABLE, relocationTableDisabled)));
		return list;
	}
	
	/**
	 * Applies the options and remembers them in the preferences.
	 * 
	 * @return an error message if an option is invalid (nothing is changed in this case), otherwise null
	 */
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		// Parse the lists first: invalid input must not be stored, otherwise it would break every later start
		int[] newBaseAddresses = null;
		int[] newSelectors = null;
		for (var option : options) {
			try {
				if (option.getName().equals(OPTION_OVERRIDE_ADDRESSES)) {
					newBaseAddresses = parseHexList(option.getValue().toString());
				} else if (option.getName().equals(OPTION_OVERRIDE_SELECTORS)) {
					newSelectors = parseHexList(option.getValue().toString());
				}
			} catch (NumberFormatException e) {
				return String.format("Invalid value for '%s': %s (expected a comma-separated list of hex values)", option.getName(), e.getMessage());
			}
		}
		
		var prefs = Preferences.userRoot().node(this.getClass().getName());
		for (Option option : options) {
			if (option.getName().equals(OPTION_MAP_EXTRA)) {
				mapExtra = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_MAP_EXTRA, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_PAGE_LABELS)) {
				createPageLabels = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_PAGE_LABELS, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_LABELS)) {
				createFixupLabels = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_LABELS, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_ADD_ENTRY)) {
				addEntry = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_ADD_ENTRY, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_DISASSEMBLE)) {
				disassembleEntry = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_DISASSEMBLE, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_LOG_FIXUP_STATS)) {
				logFixupStats = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_LOG_FIXUP_STATS, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_2)) {
				enableType[2] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_2, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_3)) {
				enableType[3] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_3, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_5)) {
				enableType[5] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_5, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_6)) {
				enableType[6] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_6, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_7)) {
				enableType[7] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_7, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_8)) {
				enableType[8] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_8, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_EMULATE_DOS32A)) {
				emulateDOS32A = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_EMULATE_DOS32A, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_RELOCATION_TABLE_DISABLE)) {
				relocationTableDisabled = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_RELOCATION_TABLE_DISABLE, Boolean.parseBoolean(option.getValue().toString()));
			}
		}
		
		for (var option : options) {
			if (option.getName().equals(OPTION_OVERRIDE_ADDRESSES)) {
				prefs.put(OPTION_OVERRIDE_ADDRESSES, option.getValue().toString());
				baseAddresses = newBaseAddresses;
			} else if (option.getName().equals(OPTION_OVERRIDE_SELECTORS)) {
				prefs.put(OPTION_OVERRIDE_SELECTORS, option.getValue().toString());
				selectors = newSelectors;
			}
		}
		return null;
	}
	
	private static int[] parseHexListOrEmpty(String value) {
		try {
			return parseHexList(value);
		} catch (NumberFormatException e) {
			return new int[0];
		}
	}
	
	/**
	 * Parses a comma-separated list of hex values (with or without 0x prefix). Empty entries become 0 
	 * (meaning "no override"). Values up to 0xFFFFFFFF are accepted.
	 * 
	 * @throws NumberFormatException if an entry is not a hex number
	 */
	static int[] parseHexList(String value) {
		String[] entries = value.split(",", -1);
		int[] result = new int[entries.length];
		for (int i = 0; i < entries.length; i++) {
			// See issue #9
			String entry = entries[i].strip();
			if (entry.startsWith("0x") || entry.startsWith("0X")) {
				entry = entry.substring(2);
			}
			result[i] = entry.isEmpty() ? 0 : Integer.parseUnsignedInt(entry, 16);
		}
		return result;
	}
}
