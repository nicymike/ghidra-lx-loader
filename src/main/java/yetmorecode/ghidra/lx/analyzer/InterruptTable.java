package yetmorecode.ghidra.lx.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Table with the names of interrupt functions (DOS, DPMI, VESA, ...).
 * 
 * A function is identified either by AX (e.g. DPMI) or only by AH (e.g. DOS).
 * An entry by AX takes precedence over an entry by AH.
 */
public class InterruptTable {

	public static final String RESOURCE = "interrupts.txt";
	
	private final Map<Integer, String> interruptNames = new HashMap<>();
	private final Map<Integer, String> functionsByAx = new HashMap<>();
	private final Map<Integer, String> functionsByAh = new HashMap<>();
	
	/**
	 * Loads the default table that is shipped with the extension.
	 */
	public static InterruptTable loadDefault() throws IOException {
		try (InputStream in = InterruptTable.class.getResourceAsStream(RESOURCE)) {
			if (in == null) {
				throw new IOException("Resource not found: " + RESOURCE);
			}
			return parse(new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)));
		}
	}
	
	public static InterruptTable parse(BufferedReader reader) throws IOException {
		var table = new InterruptTable();
		String line;
		int lineNumber = 0;
		while ((line = reader.readLine()) != null) {
			lineNumber++;
			line = line.strip();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			table.parseLine(line, lineNumber);
		}
		return table;
	}
	
	private void parseLine(String line, int lineNumber) throws IOException {
		var parts = line.split("\\s+", 3);
		if (parts.length < 3) {
			throw new IOException("Invalid line " + lineNumber + ": " + line);
		}
		int interrupt;
		try {
			interrupt = Integer.parseInt(parts[0], 16);
		} catch (NumberFormatException e) {
			throw new IOException("Invalid interrupt number in line " + lineNumber + ": " + line);
		}
		var key = parts[1];
		var name = parts[2].strip();
		
		if (key.equals("*")) {
			interruptNames.put(interrupt, name);
		} else if (key.startsWith("AX=")) {
			functionsByAx.put(functionKey(interrupt, parseHex(key.substring(3), 4, lineNumber)), name);
		} else if (key.startsWith("AH=")) {
			functionsByAh.put(functionKey(interrupt, parseHex(key.substring(3), 2, lineNumber)), name);
		} else {
			throw new IOException("Invalid key in line " + lineNumber + ": " + line);
		}
	}
	
	private static int parseHex(String value, int digits, int lineNumber) throws IOException {
		if (value.length() != digits) {
			throw new IOException("Expected " + digits + " hex digits in line " + lineNumber + ": " + value);
		}
		try {
			return Integer.parseInt(value, 16);
		} catch (NumberFormatException e) {
			throw new IOException("Invalid hex value in line " + lineNumber + ": " + value);
		}
	}
	
	private static int functionKey(int interrupt, int function) {
		return (interrupt << 16) | function;
	}
	
	/**
	 * @return true if the interrupt is known in the table
	 */
	public boolean isKnownInterrupt(int interrupt) {
		return interruptNames.containsKey(interrupt);
	}
	
	/**
	 * @return name of the interrupt (e.g. "DPMI") or null
	 */
	public String getInterruptName(int interrupt) {
		return interruptNames.get(interrupt);
	}
	
	/**
	 * Looks up the name of a function.
	 * 
	 * @param interrupt interrupt number
	 * @param ah value of AH or -1 if unknown
	 * @param al value of AL or -1 if unknown
	 * @return name of the function or null if unknown
	 */
	public String getFunctionName(int interrupt, int ah, int al) {
		if (ah < 0) {
			return null;
		}
		if (al >= 0) {
			var byAx = functionsByAx.get(functionKey(interrupt, (ah << 8) | al));
			if (byAx != null) {
				return byAx;
			}
		}
		return functionsByAh.get(functionKey(interrupt, ah));
	}
}
