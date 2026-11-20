package yetmorecode.ghidra.lx.analyzer;

import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Annotates software interrupts (INT 10h, 21h, 2Fh, 31h, 33h, ...) with the name of the called function.
 * 
 * This is mainly useful for DOS programs with a DOS extender (DOS/4GW, DOS/32A): if the extender is
 * stripped or not loaded, a DPMI or DOS call would otherwise only be a bare "INT 31h".
 * 
 * The value of AX is determined heuristically: starting at the INT, the analyzer searches backwards
 * within the same flow (without jumps and calls) for the last assignment of a constant to AL, AH, AX
 * or EAX.
 */
public class InterruptAnnotatorAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "DOS Interrupt Annotator";
	private static final String DESCRIPTION = 
		"Adds end-of-line comments with the function name to software interrupts "
		+ "(DOS, BIOS, VESA, DPMI, mouse), e.g. 'INT 31h AX=0205 - DPMI: Set Protected Mode Interrupt Vector'.";
	
	/** Prefix of the generated comments. The analyzer recognizes its own comments by it. */
	static final String COMMENT_PREFIX = "INT ";
	
	/** Number of instructions that are searched backwards for the assignment of AX. */
	private static final int MAX_LOOKBACK = 12;
	
	private InterruptTable table;
	
	public InterruptAnnotatorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS);
		setSupportsOneTimeAnalysis();
	}

	/**
	 * Enabled by default for DOS-style executables only (MZ, NE, LE/LX). It can be enabled manually for any
	 * other x86 program.
	 */
	@Override
	public boolean getDefaultEnablement(Program program) {
		var format = program.getExecutableFormat();
		return format != null && (format.contains("DOS Executable") || format.contains("Linear Executable")
			|| format.contains("New Executable"));
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("x86");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// no options
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		if (!loadTable(log)) {
			return false;
		}
		var eax = program.getLanguage().getRegister("EAX");
		if (eax == null) {
			return false;
		}
		
		var listing = program.getListing();
		int annotated = 0;
		for (var instruction : listing.getInstructions(set, true)) {
			if (monitor.isCancelled()) {
				return false;
			}
			if (!instruction.getMnemonicString().equals("INT")) {
				continue;
			}
			var number = instruction.getScalar(0);
			if (number == null || !table.isKnownInterrupt((int) number.getUnsignedValue())) {
				continue;
			}
			var comment = createComment(instruction, (int) number.getUnsignedValue(), eax);
			var existing = listing.getComment(CommentType.EOL, instruction.getAddress());
			if (existing == null || existing.startsWith(COMMENT_PREFIX)) {
				listing.setComment(instruction.getAddress(), CommentType.EOL, comment);
				annotated++;
			}
		}
		if (annotated > 0) {
			Msg.info(this, String.format("Annotated %d software interrupts", annotated));
		}
		return true;
	}
	
	private boolean loadTable(MessageLog log) {
		if (table == null) {
			try {
				table = InterruptTable.loadDefault();
			} catch (IOException e) {
				log.appendMsg(NAME, "Could not load interrupt table: " + e.getMessage());
				return false;
			}
		}
		return true;
	}
	
	private String createComment(Instruction instruction, int interrupt, Register eax) {
		var ax = findAx(instruction, eax);
		var ah = ax[0];
		var al = ax[1];
		
		var text = new StringBuilder(String.format("INT %02Xh", interrupt));
		if (ah >= 0 && al >= 0) {
			text.append(String.format(" AX=%02X%02X", ah, al));
		} else if (ah >= 0) {
			text.append(String.format(" AH=%02X", ah));
		} else {
			text.append(" AX=?");
		}
		
		var function = table.getFunctionName(interrupt, ah, al);
		if (function != null) {
			text.append(" - ").append(function);
		} else {
			text.append(" - ").append(table.getInterruptName(interrupt)).append(": unknown function");
		}
		return text.toString();
	}
	
	/**
	 * Determines AH and AL at the time of the interrupt.
	 * 
	 * @return {AH, AL}, each -1 if it cannot be determined
	 */
	private int[] findAx(Instruction interruptInstruction, Register eax) {
		int ah = -1;
		int al = -1;
		// A part is done as soon as it was set or modified in a way that cannot be determined
		boolean ahDone = false;
		boolean alDone = false;
		
		var current = interruptInstruction;
		for (int i = 0; i < MAX_LOOKBACK && !(ahDone && alDone); i++) {
			// Another path can reach this instruction: the registers may have other values there
			if (isJumpTarget(current)) {
				break;
			}
			var previous = current.getPrevious();
			if (previous == null || previous.getFlowType().isCall() 
					|| !current.getAddress().equals(previous.getFallThrough())) {
				break;
			}
			current = previous;
			
			var written = findWrittenAxRegister(previous, eax);
			if (written == null) {
				continue;
			}
			
			// Position in the base register EAX: AL = 0, AH = 8, AX/EAX = 0
			int lowestBit = written.getLeastSignificantBitInBaseRegister();
			int highestBit = lowestBit + written.getBitLength() - 1;
			boolean touchesAl = lowestBit <= 7;
			boolean touchesAh = lowestBit <= 15 && highestBit >= 8;
			
			var value = getConstantValue(previous, written);
			if (value != null) {
				if (touchesAl && !alDone) {
					al = (int) (value & 0xff);
				}
				if (touchesAh && !ahDone) {
					ah = (int) ((value >> (lowestBit == 8 ? 0 : 8)) & 0xff);
				}
			}
			alDone |= touchesAl;
			ahDone |= touchesAh;
		}
		return new int[] { ah, al };
	}
	
	/**
	 * @return true if a jump or call from somewhere else leads to the instruction (not only the previous 
	 * instruction falling through)
	 */
	private boolean isJumpTarget(Instruction instruction) {
		var references = instruction.getProgram().getReferenceManager().getReferencesTo(instruction.getAddress());
		while (references.hasNext()) {
			var type = references.next().getReferenceType();
			if (type.isFlow() && !type.isFallthrough()) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * @return the register of EAX/AX/AH/AL that the instruction writes, or null
	 */
	private Register findWrittenAxRegister(Instruction instruction, Register eax) {
		for (var result : instruction.getResultObjects()) {
			if (result instanceof Register register && eax.equals(register.getBaseRegister())) {
				return register;
			}
		}
		return null;
	}
	
	/**
	 * @return the constant the instruction writes to the register (MOV reg,imm / XOR reg,reg), otherwise null
	 */
	private Long getConstantValue(Instruction instruction, Register written) {
		var mnemonic = instruction.getMnemonicString();
		if (instruction.getNumOperands() != 2 || !written.equals(instruction.getRegister(0))) {
			return null;
		}
		if (mnemonic.equals("MOV")) {
			var operands = instruction.getOpObjects(1);
			if (operands.length == 1 && operands[0] instanceof Scalar scalar) {
				return scalar.getUnsignedValue();
			}
		} else if (mnemonic.equals("XOR") || mnemonic.equals("SUB")) {
			if (written.equals(instruction.getRegister(1))) {
				return 0L;
			}
		}
		return null;
	}
}
