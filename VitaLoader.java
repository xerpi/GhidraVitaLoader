// Vita loader script that resolves NIDs
// @author Sergi Granell
// @category Vita
// @keybinding
// @menupath
// @toolbar

/*
 * NOTE: This script depends on the yamlbeans library.
 * Download the JAR from https://github.com/EsotericSoftware/yamlbeans/releases
 * and add the path to Ghidra's "Edit" -> "Plugin Path..." configuration.
 */

package GhidraVitaLoader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.esotericsoftware.yamlbeans.YamlReader;

import docking.widgets.filechooser.GhidraFileChooser;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class VitaLoader extends GhidraScript {
	private final short ET_SCE_RELEXEC = (short)0xFE04;
	
	public class SceModuleInfo implements StructConverter {
		public short attributes;
		public short version;
		public String name;
		public byte type;
		public long gp_value;
		public long export_top;
		public long export_end;
		public long import_top;
		public long import_end;
		public long module_nid;
		public int field_38;
		public int field_3C;
		public int field_40;
		public long module_start;
		public long module_stop;
		public long exidx_top;
		public long exidx_end;
		public long extab_top;
		public long extab_end;
		public static final int SIZE = 0x5c;
		
		SceModuleInfo(BinaryReader reader) throws IOException {
			attributes = reader.readNextShort();
			version = reader.readNextShort();
			name = reader.readNextAsciiString(27);
			type = reader.readNextByte();
			gp_value = reader.readNextUnsignedInt();
			export_top = reader.readNextUnsignedInt();
			export_end = reader.readNextUnsignedInt();
			import_top = reader.readNextUnsignedInt();
			import_end = reader.readNextUnsignedInt();
			module_nid = reader.readNextUnsignedInt();
			field_38 = reader.readNextInt();
			field_3C = reader.readNextInt();
			field_40 = reader.readNextInt();
			module_start = reader.readNextUnsignedInt();
			module_stop = reader.readNextUnsignedInt();
			exidx_top = reader.readNextUnsignedInt();
			exidx_end = reader.readNextUnsignedInt();
			extab_top = reader.readNextUnsignedInt();
			extab_end = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}
	
	public class SceModuleExports implements StructConverter {
		public short size;
		public short version;
		public short flags;
		public short num_syms_funcs;
		public short num_syms_vars;
		public short num_syms_unk;
		public int unk_1;
		public long library_nid;
		public long library_name;
		public long nid_table;
		public long entry_table;
		public static final int SIZE = 0x20;
		
		SceModuleExports(BinaryReader reader) throws IOException {
			size = reader.readNextShort();
			version = reader.readNextShort();
			flags = reader.readNextShort();
			num_syms_funcs = reader.readNextShort();
			num_syms_vars = reader.readNextShort();
			num_syms_unk = reader.readNextShort();
			unk_1 = reader.readNextInt();
			library_nid = reader.readNextUnsignedInt();
			library_name = reader.readNextUnsignedInt();
			nid_table = reader.readNextUnsignedInt();
			entry_table = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}
	
	public class SceModuleImports implements StructConverter {
		public short size;
		public short version;
		public short flags;
		public short num_syms_funcs;
		public short num_syms_vars;
		public short num_syms_unk;
		public int reserved1;
		public long library_nid;
		public long library_name;
		public int reserved2;
		public long func_nid_table;
		public long func_entry_table;
		public long var_nid_table;
		public long var_entry_table;
		public long unk_nid_table;
		public long unk_entry_table;
		public static final int SIZE = 0x34;
		
		SceModuleImports(BinaryReader reader) throws IOException {
			size = reader.readNextShort();
			version = reader.readNextShort();
			flags = reader.readNextShort();
			num_syms_funcs = reader.readNextShort();
			num_syms_vars = reader.readNextShort();
			num_syms_unk = reader.readNextShort();
			reserved1 = reader.readNextInt();
			library_nid = reader.readNextUnsignedInt();
			library_name = reader.readNextUnsignedInt();
			reserved2 = reader.readNextInt();
			func_nid_table = reader.readNextUnsignedInt();
			func_entry_table = reader.readNextUnsignedInt();
			var_nid_table = reader.readNextUnsignedInt();
			var_entry_table = reader.readNextUnsignedInt();
			unk_nid_table = reader.readNextUnsignedInt();
			unk_entry_table = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}
	
	public static class NidDb {
		public static class NidDbLibrary {
			public HashMap<Long, String> functions;
	
			public NidDbLibrary() {
				functions = new HashMap<Long, String>();
			}
			
			public boolean functionExists(long functionNid) {
				return functions.containsKey(functionNid);
			}
			
			public void insertFunction(long functionNid, String name) {
				functions.put(functionNid, name);
			}
			
			public String getFunctionName(long functionNid) {
				return functions.get(functionNid);
			}
		}

		public HashMap<Long, NidDbLibrary> libraries;
		
		public NidDb() {
			libraries = new HashMap<Long, NidDbLibrary>();
		}
		
		public boolean libraryExists(long nid) {
			return libraries.containsKey(nid);
		}
		
		public void insertLibrary(long libraryNid, NidDbLibrary library) {
			libraries.put(libraryNid, library);
		}
		
		public NidDbLibrary getLibrary(long libraryNid) {
			return libraries.get(libraryNid);
		}
		
		public String getFunctionName(long libraryNid, long functionNid) {
			NidDbLibrary library = getLibrary(libraryNid);
			if (library == null)
				return null;
			return library.getFunctionName(functionNid);
		}	
	}

	public static class NidDbLibraryRaw {
		public Long nid;
		public Boolean kernel;
		public Map<String, Long> functions;
	}

	public static class NidDbModuleRaw {
		public Long nid;
		public Map<String, NidDbLibraryRaw> libraries;
	}
	
	public static class NidDbRaw {
		public int version;
		public String firmware;
		public Map<String, NidDbModuleRaw> modules;
	}
	
	public void populateNidDbFromRaw(NidDb db, NidDbRaw raw) {
		for (Map.Entry<String, NidDbModuleRaw> moduleIt: raw.modules.entrySet()) {
			NidDbModuleRaw moduleRaw = moduleIt.getValue();
			for (Map.Entry<String, NidDbLibraryRaw> libraryIt: moduleRaw.libraries.entrySet()) {
				NidDbLibraryRaw libraryRaw = libraryIt.getValue();
				NidDb.NidDbLibrary library = new NidDb.NidDbLibrary();
				
				for (Map.Entry<String, Long> functionIt: libraryRaw.functions.entrySet())
					library.insertFunction(functionIt.getValue(), functionIt.getKey());

				db.insertLibrary(libraryRaw.nid, library);
			}
		}
	}
			
	private ElfHeader getElfHeader(Memory memory) throws MemoryAccessException, ElfException {
		MemoryBlock elfHeaderMemoryBlock = memory.getBlock("_elfHeader");
		
		int elfHeaderSize = (int)elfHeaderMemoryBlock.getSize();
		Address elfHeaderStart = elfHeaderMemoryBlock.getStart();
		byte[] elfHeaderBytes = new byte[elfHeaderSize];
		
		elfHeaderMemoryBlock.getBytes(elfHeaderStart, elfHeaderBytes);
		
		ByteArrayProvider elfHeaderProvider = new ByteArrayProvider(elfHeaderBytes);
		return ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, elfHeaderProvider);
	}

	private MemoryBlock getExecutableMemoryBlock(Memory memory) {
		for (MemoryBlock block : memory.getBlocks()) {
			if ((block.getPermissions() & MemoryBlock.EXECUTE) != 0)
				return block;
		}
		return null;
	}
	
	private static void functionApplyFunctionSignature(Program program, Function function, FunctionDefinition functionDef) throws InvalidInputException, DuplicateNameException {
		/* Build function parameters */
		List<ParameterImpl> paramImpls = new ArrayList<ParameterImpl>();
		for (ParameterDefinition def: functionDef.getArguments()) {
			ParameterImpl pimpl = new ParameterImpl(def.getName(), def.getDataType().clone(program.getDataTypeManager()), program);
			paramImpls.add(new ParameterImpl(pimpl, program));
		}
		
		/* Build return type */
		ReturnParameterImpl returnParam = new ReturnParameterImpl(functionDef.getReturnType(), program);

		/* Apply function signature */
		function.updateFunction(null, returnParam, paramImpls,
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.DEFAULT);	
	}
	
	private static void applySceModuleInfoStruct(GhidraScript script, Address moduleInfoAddress, String moduleName) throws Exception {
		StructureDataType sceModuleInfoDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceModuleInfo", 0);
		sceModuleInfoDataType.add(StructConverter.WORD, "attributes", null);
		sceModuleInfoDataType.add(StructConverter.WORD, "version", null);
		sceModuleInfoDataType.add(StructConverter.STRING, 27, "name", null);
		sceModuleInfoDataType.add(StructConverter.BYTE, "type", null);
		sceModuleInfoDataType.add(Pointer32DataType.dataType, "gp_value", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "export_top", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "export_end", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "import_top", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "import_end", null);
		sceModuleInfoDataType.add(StructConverter.DWORD, "module_nid", null);
		sceModuleInfoDataType.add(StructConverter.DWORD, "field_38", null);
		sceModuleInfoDataType.add(StructConverter.DWORD, "field_3C", null);
		sceModuleInfoDataType.add(StructConverter.DWORD, "field_40", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "module_start", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "module_stop", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "exidx_top", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "exidx_end", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "extab_top", null);
		sceModuleInfoDataType.add(StructConverter.IBO32, "extab_end", null);
		
		script.clearListing(moduleInfoAddress, moduleInfoAddress.add(sceModuleInfoDataType.getLength()));
		script.createData(moduleInfoAddress, sceModuleInfoDataType);
		script.createLabel(moduleInfoAddress, moduleName + "_" + sceModuleInfoDataType.getName(), true);
	}
	
	private static void applySceModuleExportsStruct(GhidraScript script,  String moduleName, Address moduleExportsAddress, String exportsName) throws Exception {
		StructureDataType sceModuleExportsDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceModuleExports", 0);
		sceModuleExportsDataType.add(StructConverter.WORD, "size", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "version", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "flags", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "num_syms_funcs", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "num_syms_vars", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "unk_1", null);
		sceModuleExportsDataType.add(StructConverter.DWORD, "unk_2", null);
		sceModuleExportsDataType.add(StructConverter.DWORD, "library_nid", null);
		sceModuleExportsDataType.add(Pointer32DataType.dataType, "library_name", null);
		sceModuleExportsDataType.add(Pointer32DataType.dataType, "nid_table", null);
		sceModuleExportsDataType.add(Pointer32DataType.dataType, "entry_table", null);

		script.clearListing(moduleExportsAddress, moduleExportsAddress.add(sceModuleExportsDataType.getLength()));
		script.createData(moduleExportsAddress, sceModuleExportsDataType);
		script.createLabel(moduleExportsAddress, moduleName + "_exports_" + exportsName + "_" + sceModuleExportsDataType.getName(), true);
	}
	
	private static void applySceModuleImportsStruct(GhidraScript script,  String moduleName, Address moduleImportsAddress, String ImportsName) throws Exception {
		StructureDataType sceModuleImportsDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceModuleImports", 0);
		sceModuleImportsDataType.add(StructConverter.WORD, "size", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "version", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "flags", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_syms_funcs", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_syms_vars", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_syms_unk", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "reserved_1", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "library_nid", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "library_name", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "reserved_2", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "func_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "func_entry_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "var_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "var_entry_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "unk_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "unk_entry_table", null);

		script.clearListing(moduleImportsAddress, moduleImportsAddress.add(sceModuleImportsDataType.getLength()));
		script.createData(moduleImportsAddress, sceModuleImportsDataType);
		script.createLabel(moduleImportsAddress, moduleName + "_imports_" + ImportsName + "_" + sceModuleImportsDataType.getName(), true);
	}
	
	private static void processFunction(GhidraScript script, Program program, NidDb db, String libraryName, long libraryNid, long functionNid, long functionEntry, MemoryBlock block) throws DuplicateNameException, InvalidInputException {
		String functionName = db.getFunctionName(libraryNid, functionNid);
		if (functionName == null)
			functionName = libraryName + "_" + String.format("%08X", functionNid);

		//script.println("  " + String.format("0x%08X", functionNid) + ", " + functionName +
		//		", addr: " + String.format("0x%08X", functionEntry));
		
		Address functionEntryAddress = block.getStart().getNewAddress(functionEntry);
		Function function = script.getFunctionAt(functionEntryAddress);
		if (function == null)
			function = script.createFunction(functionEntryAddress, functionName);
		else
			function.setName(functionName, SourceType.IMPORTED);
		
		/* Set function signature */
		List<DataType> dataTypeList = new ArrayList<DataType>();
		program.getDataTypeManager().findDataTypes(functionName, dataTypeList);
		for (DataType dt: dataTypeList) {
			if (!(dt instanceof FunctionDefinition))
				continue;
			FunctionDefinition fdef = (FunctionDefinition)dt;
			functionApplyFunctionSignature(program, function, fdef);
		}	
	}
	
	private void processExports(Program program, NidDb db, Memory memory, MemoryBlock block, String moduleName, Address exportsAddress, SceModuleExports exports) throws Exception {
		//println("Exports NID: " + String.format("0x%08X", exports.library_nid));
		//println("Exports num funcs: " + String.format("0x%08X", exports.num_syms_funcs));
		//println("Exports nid table: " + String.format("0x%08X", exports.nid_table));
		//println("Exports size: " + String.format("0x%08X", exports.size));
		
		Address funcNidTableAddress = block.getStart().getNewAddress(exports.nid_table);
		Address funcEntryTableAddress = block.getStart().getNewAddress(exports.entry_table);
		Address libraryNameAddress = block.getStart().getNewAddress(exports.library_name);
		
		ByteProvider libraryNameByteProvider = new MemoryByteProvider(memory, libraryNameAddress);
		BinaryReader libraryNameBinaryReader = new BinaryReader(libraryNameByteProvider, true);
		String libraryName = libraryNameBinaryReader.readNextAsciiString();
		
		byte[] funcNidTableBytes = new byte[4 * exports.num_syms_funcs];
		byte[] funcEntryTableBytes = new byte[4 * exports.num_syms_funcs];
		
		block.getBytes(funcNidTableAddress, funcNidTableBytes, 0, funcNidTableBytes.length);
		block.getBytes(funcEntryTableAddress, funcEntryTableBytes, 0, funcEntryTableBytes.length);
		IntBuffer funcNidTableIntBuffer = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer funcEntryTableIntBuffer = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		
		//println("Exports library name: " + libraryName);
		
		for (int i = 0; i < exports.num_syms_funcs; i++) {
			long functionNid =  Integer.toUnsignedLong(funcNidTableIntBuffer.get(i));
			long functionEntry =  Integer.toUnsignedLong(funcEntryTableIntBuffer.get(i))  & ~1l;
			
			processFunction(this, program, db, libraryName, exports.library_nid, functionNid, functionEntry, block);
		}
		
		applySceModuleExportsStruct(this, moduleName, exportsAddress, libraryName);
		
		if (exports.num_syms_funcs > 0) {
			createDwords(funcNidTableAddress, exports.num_syms_funcs);
			createLabel(funcNidTableAddress, moduleName + "_exports_" + libraryName + "_NID_table", true);
			createLabel(funcEntryTableAddress, moduleName + "_exports_" + libraryName + "_entry_table", true);
		}
	}
	
	private void processImports(Program program, NidDb db, Memory memory, MemoryBlock block, String moduleName, Address importsAddress, SceModuleImports imports) throws Exception {
		//println("Imports NID: " + String.format("0x%08X", imports.library_nid));
		//println("Imports num funcs: " + String.format("0x%08X", imports.num_syms_funcs));
		//println("Imports nid table: " + String.format("0x%08X", imports.func_nid_table));
		//println("Imports size: " + String.format("0x%08X", imports.size));
		
		Address funcNidTableAddress = block.getStart().getNewAddress(imports.func_nid_table);
		Address funcEntryTableAddress = block.getStart().getNewAddress(imports.func_entry_table);
		Address libraryNameAddress = block.getStart().getNewAddress(imports.library_name);
		
		ByteProvider libraryNameByteProvider = new MemoryByteProvider(memory, libraryNameAddress);
		BinaryReader libraryNameBinaryReader = new BinaryReader(libraryNameByteProvider, true);
		String libraryName = libraryNameBinaryReader.readNextAsciiString();
		
		byte[] funcNidTableBytes = new byte[4 * imports.num_syms_funcs];
		byte[] funcEntryTableBytes = new byte[4 * imports.num_syms_funcs];
		
		block.getBytes(funcNidTableAddress, funcNidTableBytes, 0, funcNidTableBytes.length);
		block.getBytes(funcEntryTableAddress, funcEntryTableBytes, 0, funcEntryTableBytes.length);
		IntBuffer funcNidTableIntBuffer = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer funcEntryTableIntBuffer = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		
		//println("Imports library name: " + libraryName);
		
		for (int i = 0; i < imports.num_syms_funcs; i++) {
			long functionNid =  Integer.toUnsignedLong(funcNidTableIntBuffer.get(i));
			long functionEntry =  Integer.toUnsignedLong(funcEntryTableIntBuffer.get(i)) & ~1l;
			
			processFunction(this, program, db, libraryName, imports.library_nid, functionNid, functionEntry, block);
		}
		
		applySceModuleImportsStruct(this, moduleName, importsAddress, libraryName);
		
		if (imports.num_syms_funcs > 0) {
			createDwords(funcNidTableAddress, imports.num_syms_funcs);
			createLabel(funcNidTableAddress, moduleName + "_imports_" + libraryName + "_NID_table", true);
			createLabel(funcEntryTableAddress, moduleName + "_imports_" + libraryName + "_entry_table", true);
		}
	}
	
	private void processModuleInfo(Program program, NidDb db, Memory memory, MemoryBlock block, Address moduleInfoAddress) throws Exception {
		/* Get module info bytes */
		byte[] moduleInfoBytes = new byte[SceModuleInfo.SIZE];
		block.getBytes(moduleInfoAddress, moduleInfoBytes, 0, moduleInfoBytes.length);
		
		/* Read module info information */
		ByteProvider provider = new ByteArrayProvider(moduleInfoBytes);
		BinaryReader reader = new BinaryReader(provider, true);
		SceModuleInfo moduleInfo = new SceModuleInfo(reader);
		
		println("Vita module name: " + moduleInfo.name);
		
		applySceModuleInfoStruct(this, moduleInfoAddress, moduleInfo.name);
		
		Address exportsTop = block.getStart().add(moduleInfo.export_top);
		Address exportsEnd = block.getStart().add(moduleInfo.export_end);
		while (!exportsTop.equals(exportsEnd)) {
			byte[] exportsBytes = new byte[SceModuleExports.SIZE];
			block.getBytes(exportsTop, exportsBytes, 0, exportsBytes.length);
			
			ByteProvider exportsByteProvider = new ByteArrayProvider(exportsBytes);
			BinaryReader exportsBinaryReader = new BinaryReader(exportsByteProvider, true);
			SceModuleExports moduleExports = new SceModuleExports(exportsBinaryReader);
			if (moduleExports.size != SceModuleExports.SIZE) {
				println("Exports size mismatch");
				break;
			}
			
			processExports(program, db, memory, block, moduleInfo.name, exportsTop, moduleExports);
			
			exportsTop = exportsTop.add(moduleExports.size);
		}
		
		Address importsTop = block.getStart().add(moduleInfo.import_top);
		Address importsEnd = block.getStart().add(moduleInfo.import_end);
		while (!importsTop.equals(importsEnd)) {
			byte[] importsBytes = new byte[SceModuleImports.SIZE];
			block.getBytes(importsTop, importsBytes, 0, importsBytes.length);
			
			ByteProvider importsByteProvider = new ByteArrayProvider(importsBytes);
			BinaryReader importsBinaryReader = new BinaryReader(importsByteProvider, true);
			SceModuleImports moduleImports = new SceModuleImports(importsBinaryReader);
			if (moduleImports.size != SceModuleImports.SIZE) {
				println("Imports size mismatch");
				break;
			}
			
			processImports(program, db, memory, block, moduleInfo.name, importsTop, moduleImports);
			
			importsTop = importsTop.add(moduleImports.size);
		}
	}
	
	@Override
	public void run() throws Exception {
		println("VitaLoader by xerpi");
		
		if (!ElfLoader.ELF_NAME.equals(currentProgram.getExecutableFormat())) {
			Msg.showError(this, null, "VitaLoader",
					"Current program is not an ELF program!  (" + currentProgram.getExecutableFormat() + ")");
			return;
		}
		
		Memory memory = currentProgram.getMemory();
		ElfHeader elfHeader = getElfHeader(memory);
		if (elfHeader.e_type() != ET_SCE_RELEXEC) {
			Msg.showError(this, null, "VitaLoader",
					"Current program is not an PSVita ELF program!  (" + String.format("0x%04X", elfHeader.e_type()) + ")");
			return;
		}
		
		/* NID database choose dialog */
		GhidraFileChooser fileChooser = new GhidraFileChooser(null);
		String lastDir = Preferences.getProperty(Preferences.LAST_IMPORT_DIRECTORY);
		if (lastDir != null)
			fileChooser.setCurrentDirectory(new File(lastDir));
		fileChooser.setTitle("Choose NID database YML");
		fileChooser.setApproveButtonText("Choose NID database file");
		fileChooser.rescanCurrentDirectory();
		
		File selectedFile = fileChooser.getSelectedFile();
		if (selectedFile == null) {
			Msg.showError(this, null, "VitaLoader", "A NID database is needed!");
			return;
		}

		/* Load NID database */
		YamlReader yamlReader = new YamlReader(new FileReader(selectedFile));
		NidDbRaw dbRaw = yamlReader.read(NidDbRaw.class);
		NidDb db = new NidDb();
		populateNidDbFromRaw(db, dbRaw);
		
		/* Get module info address */
		MemoryBlock textMemoryBlock = getExecutableMemoryBlock(memory);
		Address moduleInfoAddress = textMemoryBlock.getStart().add(elfHeader.e_entry());
		
		processModuleInfo(getCurrentProgram(), db, memory, textMemoryBlock, moduleInfoAddress);
	}
}
