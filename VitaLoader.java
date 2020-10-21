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

/* TODOs:
 *   - Support variable imports/exports
 */

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
import ghidra.program.model.data.StringDataType;
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
	private final short ET_SCE_EXEC = (short)0xFE00;

	static final Map<Integer, String> noname_function_exports = Map.of(
		0x935CD196, "module_start", 
		0x79F8E492, "module_stop",
		0x913482A9, "module_exit",
		0x5C424D40, "module_bootstart"
	);

	static final Map<Integer, String> noname_variable_exports = Map.of(
		0x936C8A78, "module_sdk_version",
		0x70FBA1E7, "SceProcessParam",
		0x6C2224BA, ""
	);

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
		public long tls_start;
		public long tls_filesz;
		public long tls_memsz;
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
			tls_start = reader.readNextUnsignedInt();
			tls_filesz = reader.readNextUnsignedInt();
			tls_memsz = reader.readNextUnsignedInt();
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

	public static class SceProcessParam implements StructConverter {
		public long size;
		public long magic;
		public long version;
		public long fw_version;
		public long main_thread_name;
		public long main_thread_priority;
		public long main_thread_stacksize;
		public long main_thread_attribute;
		public long process_name;
		public long process_preload_disabled;
		public long main_thread_cpu_affinity_mask;
		public long sce_libc_param;
		public long unk;
		public static final int SIZE = 0x34;

		SceProcessParam(BinaryReader reader) throws IOException {
			size = reader.readNextUnsignedInt();
			magic = reader.readNextUnsignedInt();
			version = reader.readNextUnsignedInt();
			fw_version = reader.readNextUnsignedInt();
			main_thread_name = reader.readNextUnsignedInt();
			main_thread_priority = reader.readNextUnsignedInt();
			main_thread_stacksize = reader.readNextUnsignedInt();
			main_thread_attribute = reader.readNextUnsignedInt();
			process_name = reader.readNextUnsignedInt();
			process_preload_disabled = reader.readNextUnsignedInt();
			main_thread_cpu_affinity_mask = reader.readNextUnsignedInt();
			sce_libc_param = reader.readNextUnsignedInt();
			unk = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}

	public class SceModuleExports implements StructConverter {
		public short size;
		public short version;
		public short attribute;
		public short num_functions;
		public short num_vars;
		public short num_tls_vars;
		public int unknown1;
		public long library_nid;
		public long library_name;
		public long nid_table;
		public long entry_table;
		public static final int SIZE = 0x20;

		SceModuleExports(BinaryReader reader) throws IOException {
			size = reader.readNextShort();
			version = reader.readNextShort();
			attribute = reader.readNextShort();
			num_functions = reader.readNextShort();
			num_vars = reader.readNextShort();
			num_tls_vars = reader.readNextShort();
			unknown1 = reader.readNextInt();
			library_nid = reader.readNextUnsignedInt();
			library_name = reader.readNextUnsignedInt();
			nid_table = reader.readNextUnsignedInt();
			entry_table = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}

	public class SceModuleImports_1x implements StructConverter {
		public short size;
		public short version;
		public short attribute;
		public short num_functions;
		public short num_vars;
		public short num_syms_tls_vars;
		public int reserved1;
		public long library_nid;
		public long library_name;
		public int reserved2;
		public long func_nid_table;
		public long func_entry_table;
		public long var_nid_table;
		public long var_entry_table;
		public long tls_nid_table;
		public long tls_entry_table;
		public static final int SIZE = 0x34;

		SceModuleImports_1x(BinaryReader reader) throws IOException {
			size = reader.readNextShort();
			version = reader.readNextShort();
			attribute = reader.readNextShort();
			num_functions = reader.readNextShort();
			num_vars = reader.readNextShort();
			num_syms_tls_vars = reader.readNextShort();
			reserved1 = reader.readNextInt();
			library_nid = reader.readNextUnsignedInt();
			library_name = reader.readNextUnsignedInt();
			reserved2 = reader.readNextInt();
			func_nid_table = reader.readNextUnsignedInt();
			func_entry_table = reader.readNextUnsignedInt();
			var_nid_table = reader.readNextUnsignedInt();
			var_entry_table = reader.readNextUnsignedInt();
			tls_nid_table = reader.readNextUnsignedInt();
			tls_entry_table = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}

	public class SceModuleImports_3x implements StructConverter {
		public short size;
		public short version;
		public short attribute;
		public short num_functions;
		public short num_vars;
		public short unknown1;
		public long library_nid;
		public long library_name;
		public long func_nid_table;
		public long func_entry_table;
		public long var_nid_table;
		public long var_entry_table;
		public static final int SIZE = 0x24;

		SceModuleImports_3x(BinaryReader reader) throws IOException {
			size = reader.readNextShort();
			version = reader.readNextShort();
			attribute = reader.readNextShort();
			num_functions = reader.readNextShort();
			num_vars = reader.readNextShort();
			unknown1 = reader.readNextShort();
			library_nid = reader.readNextUnsignedInt();
			library_name = reader.readNextUnsignedInt();
			func_nid_table = reader.readNextUnsignedInt();
			func_entry_table = reader.readNextUnsignedInt();
			var_nid_table = reader.readNextUnsignedInt();
			var_entry_table = reader.readNextUnsignedInt();
		}

		public DataType toDataType() throws DuplicateNameException, IOException {
			return StructConverterUtil.toDataType(this);
		}
	}

	public static class NidDatabase {
		public static class NidDatabaseLibrary {
			public HashMap<Long, String> functions;
			public HashMap<Long, String> variables;

			public NidDatabaseLibrary() {
				functions = new HashMap<Long, String>();
				variables = new HashMap<Long, String>();
			}

			public boolean functionExists(long functionNid) {
				return functions.containsKey(functionNid);
			}

			public boolean variableExists(long variableNid) {
				return variables.containsKey(variableNid);
			}

			public void insertFunction(long functionNid, String name) {
				functions.put(functionNid, name);
			}

			public void insertVariable(long variableNid, String name) {
				variables.put(variableNid, name);
			}

			public String getFunctionName(long functionNid) {
				return functions.get(functionNid);
			}

			public String getVariableName(long variableNid) {
				return variables.get(variableNid);
			}
		}

		public HashMap<Long, NidDatabaseLibrary> libraries;

		public NidDatabase() {
			libraries = new HashMap<Long, NidDatabaseLibrary>();
		}

		public boolean libraryExists(long nid) {
			return libraries.containsKey(nid);
		}

		public void insertLibrary(long libraryNid, NidDatabaseLibrary library) {
			libraries.put(libraryNid, library);
		}

		public NidDatabaseLibrary getLibrary(long libraryNid) {
			return libraries.get(libraryNid);
		}

		public String getFunctionName(long libraryNid, long functionNid) {
			NidDatabaseLibrary library = getLibrary(libraryNid);
			if (library == null)
				return null;
			return library.getFunctionName(functionNid);
		}

		public String getVariableName(long libraryNid, long variableNid) {
			NidDatabaseLibrary library = getLibrary(libraryNid);
			if (library == null)
				return null;
			return library.getVariableName(variableNid);
		}
	}

	public static class YamlNidDatabaseLibrary {
		public Long nid;
		public Boolean kernel;
		public Map<String, Long> functions;
		public Map<String, Long> variables;
	}

	public static class YamlNidDatabaseModule {
		public Long nid;
		public Map<String, YamlNidDatabaseLibrary> libraries;
	}

	public static class YamlNidDatabase {
		public int version;
		public String firmware;
		public Map<String, YamlNidDatabaseModule> modules;
	}

	public void populateNidDatabaseFromYaml(NidDatabase db, YamlNidDatabase raw) {
		for (Map.Entry<String, YamlNidDatabaseModule> moduleIt: raw.modules.entrySet()) {
			YamlNidDatabaseModule moduleRaw = moduleIt.getValue();
			for (Map.Entry<String, YamlNidDatabaseLibrary> libraryIt: moduleRaw.libraries.entrySet()) {
				YamlNidDatabaseLibrary libraryRaw = libraryIt.getValue();
				NidDatabase.NidDatabaseLibrary library = new NidDatabase.NidDatabaseLibrary();

				for (Map.Entry<String, Long> functionIt: libraryRaw.functions.entrySet())
					library.insertFunction(functionIt.getValue(), functionIt.getKey());

				if (libraryRaw.variables != null)
					for (Map.Entry<String, Long> variableIt: libraryRaw.variables.entrySet())
						library.insertVariable(variableIt.getValue(), variableIt.getKey());

				db.insertLibrary(libraryRaw.nid, library);
			}
		}
	}

	private ElfHeader getElfHeader(Memory memory) throws MemoryAccessException, ElfException {
		MemoryBlock elfHeaderMemoryBlock = memory.getBlock("_elfHeader");

		int elfHeaderSize = (int) elfHeaderMemoryBlock.getSize();
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
		sceModuleInfoDataType.add(StructConverter.IBO32, "tls_start", null);
		sceModuleInfoDataType.add(StructConverter.DWORD, "tls_filesz", null);
		sceModuleInfoDataType.add(StructConverter.DWORD, "tls_memsz", null);
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
		sceModuleExportsDataType.add(StructConverter.WORD, "attribute", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "num_functions", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "num_vars", null);
		sceModuleExportsDataType.add(StructConverter.WORD, "num_tls_vars", null);
		sceModuleExportsDataType.add(StructConverter.DWORD, "unknown1", null);
		sceModuleExportsDataType.add(StructConverter.DWORD, "library_nid", null);
		sceModuleExportsDataType.add(Pointer32DataType.dataType, "library_name", null);
		sceModuleExportsDataType.add(Pointer32DataType.dataType, "nid_table", null);
		sceModuleExportsDataType.add(Pointer32DataType.dataType, "entry_table", null);

		script.clearListing(moduleExportsAddress, moduleExportsAddress.add(sceModuleExportsDataType.getLength()));
		script.createData(moduleExportsAddress, sceModuleExportsDataType);
		script.createLabel(moduleExportsAddress, moduleName + "_exports_" + exportsName + (exportsName.equals("") ? "" : "_") + sceModuleExportsDataType.getName(), true);
	}

	private static void applySceModuleImportsStruct_1x(GhidraScript script,  String moduleName, Address moduleImportsAddress, String ImportsName) throws Exception {
		StructureDataType sceModuleImportsDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceModuleImports_1x", 0);
		sceModuleImportsDataType.add(StructConverter.WORD, "size", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "version", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "attribute", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_functions", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_vars", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_tls_vars", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "reserved1", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "library_nid", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "library_name", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "reserved2", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "func_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "func_entry_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "var_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "var_entry_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "tls_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "tls_entry_table", null);

		script.clearListing(moduleImportsAddress, moduleImportsAddress.add(sceModuleImportsDataType.getLength()));
		script.createData(moduleImportsAddress, sceModuleImportsDataType);
		script.createLabel(moduleImportsAddress, moduleName + "_imports_" + ImportsName + "_" + sceModuleImportsDataType.getName(), true);
	}

	private static void applySceModuleImportsStruct_3x(GhidraScript script,  String moduleName, Address moduleImportsAddress, String ImportsName) throws Exception {
		StructureDataType sceModuleImportsDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceModuleImports_3x", 0);
		sceModuleImportsDataType.add(StructConverter.WORD, "size", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "version", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "attribute", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_functions", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "num_vars", null);
		sceModuleImportsDataType.add(StructConverter.WORD, "unknown1", null);
		sceModuleImportsDataType.add(StructConverter.DWORD, "library_nid", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "library_name", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "func_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "func_entry_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "var_nid_table", null);
		sceModuleImportsDataType.add(Pointer32DataType.dataType, "var_entry_table", null);

		script.clearListing(moduleImportsAddress, moduleImportsAddress.add(sceModuleImportsDataType.getLength()));
		script.createData(moduleImportsAddress, sceModuleImportsDataType);
		script.createLabel(moduleImportsAddress, moduleName + "_imports_" + ImportsName + "_" + sceModuleImportsDataType.getName(), true);
	}

	private static void applySceLibcParamStruct_1x(GhidraScript script, Address libcParamAdress, String moduleName) throws Exception, IOException, MemoryAccessException {
		StructureDataType sceLibcParamDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceLibcParam", 0);
		sceLibcParamDataType.add(StructConverter.DWORD, "size", null);
		sceLibcParamDataType.add(StructConverter.DWORD, 4, "unk_0x4", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "heap_size", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "heap_size_default", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "heap_extended_alloc", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "heap_delayed_alloc", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "unk_0x18", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "unk_0x1C", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "malloc_replace", null);		
		sceLibcParamDataType.add(StructConverter.DWORD, "free_replace", null);

		script.clearListing(libcParamAdress, libcParamAdress.add(sceLibcParamDataType.getLength()));
		script.createData(libcParamAdress, sceLibcParamDataType);
		script.createLabel(libcParamAdress, moduleName + "_" + sceLibcParamDataType.getName(), true);
	}

	private static void applySceLibcParamStruct_2x(GhidraScript script, Address libcParamAdress, String moduleName) throws Exception, IOException, MemoryAccessException {
		StructureDataType sceLibcParamDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceLibcParam", 0);
		sceLibcParamDataType.add(StructConverter.DWORD, "size", null);
		sceLibcParamDataType.add(StringDataType.dataType, 4, "unk_0x4", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "heap_size", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "heap_size_default", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "unk_0x10", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "unk_0x14", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "fw_version", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "unk_0x1C", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "malloc_replace", null);		
		sceLibcParamDataType.add(Pointer32DataType.dataType, "new_replace", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "unk_0x28", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "unk_0x2C", null);
		sceLibcParamDataType.add(StructConverter.DWORD, "unk_0x30", null);
		sceLibcParamDataType.add(Pointer32DataType.dataType, "malloc_for_tls_replace", null);

		script.clearListing(libcParamAdress, libcParamAdress.add(sceLibcParamDataType.getLength()));
		script.createData(libcParamAdress, sceLibcParamDataType);
		script.createLabel(libcParamAdress, moduleName + "_" + sceLibcParamDataType.getName(), true);
	}

	private static void applySceProcessParamStruct(GhidraScript script, Address processParamAddress, String moduleName, MemoryBlock block) throws Exception, IOException, MemoryAccessException {
		MemoryBlock dataBlock = script.getMemoryBlock(processParamAddress);
		
		/* Get process param bytes */
		byte[] processParamBytes = new byte[SceProcessParam.SIZE];
		dataBlock.getBytes(processParamAddress, processParamBytes, 0, processParamBytes.length);

		/* Read process param information */
		ByteProvider provider = new ByteArrayProvider(processParamBytes);
		BinaryReader reader = new BinaryReader(provider, true);
		SceProcessParam processParam = new SceProcessParam(reader);		

		StructureDataType sceProcessParamDataType = new StructureDataType(new CategoryPath("/VitaLoader"), "SceProcessParam", 0);
		sceProcessParamDataType.add(StructConverter.DWORD, "size", null);
		sceProcessParamDataType.add(StringDataType.dataType, 4, "magic", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "version", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "fw_version", null);
		sceProcessParamDataType.add(Pointer32DataType.dataType, "main_thread_name", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "main_thread_priority", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "main_thread_stacksize", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "main_thread_attribute", null);
		sceProcessParamDataType.add(Pointer32DataType.dataType, "process_name", null);		
		sceProcessParamDataType.add(StructConverter.DWORD, "process_preload_disabled", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "main_thread_cpu_affinity_mask", null);
		sceProcessParamDataType.add(Pointer32DataType.dataType, "sce_libc_param", null);
		sceProcessParamDataType.add(StructConverter.DWORD, "unk", null);

		if ((int) processParam.main_thread_name != 0)
			script.createLabel(block.getStart().getNewAddress(processParam.main_thread_name), moduleName + "_main_thread_name", true);
		if ((int) processParam.process_name != 0)
			script.createLabel(block.getStart().getNewAddress(processParam.process_name), moduleName + "_process_name", true);

		script.clearListing(processParamAddress, processParamAddress.add(sceProcessParamDataType.getLength()));
		script.createData(processParamAddress, sceProcessParamDataType);
		script.createLabel(processParamAddress, moduleName + "_" + sceProcessParamDataType.getName(), true);

		byte[] libcParamSizeBytes = new byte[4];
		block.getBytes(block.getStart().getNewAddress(processParam.sce_libc_param), libcParamSizeBytes, 0, libcParamSizeBytes.length);
		ByteProvider importsSizeByteProvider = new ByteArrayProvider(libcParamSizeBytes);
		BinaryReader importsSizeBinaryReader = new BinaryReader(importsSizeByteProvider, true);
		int libcParamSize = importsSizeBinaryReader.readNextUnsignedShort();

		switch (libcParamSize) {
			case 0x28:
				applySceLibcParamStruct_1x(script, block.getStart().getNewAddress(processParam.sce_libc_param), moduleName);
				break;
			case 0x38:
				applySceLibcParamStruct_2x(script, block.getStart().getNewAddress(processParam.sce_libc_param), moduleName);
				break;
			default:
				script.println(String.format("Unknown SceLibcParam struct of size 0x%X encountered.", libcParamSize));
				break;
		}
	}

	private static void processFunction(GhidraScript script, Program program, NidDatabase db, String libraryName, long libraryNid, long functionNid, long functionEntry, MemoryBlock block) throws DuplicateNameException, InvalidInputException {
		String functionName = db.getFunctionName(libraryNid, functionNid);
		if (functionName == null)
			functionName = libraryName + "_" + String.format("%08X", functionNid);

		Address functionEntryAddress = block.getStart().getNewAddress(functionEntry);

		if (libraryName.equals("") && noname_function_exports.containsKey((int) functionNid))
			functionName = noname_function_exports.get((int) functionNid);
			
		//script.println("  " + String.format("0x%08X", functionNid) + ", " + functionName +
		//		", addr: " + String.format("0x%08X", functionEntry));

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

	private static void processVariable(GhidraScript script, Program program, NidDatabase db, String moduleName, String libraryName, long libraryNid, long variableNid, long variableEntry, MemoryBlock block) throws Exception, DuplicateNameException, InvalidInputException {
		String variableName = db.getVariableName(libraryNid, variableNid);
		if (variableName == null)
			variableName = libraryName + "_" + String.format("%08X", variableNid);

		Address variableEntryAddress = block.getStart().getNewAddress(variableEntry);

		if (libraryName.equals("") && noname_variable_exports.containsKey((int) variableNid)) {
			variableName = noname_variable_exports.get((int) variableNid);

			switch ((int) variableNid) {
				case 0x70FBA1E7:
					applySceProcessParamStruct(script, variableEntryAddress, moduleName, block);
					variableName = String.format("%s_%s", moduleName, variableName);
					break;
				case 0x936C8A78:
					script.createData(variableEntryAddress, StructConverter.DWORD);
					variableName = String.format("%s_%s", moduleName, variableName);
					break;
				default:
					return;
			}
		}

		//script.println("  " + String.format("0x%08X", variableNid) + ", " + variableName +
		//		", addr: " + String.format("0x%08X", variableEntry));
		
		script.createLabel(variableEntryAddress, variableName, true);
	}

	private void processExports(Program program, NidDatabase db, Memory memory, MemoryBlock block, String moduleName, Address exportsAddress, SceModuleExports exports) throws Exception {
		//println("Exports NID: " + String.format("0x%08X", exports.library_nid));
		//println("Exports num funcs: " + String.format("0x%08X", exports.num_functions));
		//println("Exports nid table: " + String.format("0x%08X", exports.nid_table));
		//println("Exports size: " + String.format("0x%08X", exports.size));

		Address funcNidTableAddress = block.getStart().getNewAddress(exports.nid_table);
		Address funcEntryTableAddress = block.getStart().getNewAddress(exports.entry_table);
		Address varNidTableAddress = block.getStart().getNewAddress(exports.nid_table + (4 * exports.num_functions));
		Address varEntryTableAddress = block.getStart().getNewAddress(exports.entry_table + (4 * exports.num_functions));
		Address libraryNameAddress = block.getStart().getNewAddress(exports.library_name);

		ByteProvider libraryNameByteProvider = new MemoryByteProvider(memory, libraryNameAddress);
		BinaryReader libraryNameBinaryReader = new BinaryReader(libraryNameByteProvider, true);
		String libraryName = libraryNameBinaryReader.readNextAsciiString();

		byte[] funcNidTableBytes = new byte[4 * exports.num_functions];
		byte[] funcEntryTableBytes = new byte[4 * exports.num_functions];
		byte[] varNidTableBytes = new byte[4 * exports.num_vars];
		byte[] varEntryTableBytes = new byte[4 * exports.num_vars];

		if (exports.num_functions > 0) {
			block.getBytes(funcNidTableAddress, funcNidTableBytes, 0, funcNidTableBytes.length);
			block.getBytes(funcEntryTableAddress, funcEntryTableBytes, 0, funcEntryTableBytes.length);	
		}

		if (exports.num_vars > 0) {
			block.getBytes(varNidTableAddress, varNidTableBytes, 0, varNidTableBytes.length);
			block.getBytes(varEntryTableAddress, varEntryTableBytes, 0, varEntryTableBytes.length);
		}

		IntBuffer funcNidTableIntBuffer = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer funcEntryTableIntBuffer = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer varNidTableIntBuffer = ByteBuffer.wrap(varNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer varEntryTableIntBuffer = ByteBuffer.wrap(varEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

		println("Exports library name: " + libraryName);

		for (int i = 0; i < exports.num_functions; i++) {
			long functionNid =  Integer.toUnsignedLong(funcNidTableIntBuffer.get(i));
			long functionEntry =  Integer.toUnsignedLong(funcEntryTableIntBuffer.get(i))  & ~1l;

			processFunction(this, program, db, libraryName, exports.library_nid, functionNid, functionEntry, block);
		}

		for (int i = 0; i < exports.num_vars; i++) {
			long variableNid =  Integer.toUnsignedLong(varNidTableIntBuffer.get(i));
			long variableEntry =  Integer.toUnsignedLong(varEntryTableIntBuffer.get(i)) & ~1l;

			processVariable(this, program, db, moduleName, libraryName, exports.library_nid, variableNid, variableEntry, block);
		}

		applySceModuleExportsStruct(this, moduleName, exportsAddress, libraryName);

		if (exports.num_functions > 0) {
			createDwords(funcNidTableAddress, exports.num_functions);
			createLabel(funcNidTableAddress, moduleName + "_exports_" + libraryName + (libraryName.equals("") ? "" : "_") + "function_NID_table", true);
			createLabel(funcEntryTableAddress, moduleName + "_exports_" + libraryName + (libraryName.equals("") ? "" : "_") + "function_entry_table", true);
		}

		if (exports.num_vars > 0) {
			createDwords(varNidTableAddress, exports.num_vars);
			createLabel(varNidTableAddress, moduleName + "_exports_" + libraryName + (libraryName.equals("") ? "" : "_") + "variable_NID_table", true);
			createLabel(varEntryTableAddress, moduleName + "_exports_" + libraryName + (libraryName.equals("") ? "" : "_") + "variable_entry_table", true);
		}
	}

	private void processImports(Program program, NidDatabase db, Memory memory, MemoryBlock block, String moduleName, Address importsAddress,
								long libraryNid, long funcNidTable, long funcEntryTable, long varNidTable, long varEntryTable, long libraryNameLong, short numFunctions, short numVars, boolean is1xFormat) throws Exception {
		//println("Imports NID: " + String.format("0x%08X", imports.library_nid));
		//println("Imports num funcs: " + String.format("0x%08X", imports.num_functions));
		//println("Imports nid table: " + String.format("0x%08X", imports.func_nid_table));
		//println("Imports size: " + String.format("0x%08X", imports.size));

		Address funcNidTableAddress = block.getStart().getNewAddress(funcNidTable);
		Address funcEntryTableAddress = block.getStart().getNewAddress(funcEntryTable);
		Address varNidTableAddress = block.getStart().getNewAddress(varNidTable);
		Address varEntryTableAddress = block.getStart().getNewAddress(varEntryTable);
		Address libraryNameAddress = block.getStart().getNewAddress(libraryNameLong);

		ByteProvider libraryNameByteProvider = new MemoryByteProvider(memory, libraryNameAddress);
		BinaryReader libraryNameBinaryReader = new BinaryReader(libraryNameByteProvider, true);
		String libraryName = libraryNameBinaryReader.readNextAsciiString();

		byte[] funcNidTableBytes = new byte[4 * numFunctions];
		byte[] funcEntryTableBytes = new byte[4 * numFunctions];
		byte[] varNidTableBytes = new byte[4 * numVars];
		byte[] varEntryTableBytes = new byte[4 * numVars];

		if (numFunctions > 0) {
			block.getBytes(funcNidTableAddress, funcNidTableBytes, 0, funcNidTableBytes.length);
			block.getBytes(funcEntryTableAddress, funcEntryTableBytes, 0, funcEntryTableBytes.length);
		}
		if (numVars > 0) {
			block.getBytes(varNidTableAddress, varNidTableBytes, 0, varNidTableBytes.length);
			block.getBytes(varEntryTableAddress, varEntryTableBytes, 0, varEntryTableBytes.length);
		}			

		IntBuffer funcNidTableIntBuffer = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer funcEntryTableIntBuffer = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer varNidTableIntBuffer = ByteBuffer.wrap(varNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		IntBuffer varEntryTableIntBuffer = ByteBuffer.wrap(varEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

		println("Imports library name: " + libraryName);

		for (int i = 0; i < numFunctions; i++) {
			long functionNid =  Integer.toUnsignedLong(funcNidTableIntBuffer.get(i));
			long functionEntry =  Integer.toUnsignedLong(funcEntryTableIntBuffer.get(i)) & ~1l;

			processFunction(this, program, db, libraryName, libraryNid, functionNid, functionEntry, block);
		}
		for (int i = 0; i < numVars; i++) {
			long variableNid =  Integer.toUnsignedLong(varNidTableIntBuffer.get(i));
			long variableEntry =  Integer.toUnsignedLong(varEntryTableIntBuffer.get(i)) & ~1l;

			processVariable(this, program, db, moduleName, libraryName, libraryNid, variableNid, variableEntry, block);
		}

		if (is1xFormat)
			applySceModuleImportsStruct_1x(this, moduleName, importsAddress, libraryName);
		else
			applySceModuleImportsStruct_3x(this, moduleName, importsAddress, libraryName);

		if (numFunctions > 0) {
			createDwords(funcNidTableAddress, numFunctions);
			createLabel(funcNidTableAddress, moduleName + "_imports_" + libraryName + "_function_NID_table", true);
			createLabel(funcEntryTableAddress, moduleName + "_imports_" + libraryName + "_function_entry_table", true);
		}

		if (numVars > 0) {
			createDwords(varNidTableAddress, numVars);
			createLabel(varNidTableAddress, moduleName + "_imports_" + libraryName + "_variable_NID_table", true);
			createLabel(varEntryTableAddress, moduleName + "_imports_" + libraryName + "_variable_entry_table", true);
		}
	}

	private void processModuleInfo(Program program, NidDatabase db, Memory memory, MemoryBlock block, Address moduleInfoAddress) throws Exception {
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
				println("Exports size mismatch (got " + String.format("0x%X", moduleExports.size) + ")");
				break;
			}

			processExports(program, db, memory, block, moduleInfo.name, exportsTop, moduleExports);

			exportsTop = exportsTop.add(moduleExports.size);
		}

		Address importsTop = block.getStart().add(moduleInfo.import_top);
		Address importsEnd = block.getStart().add(moduleInfo.import_end);
		while (!importsTop.equals(importsEnd)) {
			byte[] importsSizeBytes = new byte[2];
			block.getBytes(importsTop, importsSizeBytes, 0, importsSizeBytes.length);
			ByteProvider importsSizeByteProvider = new ByteArrayProvider(importsSizeBytes);
			BinaryReader importsSizeBinaryReader = new BinaryReader(importsSizeByteProvider, true);
			int importsSize = importsSizeBinaryReader.readNextUnsignedShort();

			byte[] importsBytes = null;
			if (importsSize == SceModuleImports_1x.SIZE) {
				importsBytes = new byte[SceModuleImports_1x.SIZE];
			} else if (importsSize == SceModuleImports_3x.SIZE) {
				importsBytes = new byte[SceModuleImports_3x.SIZE];
			} else {
				println("Imports size mismatch (got " + String.format("0x%X", importsSize) + ")");
				break;
			}
			block.getBytes(importsTop, importsBytes, 0, importsBytes.length);

			ByteProvider importsByteProvider = new ByteArrayProvider(importsBytes);
			BinaryReader importsBinaryReader = new BinaryReader(importsByteProvider, true);

			long libraryNid, funcNidTable, funcEntryTable, varNidTable, varEntryTable, libraryNameLong;
			short numFunctions, numVars;

			if (importsSize == SceModuleImports_1x.SIZE) {
				SceModuleImports_1x moduleImports = new SceModuleImports_1x(importsBinaryReader);
				libraryNid = moduleImports.library_nid;
				funcNidTable = moduleImports.func_nid_table;
				funcEntryTable = moduleImports.func_entry_table;
				varNidTable = moduleImports.var_nid_table;
				varEntryTable = moduleImports.var_entry_table;
				libraryNameLong = moduleImports.library_name;
				numFunctions = moduleImports.num_functions;
				numVars = moduleImports.num_vars;
			} else { /* Can only be 3.x format */
				SceModuleImports_3x moduleImports = new SceModuleImports_3x(importsBinaryReader);
				libraryNid = moduleImports.library_nid;
				funcNidTable = moduleImports.func_nid_table;
				funcEntryTable = moduleImports.func_entry_table;
				varNidTable = moduleImports.var_nid_table;
				varEntryTable = moduleImports.var_entry_table;
				libraryNameLong = moduleImports.library_name;
				numFunctions = moduleImports.num_functions;
				numVars = moduleImports.num_vars;
			}

			processImports(program, db, memory, block, moduleInfo.name, importsTop, libraryNid, funcNidTable,
					funcEntryTable, varNidTable, varEntryTable, libraryNameLong, numFunctions, numVars, (importsSize == SceModuleImports_1x.SIZE));

			importsTop = importsTop.add(importsSize);
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
		if (elfHeader.e_type() != ET_SCE_RELEXEC && elfHeader.e_type() != ET_SCE_EXEC) {
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
		YamlNidDatabase dbRaw = yamlReader.read(YamlNidDatabase.class);
		NidDatabase db = new NidDatabase();
		populateNidDatabaseFromYaml(db, dbRaw);

		/* Get module info address */
		MemoryBlock textMemoryBlock = getExecutableMemoryBlock(memory);
		Address moduleInfoAddress = textMemoryBlock.getStart().add(elfHeader.e_entry());

		processModuleInfo(getCurrentProgram(), db, memory, textMemoryBlock, moduleInfoAddress);
	}
}
