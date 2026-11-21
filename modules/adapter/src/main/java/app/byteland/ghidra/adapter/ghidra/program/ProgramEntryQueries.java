package app.byteland.ghidra.adapter.ghidra.program;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.address.AddressResource.FunctionSummary;
import app.byteland.ghidra.service.program.ExportResource;
import app.byteland.ghidra.service.program.ImportResource;
import app.byteland.ghidra.service.program.ProgramService.ExportQuery;
import app.byteland.ghidra.service.program.ProgramService.ImportQuery;
import app.byteland.ghidra.service.program.ProgramTextMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

final class ProgramEntryQueries {
  private static final String DEFAULT_EXTERNAL_LIBRARY = "<EXTERNAL>";
  private static final String GLOBAL_NAMESPACE = "Global";
  private static final String ORDINAL_PREFIX = "Ordinal_";

  private final GhidraSession context;
  private final Program program;

  ProgramEntryQueries(GhidraSession context) {
    this.context = context;
    this.program = context.currentProgram();
  }

  Page<ImportResource> listImports(ImportQuery query) {
    int limit = Page.clampLimit(query.limit());
    ProgramTextMatcher nameMatcher =
        ProgramTextMatcher.compile(query.name(), query.regex(), query.nameRegex(), "name");
    ProgramTextMatcher libraryMatcher =
        ProgramTextMatcher.compile(query.library(), query.regex(), query.libraryRegex(), "library");
    ImportCursor cursor = parseImportCursor(query.cursor());

    ExternalManager externalManager = program.getExternalManager();
    SymbolIterator symbols = program.getSymbolTable().getExternalSymbols();
    List<ImportCandidate> candidates = new ArrayList<>();
    while (symbols.hasNext()) {
      Symbol symbol = symbols.next();
      ExternalLocation location = externalManager.getExternalLocation(symbol);
      String library = resolveLibraryName(symbol, location);
      String name = symbol.getName();
      if (libraryMatcher != null && !libraryMatcher.matches(library)) continue;
      if (nameMatcher != null && !nameMatcher.matches(name)) continue;
      Address extAddress =
          location != null && location.getExternalSpaceAddress() != null
              ? location.getExternalSpaceAddress()
              : symbol.getAddress();
      candidates.add(new ImportCandidate(extAddress, library, name, symbol, location));
    }

    candidates.sort(
        Comparator.comparing(ImportCandidate::address)
            .thenComparing(ImportCandidate::library)
            .thenComparing(ImportCandidate::name));

    List<ImportResource> items = new ArrayList<>();
    String nextCursor = null;
    for (ImportCandidate candidate : candidates) {
      if (cursor != null && compareImport(candidate, cursor) <= 0) continue;
      if (items.size() >= limit) {
        ImportResource last = items.getLast();
        nextCursor = encodeImportCursor(last.address(), last.library(), last.name());
        break;
      }
      items.add(describeImport(candidate));
    }
    return Page.of(items, limit, nextCursor);
  }

  Page<ExportResource> listExports(ExportQuery query) {
    return listExternalEntries(query, true);
  }

  Page<ExportResource> listEntryPoints(ExportQuery query) {
    return listExternalEntries(query, false);
  }

  private Page<ExportResource> listExternalEntries(ExportQuery query, boolean includeAliases) {
    int limit = Page.clampLimit(query.limit());
    ProgramTextMatcher nameMatcher =
        ProgramTextMatcher.compile(query.name(), query.regex(), query.nameRegex(), "name");
    ExportCursor cursor = parseExportCursor(query.cursor());

    SymbolTable symbolTable = program.getSymbolTable();
    AddressIterator addresses = symbolTable.getExternalEntryPointIterator();
    List<ExportResource> items = new ArrayList<>();
    String nextCursor = null;

    outer:
    while (addresses.hasNext()) {
      Address address = addresses.next();
      if (cursor != null && address.compareTo(cursor.address()) < 0) continue;
      List<ExportResource> atAddress = describeEntriesAt(address, symbolTable, includeAliases);
      for (ExportResource entry : atAddress) {
        if (cursor != null
            && address.equals(cursor.address())
            && entry.name().compareTo(cursor.name()) <= 0) {
          continue;
        }
        if (!matchesExport(entry, query, nameMatcher)) continue;
        if (items.size() >= limit) {
          ExportResource last = items.getLast();
          nextCursor = CompositeCursor.key(last.address(), last.name());
          break outer;
        }
        items.add(entry);
      }
    }
    return Page.of(items, limit, nextCursor);
  }

  private List<ExportResource> describeEntriesAt(
      Address address, SymbolTable symbolTable, boolean includeAliases) {
    String canonicalAddress = AddressUtil.canonicalAddress(address);
    Function function = program.getFunctionManager().getFunctionAt(address);
    FunctionSummary functionSummary =
        function == null
            ? null
            : new FunctionSummary(
                AddressUtil.canonicalAddress(function.getEntryPoint()), function.getName());
    Symbol[] symbols = symbolTable.getSymbols(address);
    Integer companionOrdinal = findCompanionOrdinal(symbols);
    List<Symbol> selected = selectEntrySymbols(symbols, symbolTable, address, includeAliases);
    if (selected.isEmpty()) {
      String fallbackName = function != null ? function.getName() : canonicalAddress;
      boolean isFunction = function != null;
      return List.of(
          new ExportResource(
              canonicalAddress,
              fallbackName,
              CppSymbolNames.demangled(program, fallbackName, address),
              GLOBAL_NAMESPACE,
              isFunction,
              functionSummary,
              companionOrdinal));
    }

    List<ExportResource> entries = new ArrayList<>(selected.size());
    for (Symbol symbol : selected) {
      String name = symbol.getName();
      boolean isFunction = function != null || symbol.getSymbolType() == SymbolType.FUNCTION;
      Integer ordinal = companionOrdinal != null ? companionOrdinal : parseOrdinal(name);
      entries.add(
          new ExportResource(
              canonicalAddress,
              name,
              CppSymbolNames.demangled(program, name, address),
              resolveNamespace(symbol.getParentNamespace()),
              isFunction,
              functionSummary,
              ordinal));
    }
    entries.sort(Comparator.comparing(ExportResource::name));
    return entries;
  }

  private static List<Symbol> selectEntrySymbols(
      Symbol[] symbols, SymbolTable symbolTable, Address address, boolean includeAliases) {
    if (symbols == null || symbols.length == 0) {
      return List.of();
    }
    if (!includeAliases) {
      for (Symbol symbol : symbols) {
        if (symbol.isPrimary() && parseOrdinal(symbol.getName()) == null) {
          return List.of(symbol);
        }
      }
      Symbol primary = symbolTable.getPrimarySymbol(address);
      return primary == null ? List.of(symbols[0]) : List.of(primary);
    }

    List<Symbol> named = new ArrayList<>();
    for (Symbol symbol : symbols) {
      if (parseOrdinal(symbol.getName()) != null) continue;
      if (!symbol.isPrimary() && symbol.getSource() == SourceType.DEFAULT) continue;
      named.add(symbol);
    }
    if (!named.isEmpty()) {
      return named;
    }
    Symbol primary = symbolTable.getPrimarySymbol(address);
    return primary == null ? List.of(symbols[0]) : List.of(primary);
  }

  private static boolean matchesExport(
      ExportResource entry, ExportQuery query, ProgramTextMatcher nameMatcher) {
    if (query.namespace() != null && !query.namespace().equals(entry.namespace())) {
      return false;
    }
    if (query.isFunction() != null && entry.isFunction() != query.isFunction()) {
      return false;
    }
    return nameMatcher == null || nameMatcher.matches(entry.name());
  }

  private ImportResource describeImport(ImportCandidate candidate) {
    ExternalLocation location = candidate.location();
    Symbol symbol = candidate.symbol();
    Function extFunction = resolveExternalFunction(symbol, location);
    boolean isFunction =
        extFunction != null
            || (location != null && location.isFunction())
            || symbol.getSymbolType() == SymbolType.FUNCTION;
    String originalName = location == null ? null : blankToNull(location.getOriginalImportedName());
    String demangled = CppSymbolNames.demangled(program, candidate.name(), candidate.address());
    if (demangled == null && originalName != null) {
      demangled = CppSymbolNames.demangled(program, originalName, candidate.address());
    }
    Integer ordinal = parseOrdinal(originalName != null ? originalName : candidate.name());
    String signature = extFunction == null ? null : String.valueOf(extFunction.getSignature());
    List<String> thunkAddresses = collectThunkAddresses(extFunction);
    return new ImportResource(
        AddressUtil.canonicalAddress(candidate.address()),
        candidate.library(),
        candidate.name(),
        originalName,
        demangled,
        ordinal,
        thunkAddresses,
        signature,
        isFunction);
  }

  private static Function resolveExternalFunction(Symbol symbol, ExternalLocation location) {
    if (location != null && location.getFunction() != null) {
      return location.getFunction();
    }
    Object symbolObject = symbol.getObject();
    return symbolObject instanceof Function function ? function : null;
  }

  private static List<String> collectThunkAddresses(Function extFunction) {
    if (extFunction == null) {
      return List.of();
    }
    Address[] rawThunks = extFunction.getFunctionThunkAddresses(true);
    if (rawThunks == null || rawThunks.length == 0) {
      return List.of();
    }
    Address[] sorted = Arrays.copyOf(rawThunks, rawThunks.length);
    Arrays.sort(sorted);
    List<String> canonical = new ArrayList<>(sorted.length);
    String previous = null;
    for (Address thunk : sorted) {
      String text = AddressUtil.canonicalAddress(thunk);
      if (text != null && !text.equals(previous)) {
        canonical.add(text);
        previous = text;
      }
    }
    return List.copyOf(canonical);
  }

  private static String resolveLibraryName(Symbol symbol, ExternalLocation location) {
    if (location != null) {
      String library = blankToNull(location.getLibraryName());
      if (library != null) return library;
    }
    Namespace parent = symbol.getParentNamespace();
    if (parent != null && !parent.isGlobal()) {
      String namespace = blankToNull(parent.getName(true));
      if (namespace != null) return namespace;
    }
    return DEFAULT_EXTERNAL_LIBRARY;
  }

  private static String resolveNamespace(Namespace namespace) {
    if (namespace == null || namespace.isGlobal()) {
      return GLOBAL_NAMESPACE;
    }
    return namespace.getName(true);
  }

  private static Integer findCompanionOrdinal(Symbol[] symbols) {
    if (symbols == null) return null;
    for (Symbol symbol : symbols) {
      Integer ordinal = parseOrdinal(symbol.getName());
      if (ordinal != null) return ordinal;
    }
    return null;
  }

  private static Integer parseOrdinal(String symbolName) {
    if (symbolName == null || !symbolName.startsWith(ORDINAL_PREFIX)) {
      return null;
    }
    String digits = symbolName.substring(ORDINAL_PREFIX.length());
    if (digits.isEmpty()) return null;
    for (int index = 0; index < digits.length(); index++) {
      if (!Character.isDigit(digits.charAt(index))) return null;
    }
    try {
      return Integer.valueOf(digits);
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  private static String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static String encodeImportCursor(String address, String library, String name) {
    return address + '\0' + library + '\0' + name;
  }

  private ImportCursor parseImportCursor(String cursor) {
    if (cursor == null || cursor.isBlank()) return null;
    int first = cursor.indexOf('\0');
    int second = first < 0 ? -1 : cursor.indexOf('\0', first + 1);
    if (first <= 0 || second <= first + 1 || second >= cursor.length() - 1) {
      throw new IllegalArgumentException("invalid imports cursor");
    }
    return new ImportCursor(
        context.parseAddress(cursor.substring(0, first)),
        cursor.substring(first + 1, second),
        cursor.substring(second + 1));
  }

  private ExportCursor parseExportCursor(String cursor) {
    CompositeCursor parts = CompositeCursor.parse(cursor, "exports");
    if (parts == null) return null;
    return new ExportCursor(context.parseAddress(parts.address()), parts.secondary());
  }

  private static int compareImport(ImportCandidate candidate, ImportCursor cursor) {
    int byAddress = candidate.address().compareTo(cursor.address());
    if (byAddress != 0) return byAddress;
    int byLibrary = candidate.library().compareTo(cursor.library());
    if (byLibrary != 0) return byLibrary;
    return candidate.name().compareTo(cursor.name());
  }

  private record ImportCandidate(
      Address address,
      String library,
      String name,
      Symbol symbol,
      ExternalLocation location) {}

  private record ImportCursor(Address address, String library, String name) {}

  private record ExportCursor(Address address, String name) {}
}
