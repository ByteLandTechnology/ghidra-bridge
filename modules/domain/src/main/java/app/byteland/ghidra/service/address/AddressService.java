package app.byteland.ghidra.service.address;

/**
 * Resolves address strings to program address metadata.
 */
@FunctionalInterface
public interface AddressService {
  /**
   * Resolves a raw address expression.
   *
   * @param rawAddress the raw address expression to resolve
   * @return resolved address metadata resource
   */
  AddressResource resolveAddress(String rawAddress);
}
