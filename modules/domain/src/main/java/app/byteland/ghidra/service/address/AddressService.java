package app.byteland.ghidra.service.address;

import java.util.Set;

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

  /**
   * Resolves a raw address expression with an optional field projection.
   */
  default AddressResource resolveAddress(String rawAddress, Set<String> fields) {
    return resolveAddress(rawAddress);
  }
}
