package app.byteland.ghidra.mcp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * Test resolver that counts DNS lookups for synthetic {@code .mcp-test.internal} hostnames and
 * delegates all other lookups to the JDK built-in resolver.
 */
public final class CountingInetAddressResolverProvider extends InetAddressResolverProvider {
  static final String TEST_DOMAIN_SUFFIX = ".mcp-test.internal";
  private static final ConcurrentHashMap<String, AtomicInteger> LOOKUP_COUNTS =
      new ConcurrentHashMap<>();

  public static int lookupCount(String host) {
    AtomicInteger counter = LOOKUP_COUNTS.get(normalize(host));
    return counter == null ? 0 : counter.get();
  }

  @Override
  public InetAddressResolver get(Configuration configuration) {
    InetAddressResolver builtin = configuration.builtinResolver();
    return new InetAddressResolver() {
      @Override
      public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
          throws UnknownHostException {
        String normalized = normalize(host);
        if (normalized.endsWith(TEST_DOMAIN_SUFFIX)) {
          LOOKUP_COUNTS.computeIfAbsent(normalized, ignored -> new AtomicInteger())
              .incrementAndGet();
          if (normalized.startsWith("unresolvable.")) {
            throw new UnknownHostException("unresolvable test host: " + host);
          }
          byte[] address =
              normalized.startsWith("external.")
                  ? new byte[] {(byte) 192, 0, 2, 10}
                  : new byte[] {127, 0, 0, 1};
          return Stream.of(InetAddress.getByAddress(host, address));
        }
        return builtin.lookupByName(host, lookupPolicy);
      }

      @Override
      public String lookupByAddress(byte[] addr) throws UnknownHostException {
        return builtin.lookupByAddress(addr);
      }
    };
  }

  @Override
  public String name() {
    return "mcp-test-counting-resolver";
  }

  private static String normalize(String host) {
    return host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
  }
}
