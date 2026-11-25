package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GhidraLauncherSnapshotTest {
  private static final String BOOTSTRAP_CLASS_ENTRY = "app/byteland/ghidra/Bootstrap.class";

  @TempDir Path tempDir;

  @Test
  void snapshotJarPreservesOwnerOnlyPosixPermissionsFor0644And0664Jars() throws Exception {
    Assumptions.assumeTrue(
        FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "POSIX file permissions are not supported on the default file system");

    Path tmpDir = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize();

    for (String launcherClassName : new String[] {"Bridge", "GhidraMcp"}) {
      for (String sourceMode : new String[] {"rw-r--r--", "rw-rw-r--"}) {
        Path sourceJar =
            createValidRuntimeJar(
                tempDir.resolve(launcherClassName + "-" + sourceMode + ".jar"));
        Set<PosixFilePermission> expectedSourcePerms = PosixFilePermissions.fromString(sourceMode);
        Files.setPosixFilePermissions(sourceJar, expectedSourcePerms);
        assertEquals(expectedSourcePerms, Files.getPosixFilePermissions(sourceJar));

        Path activeSnapshot = invokeSnapshotJar(launcherClassName, sourceJar);
        try {
          assertEquals(
              tmpDir,
              activeSnapshot.toAbsolutePath().normalize().getParent(),
              "Snapshot should be created in java.io.tmpdir");

          Set<PosixFilePermission> perms = Files.getPosixFilePermissions(activeSnapshot);
          assert perms.equals(PosixFilePermissions.fromString("rw-------"))
              : "Expected rw------- on snapshot in java.io.tmpdir, got "
                  + PosixFilePermissions.toString(perms);
          assertEquals(PosixFilePermissions.fromString("rw-------"), perms);
          assertEquals(-1L, Files.mismatch(sourceJar, activeSnapshot));
        } finally {
          Files.deleteIfExists(activeSnapshot);
        }
      }
    }
  }

  @Test
  void snapshotJarStreamsBytesAndCleansUpFailedSnapshots() throws Exception {
    Path validJar = createValidRuntimeJar(tempDir.resolve("valid.jar"));
    Path snapshot = invokeSnapshotJar("Bridge", validJar);
    try {
      assertTrue(Files.isRegularFile(snapshot));
      assertEquals(-1L, Files.mismatch(validJar, snapshot));
    } finally {
      Files.deleteIfExists(snapshot);
    }

    Path invalidJar = tempDir.resolve("invalid.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(invalidJar))) {
      out.putNextEntry(new JarEntry("README.txt"));
      out.write("missing bootstrap class".getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
    }

    Path tmpDir = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize();
    Set<Path> beforeSnapshots = listRuntimeSnapshots(tmpDir);

    InvocationTargetException thrown =
        assertThrows(
            InvocationTargetException.class,
            () -> invokeSnapshotJarReflectively("Bridge", invalidJar));
    assertTrue(thrown.getTargetException() instanceof IOException);

    Set<Path> leakedSnapshots =
        listRuntimeSnapshots(tmpDir).stream()
            .filter(candidate -> !beforeSnapshots.contains(candidate))
            .collect(Collectors.toSet());
    assertEquals(Set.of(), leakedSnapshots, "Failed snapshot attempts must clean up temp files");
  }

  private static Path invokeSnapshotJar(String launcherClassName, Path sourceJar) throws Exception {
    try {
      return invokeSnapshotJarReflectively(launcherClassName, sourceJar);
    } catch (InvocationTargetException invocation) {
      if (invocation.getTargetException() instanceof Exception targetException) {
        throw targetException;
      }
      if (invocation.getTargetException() instanceof Error targetError) {
        throw targetError;
      }
      throw invocation;
    }
  }

  private static Path invokeSnapshotJarReflectively(String launcherClassName, Path sourceJar)
      throws Exception {
    Class<?> launcherClass = Class.forName(launcherClassName);
    Object launcher = launcherClass.getDeclaredConstructor().newInstance();
    Method snapshotJar = launcherClass.getDeclaredMethod("snapshotJar", File.class);
    snapshotJar.setAccessible(true);
    return (Path) snapshotJar.invoke(launcher, sourceJar.toFile());
  }

  private static Path createValidRuntimeJar(Path destination) throws IOException {
    byte[] bootstrapBytes;
    try (InputStream classStream =
        Bootstrap.class.getClassLoader().getResourceAsStream(BOOTSTRAP_CLASS_ENTRY)) {
      if (classStream == null) {
        throw new IllegalStateException("Missing resource on classpath: " + BOOTSTRAP_CLASS_ENTRY);
      }
      bootstrapBytes = classStream.readAllBytes();
    }

    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(destination))) {
      JarEntry bootstrapEntry = new JarEntry(BOOTSTRAP_CLASS_ENTRY);
      out.putNextEntry(bootstrapEntry);
      out.write(bootstrapBytes);
      out.closeEntry();

      JarEntry metadataEntry = new JarEntry("META-INF/test-marker.txt");
      out.putNextEntry(metadataEntry);
      out.write("ghidra-bridge-test".getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
    }
    return destination;
  }

  private static Set<Path> listRuntimeSnapshots(Path tmpDir) throws IOException {
    try (Stream<Path> entries = Files.list(tmpDir)) {
      return entries
          .filter(
              path -> {
                Path fileName = path.getFileName();
                if (fileName == null) {
                  return false;
                }
                String name = fileName.toString();
                return name.startsWith("ghidra-bridge-runtime-") && name.endsWith(".jar");
              })
          .collect(Collectors.toSet());
    }
  }
}
