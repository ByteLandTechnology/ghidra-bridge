package app.byteland.ghidra.adapter.ghidra.analysis;

final class AnalysisStatusPolicy {
  private AnalysisStatusPolicy() {}

  static StartDecision start(boolean closed, boolean bridgeRunning, boolean ghidraRunning) {
    if (closed) {
      return StartDecision.REJECT_CLOSED;
    }
    if (bridgeRunning) {
      return StartDecision.RETURN_BRIDGE;
    }
    if (ghidraRunning) {
      return StartDecision.RETURN_GHIDRA;
    }
    return StartDecision.START_BRIDGE;
  }

  static SnapshotSource status(
      boolean bridgeTaskExists, boolean bridgeRunning, boolean ghidraRunning) {
    if (bridgeRunning) {
      return SnapshotSource.BRIDGE;
    }
    if (ghidraRunning) {
      return SnapshotSource.GHIDRA;
    }
    return bridgeTaskExists ? SnapshotSource.BRIDGE : SnapshotSource.GHIDRA;
  }

  enum StartDecision {
    REJECT_CLOSED,
    RETURN_BRIDGE,
    RETURN_GHIDRA,
    START_BRIDGE
  }

  enum SnapshotSource {
    BRIDGE,
    GHIDRA
  }
}
