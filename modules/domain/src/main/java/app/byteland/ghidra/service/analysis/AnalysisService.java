package app.byteland.ghidra.service.analysis;

import java.util.List;

/**
 * Controls Ghidra background auto-analysis tasks.
 */
public interface AnalysisService extends AutoCloseable {
  /**
   * Starts background analysis with selected analyzers.
   *
   * @param analyzers analyzer names to run, or null for the default analyzers; must not be empty
   * @return active analysis task snapshot
   */
  AnalysisResource startAnalysis(List<String> analyzers);

  /**
   * Returns current background analysis status.
   *
   * @return analysis progress and state
   */
  AnalysisResource getStatus();

  /**
   * Rejects new analysis requests and waits until running analysis finishes.
   */
  @Override
  void close();
}
