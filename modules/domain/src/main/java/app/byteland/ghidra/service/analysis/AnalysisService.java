package app.byteland.ghidra.service.analysis;

import java.util.List;

/**
 * Controls Ghidra background auto-analysis tasks.
 */
public interface AnalysisService extends AutoCloseable {
  /**
   * Starts background analysis with selected analyzers.
   *
   * @param analyzers analyzer names to run, or null for the default analyzers. The list must not be empty
   * @return snapshot of the active analysis task
   */
  AnalysisResource startAnalysis(List<String> analyzers);

  /**
   * Returns current background analysis status.
   *
   * @return analysis progress and state
   */
  AnalysisResource getStatus();

  /**
   * Requests cancellation of active background analysis and returns the current status.
   *
   * @return analysis progress and state
   */
  AnalysisResource cancelAnalysis();

  /**
   * Rejects new analysis requests and waits until the active analysis finishes.
   */
  @Override
  void close();
}
