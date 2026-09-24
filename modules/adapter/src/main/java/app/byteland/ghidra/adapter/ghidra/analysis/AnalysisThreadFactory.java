package app.byteland.ghidra.adapter.ghidra.analysis;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

final class AnalysisThreadFactory implements ThreadFactory {
  private final AtomicInteger sequence = new AtomicInteger();
  private final String programName;

  AnalysisThreadFactory(String programName) {
    this.programName = programName == null || programName.isBlank() ? "program" : programName;
  }

  @Override
  public Thread newThread(Runnable runnable) {
    Thread thread =
        new Thread(
            runnable, "ghidra-bridge-analysis-" + programName + "-" + sequence.incrementAndGet());
    thread.setDaemon(true);
    return thread;
  }
}
