package app.byteland.ghidra.adapter.ghidra.analysis;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

final class AnalysisTaskMonitor implements TaskMonitor {
  private final List<CancelledListener> cancelledListeners = new CopyOnWriteArrayList<>();
  private volatile boolean cancelled;
  private volatile boolean cancelEnabled = true;
  private volatile boolean indeterminate = true;
  private volatile String message = "Analysis queued";
  private final AtomicLong progress = new AtomicLong();
  private volatile long maximum = TaskMonitor.NO_PROGRESS_VALUE;

  AnalysisTaskMonitor() {}

  @Override
  public boolean isCancelled() {
    return cancelled;
  }

  @Override
  public void setShowProgressValue(boolean showProgressValue) {
  }

  @Override
  public void setMessage(String message) {
    this.message = message == null ? "" : message;
  }

  @Override
  public String getMessage() {
    return message;
  }

  @Override
  public void setProgress(long progress) {
    this.progress.set(Math.max(0, progress));
  }

  @Override
  public void initialize(long maximum) {
    this.maximum = maximum;
    this.progress.set(0);
    this.indeterminate = maximum <= 0;
  }

  @Override
  public void setMaximum(long maximum) {
    this.maximum = maximum;
    this.indeterminate = maximum <= 0;
  }

  @Override
  public long getMaximum() {
    return maximum;
  }

  @Override
  public void setIndeterminate(boolean indeterminate) {
    this.indeterminate = indeterminate;
  }

  @Override
  public boolean isIndeterminate() {
    return indeterminate;
  }

  @Override
  public void checkCancelled() throws CancelledException {
    if (cancelled) {
      throw new CancelledException();
    }
  }

  @SuppressWarnings("InlineMeSuggester")
  @Deprecated(since = "10.3")
  @Override
  public void checkCanceled() throws CancelledException {
    checkCancelled();
  }

  @Override
  public void incrementProgress(long incrementAmount) {
    progress.updateAndGet(current -> Math.max(0, current + incrementAmount));
  }

  @Override
  public long getProgress() {
    return progress.get();
  }

  @Override
  public void cancel() {
    if (!cancelEnabled || cancelled) {
      return;
    }
    cancelled = true;
    for (CancelledListener listener : cancelledListeners) {
      listener.cancelled();
    }
  }

  @Override
  public void addCancelledListener(CancelledListener listener) {
    if (listener != null) {
      cancelledListeners.add(listener);
    }
  }

  @Override
  public void removeCancelledListener(CancelledListener listener) {
    cancelledListeners.remove(listener);
  }

  @Override
  public void setCancelEnabled(boolean cancelEnabled) {
    this.cancelEnabled = cancelEnabled;
  }

  @Override
  public boolean isCancelEnabled() {
    return cancelEnabled;
  }

  @Override
  public void clearCancelled() {
    cancelled = false;
  }

  @SuppressWarnings("InlineMeSuggester")
  @Deprecated(since = "10.3")
  @Override
  public void clearCanceled() {
    clearCancelled();
  }

  Double percent() {
    long max = maximum;
    if (indeterminate || max <= 0) {
      return null;
    }
    return Math.max(0.0, Math.min(100.0, (progress.get() * 100.0) / max));
  }
}
