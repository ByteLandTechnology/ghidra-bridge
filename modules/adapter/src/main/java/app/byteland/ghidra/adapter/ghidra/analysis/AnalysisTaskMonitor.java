package app.byteland.ghidra.adapter.ghidra.analysis;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
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

  BridgedMonitor bridge(TaskMonitor delegate) {
    return new BridgedMonitor(TaskMonitor.dummyIfNull(delegate));
  }

  final class BridgedMonitor implements TaskMonitor, AutoCloseable {
    private final TaskMonitor delegate;
    private final CancelledListener toDelegate;
    private final CancelledListener fromDelegate;
    private final AtomicBoolean syncingCancel = new AtomicBoolean();

    private BridgedMonitor(TaskMonitor delegate) {
      this.delegate = delegate;
      if (AnalysisTaskMonitor.this.isCancelled()) {
        if (!delegate.isCancelled()) {
          delegate.cancel();
        }
      } else if (delegate.isCancelled()) {
        AnalysisTaskMonitor.this.cancel();
      }
      delegate.setIndeterminate(AnalysisTaskMonitor.this.isIndeterminate());
      String initialMessage = AnalysisTaskMonitor.this.getMessage();
      if (!initialMessage.isEmpty()) {
        delegate.setMessage(initialMessage);
      }
      this.toDelegate =
          () -> {
            if (syncingCancel.compareAndSet(false, true)) {
              try {
                if (!delegate.isCancelled()) {
                  delegate.cancel();
                }
              } finally {
                syncingCancel.set(false);
              }
            }
          };
      this.fromDelegate =
          () -> {
            if (syncingCancel.compareAndSet(false, true)) {
              try {
                if (!AnalysisTaskMonitor.this.isCancelled()) {
                  AnalysisTaskMonitor.this.cancel();
                }
              } finally {
                syncingCancel.set(false);
              }
            }
          };
      AnalysisTaskMonitor.this.addCancelledListener(toDelegate);
      delegate.addCancelledListener(fromDelegate);
    }

    @Override
    public boolean isCancelled() {
      if (delegate.isCancelled() && !AnalysisTaskMonitor.this.isCancelled()) {
        fromDelegate.cancelled();
      }
      return AnalysisTaskMonitor.this.isCancelled() || delegate.isCancelled();
    }

    @Override
    public void setShowProgressValue(boolean showProgressValue) {
      AnalysisTaskMonitor.this.setShowProgressValue(showProgressValue);
      delegate.setShowProgressValue(showProgressValue);
    }

    @Override
    public void setMessage(String message) {
      AnalysisTaskMonitor.this.setMessage(message);
      delegate.setMessage(message);
    }

    @Override
    public String getMessage() {
      return AnalysisTaskMonitor.this.getMessage();
    }

    @Override
    public void setProgress(long progress) {
      AnalysisTaskMonitor.this.setProgress(progress);
      delegate.setProgress(progress);
    }

    @Override
    public void initialize(long maximum) {
      AnalysisTaskMonitor.this.initialize(maximum);
      delegate.initialize(maximum);
      delegate.setIndeterminate(AnalysisTaskMonitor.this.isIndeterminate());
    }

    @Override
    public void initialize(long maximum, String message) {
      AnalysisTaskMonitor.this.initialize(maximum);
      AnalysisTaskMonitor.this.setMessage(message);
      delegate.initialize(maximum, message);
      delegate.setIndeterminate(AnalysisTaskMonitor.this.isIndeterminate());
    }

    @Override
    public void setMaximum(long maximum) {
      AnalysisTaskMonitor.this.setMaximum(maximum);
      delegate.setMaximum(maximum);
      delegate.setIndeterminate(AnalysisTaskMonitor.this.isIndeterminate());
    }

    @Override
    public long getMaximum() {
      return AnalysisTaskMonitor.this.getMaximum();
    }

    @Override
    public void setIndeterminate(boolean indeterminate) {
      AnalysisTaskMonitor.this.setIndeterminate(indeterminate);
      delegate.setIndeterminate(indeterminate);
    }

    @Override
    public boolean isIndeterminate() {
      return AnalysisTaskMonitor.this.isIndeterminate();
    }

    @Override
    public void checkCancelled() throws CancelledException {
      if (isCancelled()) {
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
      AnalysisTaskMonitor.this.incrementProgress(incrementAmount);
      delegate.incrementProgress(incrementAmount);
    }

    @Override
    public long getProgress() {
      return AnalysisTaskMonitor.this.getProgress();
    }

    @Override
    public void cancel() {
      AnalysisTaskMonitor.this.cancel();
      if (!delegate.isCancelled()) {
        delegate.cancel();
      }
    }

    @Override
    public void addCancelledListener(CancelledListener listener) {
      AnalysisTaskMonitor.this.addCancelledListener(listener);
    }

    @Override
    public void removeCancelledListener(CancelledListener listener) {
      AnalysisTaskMonitor.this.removeCancelledListener(listener);
    }

    @Override
    public void setCancelEnabled(boolean cancelEnabled) {
      AnalysisTaskMonitor.this.setCancelEnabled(cancelEnabled);
      delegate.setCancelEnabled(cancelEnabled);
    }

    @Override
    public boolean isCancelEnabled() {
      return AnalysisTaskMonitor.this.isCancelEnabled() && delegate.isCancelEnabled();
    }

    @Override
    public void clearCancelled() {
      AnalysisTaskMonitor.this.clearCancelled();
      delegate.clearCancelled();
    }

    @SuppressWarnings("InlineMeSuggester")
    @Deprecated(since = "10.3")
    @Override
    public void clearCanceled() {
      clearCancelled();
    }

    @Override
    public void close() {
      AnalysisTaskMonitor.this.removeCancelledListener(toDelegate);
      delegate.removeCancelledListener(fromDelegate);
    }
  }
}
