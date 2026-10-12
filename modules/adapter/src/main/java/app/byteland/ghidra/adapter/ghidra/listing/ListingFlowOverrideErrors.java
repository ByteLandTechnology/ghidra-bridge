package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.service.DomainException;
import app.byteland.ghidra.service.TransactionExecutionException;

final class ListingFlowOverrideErrors {
  private ListingFlowOverrideErrors() {}

  static Conflict conflict(String message) {
    return new Conflict(message);
  }

  static UpdateFailed updateFailed(String message) {
    return new UpdateFailed(message);
  }

  static UpdateFailed updateFailed(String message, Throwable cause) {
    return new UpdateFailed(message, cause);
  }

  static final class Conflict extends RuntimeException implements DomainException {
    private static final long serialVersionUID = 1L;

    private Conflict(String message) {
      super(message);
    }

    @Override
    public int status() {
      return 409;
    }

    @Override
    public String code() {
      return "conflict";
    }

    @Override
    public String target() {
      return null;
    }
  }

  static final class UpdateFailed extends TransactionExecutionException {
    private static final long serialVersionUID = 1L;

    private UpdateFailed(String message) {
      super(message);
    }

    private UpdateFailed(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
