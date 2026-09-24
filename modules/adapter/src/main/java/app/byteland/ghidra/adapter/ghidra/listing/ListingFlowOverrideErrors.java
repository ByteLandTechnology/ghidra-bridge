package app.byteland.ghidra.adapter.ghidra.listing;

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

  static final class Conflict extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private Conflict(String message) {
      super(message);
    }
  }

  static final class UpdateFailed extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private UpdateFailed(String message) {
      super(message);
    }

    private UpdateFailed(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
