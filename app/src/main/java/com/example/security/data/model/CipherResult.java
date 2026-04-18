package com.example.security.data.model;

public final class CipherResult {

    private final String  result;
    private final boolean success;
    private final String  errorMessage;

    private CipherResult(String result, boolean success, String errorMessage) {
        this.result       = result;
        this.success      = success;
        this.errorMessage = errorMessage;
    }

    public static CipherResult success(String result) {
        return new CipherResult(result, true, null);
    }

    public static CipherResult failure(String errorMessage) {
        return new CipherResult(null, false, errorMessage);
    }

    public String  getResult()       { return result;       }
    public boolean isSuccess()       { return success;      }
    public String  getErrorMessage() { return errorMessage; }
}
