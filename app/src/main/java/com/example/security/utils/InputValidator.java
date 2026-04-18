package com.example.security.utils;

public final class InputValidator {

    private InputValidator() {

    }

    public static ValidationResult validate(String text, String key, boolean requiresKey) {
        if (text == null || text.trim().isEmpty()) {
            return ValidationResult.failure("Input text cannot be empty.");
        }
        if (requiresKey && (key == null || key.trim().isEmpty())) {
            return ValidationResult.failure("Key cannot be empty for this algorithm.");
        }
        return ValidationResult.success();
    }

    public static final class ValidationResult {

        private final boolean valid;
        private final String  errorMessage;

        private ValidationResult(boolean valid, String errorMessage) {
            this.valid        = valid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult failure(String message) {
            return new ValidationResult(false, message);
        }

        public boolean isValid()          { return valid;        }
        public String  getErrorMessage()  { return errorMessage; }
    }
}
