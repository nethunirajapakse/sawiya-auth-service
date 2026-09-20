package com.sawiya.auth.dto;

import java.time.Instant;
import java.util.List;

public record ErrorResponseDTO(
        Instant timestamp,
        int status,
        String error,
        List<String> messages
) {
    public static ErrorResponseDTO of(int status, String error, List<String> messages) {
        return new ErrorResponseDTO(Instant.now(), status, error, messages);
    }
}
