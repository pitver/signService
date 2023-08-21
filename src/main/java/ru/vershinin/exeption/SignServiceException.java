package ru.vershinin.exeption;

public class SignServiceException extends RuntimeException {

    public SignServiceException(String message) {
        super(message);
    }

    public SignServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
