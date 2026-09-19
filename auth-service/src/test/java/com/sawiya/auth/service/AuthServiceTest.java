package com.sawiya.auth.service;

import com.sawiya.auth.dto.SigninRequest;
import com.sawiya.auth.dto.SignupRequest;
import com.sawiya.auth.entity.User;
import com.sawiya.auth.exception.DuplicateEmailException;
import com.sawiya.auth.exception.InvalidCredentialsException;
import com.sawiya.auth.repository.UserRepository;
import com.sawiya.auth.security.JwtService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private TokenDenylistService tokenDenylistService;
    @Mock
    private RefreshTokenStore refreshTokenStore;

    @InjectMocks
    private AuthService authService;

    private User existingUser;

    @BeforeEach
    void setUp() {
        existingUser = User.builder()
                .id(UUID.randomUUID())
                .firstName("Nethuni")
                .lastName("Rajapakse")
                .email("nethuni@example.com")
                .password("hashed-password")
                .createdAt(Instant.now())
                .build();
    }

    @Test
    void signup_throwsWhenEmailAlreadyExists() {
        SignupRequest request = new SignupRequest();
        request.setEmail("nethuni@example.com");
        request.setPassword("Password@123");
        request.setFirstName("Nethuni");
        request.setLastName("Rajapakse");

        when(userRepository.existsByEmail("nethuni@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.signup(request))
                .isInstanceOf(DuplicateEmailException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void signup_hashesPasswordBeforeSaving() {
        SignupRequest request = new SignupRequest();
        request.setEmail("new@example.com");
        request.setPassword("Password@123");
        request.setFirstName("New");
        request.setLastName("User");

        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(passwordEncoder.encode("Password@123")).thenReturn("hashed-value");

        authService.signup(request);

        verify(userRepository).save(argThat(user -> user.getPassword().equals("hashed-value")));
    }

    @Test
    void signin_succeedsWithCorrectPassword() {
        SigninRequest request = new SigninRequest();
        request.setEmail(existingUser.getEmail());
        request.setPassword("correct-password");

        when(userRepository.findByEmail(existingUser.getEmail())).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches("correct-password", existingUser.getPassword())).thenReturn(true);
        when(jwtService.generateAccessToken(any(), anyString()))
                .thenReturn(new JwtService.GeneratedToken("access-jwt", "access-jti", Instant.now().plusSeconds(900)));
        when(jwtService.generateRefreshToken(any()))
                .thenReturn(new JwtService.GeneratedToken("refresh-jwt", "refresh-jti", Instant.now().plusSeconds(604800)));

        AuthService.TokenPair result = authService.signin(request);

        assertThat(result.accessToken().token()).isEqualTo("access-jwt");
        assertThat(result.refreshToken().token()).isEqualTo("refresh-jwt");
        verify(refreshTokenStore).store(eq("refresh-jti"), eq(existingUser.getId().toString()), any());
    }

    @Test
    void signin_failsWithWrongPassword() {
        SigninRequest request = new SigninRequest();
        request.setEmail(existingUser.getEmail());
        request.setPassword("wrong-password");

        when(userRepository.findByEmail(existingUser.getEmail())).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches("wrong-password", existingUser.getPassword())).thenReturn(false);

        assertThatThrownBy(() -> authService.signin(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void signin_failsWhenUserDoesNotExist() {
        SigninRequest request = new SigninRequest();
        request.setEmail("nobody@example.com");
        request.setPassword("whatever");

        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.signin(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void signout_denylistsAccessTokenAndRevokesRefreshToken() {
        Claims accessClaims = mock(Claims.class);
        when(accessClaims.getId()).thenReturn("access-jti");
        when(accessClaims.getExpiration()).thenReturn(java.util.Date.from(Instant.now().plusSeconds(900)));

        Claims refreshClaims = mock(Claims.class);
        when(refreshClaims.getId()).thenReturn("refresh-jti");

        when(jwtService.parseClaims("access-jwt")).thenReturn(accessClaims);
        when(jwtService.parseClaims("refresh-jwt")).thenReturn(refreshClaims);

        authService.signout("access-jwt", "refresh-jwt");

        verify(tokenDenylistService).denylist(eq("access-jti"), any());
        verify(refreshTokenStore).revoke("refresh-jti");
    }

    private static <T> T eq(T value) {
        return org.mockito.ArgumentMatchers.eq(value);
    }
}
