package com.chitanta.springbackend.auth;

import com.chitanta.springbackend.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String email;
    private String firstname;
    private String lastname;
    private Role role;
}
