package com.detrasoft.framework.security.model;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JwtPayload implements UserDetails {
    private String userId;
    private String username;
    private List<SimpleGrantedAuthority> authorities;
    private String password;
    private String firstName;
    private String lastName;
    private UserType type;
    private Long detrasoftId;
    private String urlImg;
    private String urlHome;
    private String business;
    private SessionStatus status;
}
