package com.chitanta.springbackend.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public enum Role {
    ADMIN(Set.of(
            Permission.ADMIN_READ,
            Permission.ADMIN_UPDATE,
            Permission.ADMIN_DELETE,
            Permission.ADMIN_CREATE,
            Permission.MANAGER_CREATE,
            Permission.MANAGER_READ,
            Permission.MANAGER_UPDATE,
            Permission.MANAGER_DELETE
    )),
    MANAGER(Set.of(
            Permission.MANAGER_CREATE,
            Permission.MANAGER_READ,
            Permission.MANAGER_UPDATE,
            Permission.MANAGER_DELETE
    )),
    USER(Collections.emptySet())
    ;

    /**
     * Spring authorities always have this prefix
     */
    private final String AUTHORITY_PREFIX = "ROLE_";
    @Getter
    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = getPermissions()
                .stream()
                .map((permission) -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        //converts enum into authority
        authorities.add(new SimpleGrantedAuthority(AUTHORITY_PREFIX + this.name()));

        return authorities;
    }
}
