package com.detrasoft.framework.security.dtos;

import java.io.Serializable;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Configuracao de usuario transportada no access token.
 *
 * Deliberadamente NAO implementa GenericDTO e nao tem `toDto`: a versao
 * original vivia junto das entidades do authorization-server e fazia cast para
 * `com.detrasoft.authorization.domain.entities.UserConfig`, o que amarrava o
 * framework ao dominIo de um servico especifico. Aqui e um POJO puro -- o
 * framework nao deve conhecer entidade de ninguem.
 */
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserConfigDTO implements Serializable {
    private UUID id;
    private String name;
    private String value;
}
