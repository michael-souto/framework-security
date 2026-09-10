package com.detrasoft.framework.security.dtos;

import java.io.Serializable;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Favorito de usuario transportado no access token.
 *
 * Mesmo caso do {@link UserConfigDTO}: a versao original convertia por reflexao
 * a partir de uma entidade de outro servico. Aqui e um POJO puro, e quem tem a
 * entidade e quem monta o DTO.
 */
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserFavoriteDTO implements Serializable {
    private UUID id;
    private UUID userId;
    private String name;
    private String url;
    private String route;
    private String feature;
    private UUID entityId;
    private String icon;
    private Integer ordering;
    private String system;
}
