package com.detrasoft.framework.security.domain.entities;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import java.time.Instant;

@Data
@Embeddable
public class Audit {

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE", updatable = false)
    private Instant createdAt;
    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Instant updatedAt;

    @Column(updatable = false)
    private String userCreated;
    private String userUpdated;
}
