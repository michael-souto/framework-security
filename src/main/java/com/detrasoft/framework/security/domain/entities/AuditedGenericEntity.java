package com.detrasoft.framework.security.domain.entities;

import com.detrasoft.framework.core.context.GenericContext;
import com.detrasoft.framework.crud.entities.Audit;
import com.detrasoft.framework.crud.entities.GenericEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.persistence.Embedded;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.time.Instant;

@MappedSuperclass
@Getter
@Setter
public abstract class AuditedGenericEntity extends GenericEntity {

    @Embedded
    private com.detrasoft.framework.crud.entities.Audit audit = new Audit();

    @PostLoad
    public void onPostLoad() {
        if (audit == null) {
            audit = new Audit();
        }
    }
    
    @PrePersist
    public void prePersist() {
        audit.setCreatedAt(Instant.now());
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            audit.setUserCreated(GenericContext.getContexts("userId").toString());
        } else {
            audit.setUserCreated("anonymousUser");
        }
    }

    @PreUpdate
    public void preUpdate() {
        audit.setUpdatedAt(Instant.now());
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            audit.setUserUpdated(GenericContext.getContexts("userId").toString());
        } else {
            audit.setUserUpdated("anonymousUser");
        }
    }
}
