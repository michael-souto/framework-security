package com.detrasoft.framework.security.domain.dtos;

import com.detrasoft.framework.crud.entities.Audit;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuditedGenericDTO {
    private Audit audit = new Audit();
}
