package com.example.security.data.model;

import com.example.security.base.AlgorithmType;

public final class AlgorithmItem {

    private final AlgorithmType type;
    private final String        description;

    public AlgorithmItem(AlgorithmType type, String description) {
        this.type        = type;
        this.description = description;
    }

    public AlgorithmType getType()        { return type;                   }
    public String        getName()        { return type.getDisplayName();  }
    public String        getDescription() { return description;            }
}
