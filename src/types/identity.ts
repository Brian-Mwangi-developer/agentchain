// ─── Agent Identity Types ─────────────────────────────────────────────────────

export type AgentConfig = {
   
    agentName: string;
   
    hostname: string;
  
    capabilities: string[];
    /**
     * Optional AES-256-GCM encryption key (64 hex chars = 32 bytes).
     * If omitted, a random key is generated per session.
     * Provide this if you need to persist and reload audit logs.
     */
    encryptionKey?: string;
};

export type CapabilityGrant = {
    capability: string;
    grantedAt: number;    
    constraints?: CapabilityConstraints;
};


export type CapabilityConstraints = Record<string, ConstraintValue>;

export type ConstraintPrimitive = string | number | boolean;

export type ConstraintOperator = {
    max?: number;
    min?: number;
    in?: ConstraintPrimitive[];
    not_in?: ConstraintPrimitive[];
};

export type ConstraintValue = ConstraintPrimitive | ConstraintOperator;

export type RegisteredAgent = {
    agentId: string;       
    agentName: string;
    hostname: string;
    publicKeyJwk: JsonWebKey;
    thumbprint: string;    
    capabilities: CapabilityGrant[];
    registeredAt: number;   
};
