/** Maps capability names to Capability objects and builds well-known discovery config. */

import type { Capability } from "../types/capabilities.js";
import type { AgentConfiguration } from "../types/protocol.js";

export class CapabilityRegistry {
    private readonly caps = new Map<string, Capability>();

    register<TIn, TOut>(cap: Capability<TIn, TOut>): this {
        if (this.caps.has(cap.name)) {
            throw new Error(`CapabilityRegistry: capability "${cap.name}" is already registered`);
        }
        this.caps.set(cap.name, cap as Capability);
        return this;
    }

    get(name: string): Capability | undefined {
        return this.caps.get(name);
    }

    list(): Capability[] {
        return Array.from(this.caps.values());
    }

    has(name: string): boolean {
        return this.caps.has(name);
    }

    get size(): number {
        return this.caps.size;
    }

    buildWellKnownConfig(
        issuer: string,
        providerName: string,
        endpointPrefix = "",
        opts?: { description?: string; jwks_uri?: string }
    ): AgentConfiguration {
        return {
            version: "1.0-draft",
            provider_name: providerName,
            ...(opts?.description ? { description: opts.description } : {}),
            issuer,
            algorithms: ["Ed25519"],
            modes: ["delegated", "autonomous"],
            approval_methods: ["device_authorization"],
            endpoints: {
                register: `${endpointPrefix}/agent/register`,
                capabilities: `${endpointPrefix}/capability/list`,
                describe_capability: `${endpointPrefix}/capability/describe`,
                execute: `${endpointPrefix}/capability/execute`,
                status: `${endpointPrefix}/agent/status`,
                reactivate: `${endpointPrefix}/agent/reactivate`,
                revoke: `${endpointPrefix}/agent/revoke`,
                rotate_key: `${endpointPrefix}/agent/rotate-key`,
                request_capability: `${endpointPrefix}/agent/request-capability`,
                introspect: `${endpointPrefix}/agent/introspect`,
            },
            default_capabilities: Array.from(this.caps.keys()),
            ...(opts?.jwks_uri ? { jwks_uri: opts.jwks_uri } : {}),
        };
    }
}
