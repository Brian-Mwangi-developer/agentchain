/**
 * CapabilityRegistry — registers Capability objects and generates well-known config.
 *
 * When building an AppChain, you register all capabilities the app exposes.
 * The registry is then used by the app-wrapper Proxy to gate calls and by
 * well-known.ts to generate the discovery config.
 */

import type { Capability } from "../types/capabilities.js";
import type { AgentConfiguration } from "../types/protocol.js";

export class CapabilityRegistry {
    private readonly caps = new Map<string, Capability>();

    /**
     * Register a capability. Chainable.
     * Throws if a capability with the same name is already registered.
     */
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

    /**
     * Build an AgentConfiguration object suitable for serving at
     * GET /.well-known/agent-configuration.
     *
     * Endpoint paths match the agent-auth protocol spec (1.0-draft).
     * Consumers are responsible for implementing these routes in their server.
     *
     * @param issuer         The base URL of the server (e.g. "https://billing.mycompany.com")
     * @param providerName   Short name for the app (e.g. "billing-service")
     * @param endpointPrefix Optional prefix for endpoint paths (default: "")
     * @param opts           Optional fields: description, jwks_uri
     */
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
