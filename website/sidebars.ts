import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'getting-started',
    {
      type: 'category',
      label: 'Core Concepts',
      collapsed: false,
      items: [
        'concepts/host-and-agent',
        'concepts/capabilities',
        'concepts/grants-and-constraints',
        'concepts/verification-pipeline',
        'concepts/audit-log',
        'concepts/context-awareness',
      ],
    },
    {
      type: 'category',
      label: 'Access Requests',
      collapsed: false,
      items: [
        'access-requests/overview',
        'access-requests/approval-scopes',
        'access-requests/security-model',
      ],
    },
    {
      type: 'category',
      label: 'Advanced',
      items: [
        'advanced/identity-persistence',
        'advanced/store-adapters',
        'advanced/sdk-wrappers',
        'advanced/well-known-discovery',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [
        'api/appchain-config',
        'api/types',
        'api/error-codes',
      ],
    },
    {
      type: 'category',
      label: 'Examples',
      items: [
        'examples/basic-service',
        'examples/sms-gateway',
        'examples/access-request-flow',
      ],
    },
    'architecture',
    'agent-guide',
  ],
};

export default sidebars;
