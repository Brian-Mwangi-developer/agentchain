import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'agents-chain',
  tagline: 'Identity, auth, and audit for AI agent systems',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://brian-mwangi-developer.github.io',
  baseUrl: '/agentchain/',

  organizationName: 'Brian-Mwangi-developer',
  projectName: 'agentchain',

  onBrokenLinks: 'throw',

  markdown: {
    mermaid: true,
  },

  themes: ['@docusaurus/theme-mermaid'],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl:
            'https://github.com/Brian-Mwangi-developer/agentchain/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'agents-chain',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/docs/examples/basic-service',
          label: 'Examples',
          position: 'left',
        },
        {
          href: 'https://www.npmjs.com/package/agents-chain',
          label: 'npm',
          position: 'right',
        },
        {
          href: 'https://github.com/Brian-Mwangi-developer/agentchain',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting Started', to: '/docs/getting-started'},
            {label: 'API Reference', to: '/docs/api/appchain-config'},
            {label: 'Examples', to: '/docs/examples/basic-service'},
          ],
        },
        {
          title: 'Links',
          items: [
            {label: 'GitHub', href: 'https://github.com/Brian-Mwangi-developer/agentchain'},
            {label: 'npm', href: 'https://www.npmjs.com/package/agents-chain'},
          ],
        },
        {
          title: 'Sponsored by',
          items: [
            {label: 'Melduo', href: 'https://melduo.com'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} agents-chain. Built with Docusaurus. Sponsored by <a href="https://melduo.com" target="_blank">Melduo</a>.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'json'],
    },
    mermaid: {
      theme: {light: 'neutral', dark: 'dark'},
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
