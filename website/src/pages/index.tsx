import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import styles from './index.module.css';

const features = [
  {
    title: 'Cryptographic Identity',
    description: 'Ed25519 keypairs for every Host and Agent. JWK thumbprints as stable IDs. Full delegation chain verification on every call.',
  },
  {
    title: '11-Step Verification',
    description: 'Every capability call mints a signed JWT and passes through 11 verification steps — signature, replay protection, grant check, constraint enforcement — before your code runs.',
  },
  {
    title: 'Grant Constraints',
    description: 'Field-level constraints on call arguments: max, min, in, not_in, exact equality. Required fields from the schema are enforced. No reasoning required — the gate holds.',
  },
  {
    title: 'Access Requests',
    description: 'When an agent is denied, the call suspends and waits for human approval out-of-band. HMAC-verified codes, 4 approval scopes, tamper-proof rule storage.',
  },
  {
    title: 'Encrypted Audit Trail',
    description: 'AES-256-GCM in-memory ring buffer. Every call, denial, and error recorded with auth overhead. Drain to any HTTP endpoint or custom exporter.',
  },
  {
    title: 'Zero Dependencies',
    description: 'Ships ESM + CJS. Everything defaults to in-memory. External systems (Redis, databases) are adapter-injected by you. Node.js 18+ only.',
  },
];

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <p style={{fontSize: '1rem', opacity: 0.7, marginBottom: '1.5rem'}}>
          Zero-dependency security layer for AI agent systems
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/getting-started">
            Get Started
          </Link>
          <Link
            className="button button--outline button--lg"
            style={{marginLeft: '1rem', color: '#fff', borderColor: 'rgba(255,255,255,0.4)'}}
            href="https://www.npmjs.com/package/agents-chain">
            npm install agents-chain
          </Link>
        </div>
      </div>
    </header>
  );
}

function Feature({title, description}: {title: string; description: string}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="padding-horiz--md padding-vert--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="Identity, auth & audit for AI agents"
      description="Lightweight security layer for AI agent SDKs. Ed25519 identity, JWT auth, constraint enforcement, encrypted audit, and human-in-the-loop access requests.">
      <HomepageHeader />
      <main>
        <section className={styles.features}>
          <div className="container">
            <div className="row">
              {features.map((props, idx) => (
                <Feature key={idx} {...props} />
              ))}
            </div>
          </div>
        </section>
        <section style={{textAlign: 'center', padding: '2rem 0 3rem'}}>
          <p style={{opacity: 0.6, fontSize: '0.9rem'}}>
            Sponsored by{' '}
            <a href="https://melduo.com" target="_blank" rel="noopener noreferrer">
              Melduo
            </a>
          </p>
        </section>
      </main>
    </Layout>
  );
}
