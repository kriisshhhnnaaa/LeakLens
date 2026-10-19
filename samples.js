/*
 * LeakLens — samples: realistic but unmistakably fictional fixtures.
 *
 * Domains are IETF-reserved, addresses come from RFC 5737 documentation
 * ranges, and credential-like values spell out that they are not real.
 * Never replace these with values copied from real systems, provider
 * documentation, or public repositories.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.LeakLensSamples = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  return [
    {
      id: 'config',
      name: 'Config snippet',
      blurb: 'Env-style assignments: one long API key, one obvious placeholder.',
      text: [
        '# deploy.env for the demo service (all values fake)',
        'SERVICE_NAME=invoice-worker',
        'API_KEY=FAKE-NOT-A-REAL-SECRET-4f8a2c9e17b3d605',
        'API_KEY=YOUR_API_KEY_HERE',
        'REGION=eu-west-1'
      ].join('\n'),
      expect: { contains: [{ ruleId: 'api-key-assignment', min: 2 }] }
    },
    {
      id: 'error-log',
      name: 'Error log',
      blurb: 'A log line with a fictional email and a documentation-range IP address.',
      text: [
        '2026-03-14 09:21:07 ERROR  worker-3 retry failed (attempt 4/5)',
        '  user jane.doe+ops@example.test could not reach 192.0.2.128:8443',
        '  will retry in 30s'
      ].join('\n'),
      expect: {
        contains: [
          { ruleId: 'email-address', min: 1 },
          { ruleId: 'ipv4-address', min: 1 }
        ]
      }
    },
    {
      id: 'database-uris',
      name: 'Database connection strings',
      blurb: 'Two URIs with fictional credentials; one embeds a loopback address (nested finding).',
      text: [
        'DATABASE_URL=postgres://demo_user:FAKE_PW_not_real@db.internal.example:5432/app',
        'CACHE_URL=redis://cache_user:also_not_a_real_pw@127.0.0.1:6379/0'
      ].join('\n'),
      expect: {
        contains: [
          { ruleId: 'database-uri-credentials', min: 2 },
          { ruleId: 'ipv4-address', min: 1 }
        ]
      }
    },
    {
      id: 'auth-header',
      name: 'Authorization headers',
      blurb: 'A Bearer header with a fabricated token, and a JWT-shaped value (merged finding).',
      text: [
        'curl -H "Authorization: Bearer SK_FAKE_9c81b2e4f7a6d5c3b201" \\',
        '     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vIn0.FAKE_SIG_not_a_real_signature" \\',
        '     https://api.example.test/v2/invoices'
      ].join('\n'),
      expect: {
        contains: [
          { ruleId: 'bearer-token', min: 2 },
          { ruleId: 'jwt-like-token', min: 1 }
        ]
      }
    },
    {
      id: 'harmless',
      name: 'Harmless team note',
      blurb: 'Plain prose with no credential-shaped content. Expected: no findings at all.',
      text: [
        'Team note — sprint 42',
        '',
        'The invoice worker now retries five times before paging.',
        'Docs live under /docs/worker; deployment notes are in the wiki.',
        'Next review is Tuesday at 10:00 in room 4B.'
      ].join('\n'),
      expect: { none: true }
    },
    {
      id: 'vendor-keys',
      name: 'Vendor API keys',
      blurb: 'Provider-shaped tokens (OpenAI, Slack, Google, Stripe) — all fabricated.',
      text: [
        '# fictional provider keys for the demo (none are real)',
        'sk-proj-' + 'NOTREALKEY0123456789abcdefghijklmnopqrstuvwx',
        'xox' + 'b-012345678901-012345678901-NOTREAL0123456789abcdef',
        'AIza' + 'NOTREAL0123456789abcdefghijklmnopqrstuvw',
        'sk_test_' + 'NOTREAL0123456789abcdef'
      ].join('\n'),
      expect: { contains: [{ ruleId: 'vendor-api-key', min: 4 }] }
    },
    {
      id: 'private-keys',
      name: 'Private-key blocks',
      blurb: 'A complete synthetic block (Critical) and an unterminated one (Review) to show the boundary policy.',
      text: [
        '--- excerpt from a made-up tutorial ---',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIFakeNOTAREALKEYabcdefghij0123456789ABCDEFGH',
        'zz01NOTAREALKEYBODY2233445566778899aabbccdd',
        '-----END RSA PRIVATE KEY-----',
        '',
        'and an incomplete paste:',
        '-----BEGIN PRIVATE KEY-----',
        'MIIFakeALSO_NOT_A_REAL_KEY_qq11223344556677'
      ].join('\n'),
      expect: {
        contains: [{ ruleId: 'private-key-block', min: 2 }],
        severities: ['critical', 'review']
      }
    }
  ];
});
