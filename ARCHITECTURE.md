# AdGuard Hotdeal Focus architecture

## Ubiquitous language and boundaries

- **Standalone Reader Gate** — the only installed runtime and public executable artifact: `hotdeal-focus.user.js`.
- **Content Contract** — one atomic site/layout/profile variant defining the page root, title, optional purchase boundary, body, comment mount, comment items, controls, and ignored comment chrome.
- **Projection** — the exact original DOM node identities that a Content Contract owns and may reveal.
- **Profile-complete proof** — live evidence for every applicable profile. A desktop/mobile layout is not promotable until both profiles independently satisfy the sample contract.
- **Release Gate** — the GitHub-hosted deterministic build, proof, promotion, and Pages attestation pipeline.

Runtime, content configuration, candidate discovery, release publication, and Windows deployment are separate bounded contexts. Canonical JSON and exact DTOs cross those boundaries; browser or infrastructure objects do not.

Seven Algumon sources are exact and exhaustive: Clien, Ppomppu, Ruliweb, QuasarZone, Eomisae, ZOD, and Arca Live. Desktop and mobile contracts remain distinct proof profiles even when they share selectors.

## Single runtime authority

The Userscript is installed from one stable URL:

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

`@downloadURL` and `@updateURL` equal that URL. The stable `@name` and `@namespace` identify the extension, while a strict numeric `x.y.z` `@version` provides monotonic updates. The compiled script contains its canonical Content Contracts; it does not fetch a second mutable configuration.

No custom filter participates in locking, release, installation, update, or proof. The historical `gate-v2.0.2` asset remains remote only to avoid breaking old subscribers. It is not published to Pages and cannot block current releases.

## Browser state machine

```text
document-start
    |
    v
  LOCKED -- exact seed + one projection --> VALIDATING -- atomic release --> ACTIVE
    ^                                         |                            |
    |                                         +-- missing / ambiguous -----+
    +--------- URL / DOM / CSS / ownership / top-layer mutation -----------+
```

`LOCKED` is the default and terminal error state.

1. An inline `!important` bootstrap lock is claimed at `document-start`, before page paint.
2. `GM_addElement` installs a nonce-bound runtime stylesheet that remains effective under strict CSP.
3. A two-frame standalone cascade proof checks stylesheet identity, CSSOM, computed visibility, and an unowned adversarial probe. There is no external ExtendedCSS callback.
4. Exactly one Content Contract must resolve one complete Projection.
5. Releasing the bootstrap lock and forcing a full computed-style, top-layer, backdrop, and ownership scan occur in the same task. Any leak synchronously restores the lock before paint.
6. Mutation, stylesheet, URL-change, shadow-root, animation-frame, and top-layer sentinels continuously revalidate the active document.

`window.onurlchange` is the authoritative AdGuard SPA signal; native `hashchange` and wrapped History API events provide additional coverage. A different article identity or unknown route terminally locks the current document. The same document does not rediscover after a terminal failure.

## Original DOM preservation

The gate marks existing nodes; it does not clone, flatten, replace, or rewrite article and comment content. Preserved nodes retain their event listeners, links, images, tables, nested replies, and layout semantics.

Ancestor shells stay hidden. Only nonce-owned descendants become visible, and every unowned sibling remains suppressed. Direct ancestor text, pseudo-content, advertisements, sidebars, recommendations, headers, footers, and later injected widgets therefore stay unavailable.

A comment mount is complete only when every meaningful descendant belongs to exactly one of:

- a preserved comment/reply item,
- an approved comment control,
- explicitly ignored comment chrome that remains hidden.

One known comment plus one newly shaped reply is a failure, not an incomplete visible thread. Optional purchase information has exact zero-or-one or required cardinality; two candidates are ambiguity.

## Algumon provenance

The Algumon source picker must contain the configured seven identities exactly once. Missing, duplicate, unknown, eighth, or contradictory identities produce no relay target and no candidate.

On explicit activation of one exact signed `/l/d/<id>?v=<32-hex>&t=<13-digits>` relay, the script performs one credentialed same-origin fetch. It accepts only a 200 response whose inertly parsed document contains one whole-string redirect script and one anchor naming the same allowlisted HTTPS destination. Credentials, fragments, non-default ports, parser ambiguity, popup failure, or host mismatch fail closed with no secondary carrier.

The destination receives a bounded expiring fragment seed and removes it at `document-start`. Authorization requires agreement among seed site type, URL route, article identity, title core, article metadata, and the complete structural Projection. The seed contains no body, comments, account state, cookies, or tokens and is insufficient by itself.

## Deterministic adaptation without AI

Once each Monday at 03:17 KST (Sunday 18:17 UTC), the scheduled workflow performs one bounded source collection:

```text
exact Algumon inventory
→ desktop/mobile relay acquisition
→ semantic candidate generation
→ isolated userscript-only build
→ profile-complete live proof
→ historical + tamper + zero-leak regression
→ one-parent allowlisted commit
→ deploy-key fast-forward promotion
→ Pages monotonic preflight
→ Pages deployment
→ live HTTPS byte attestation
```

The only live Algumon source pass has an exact request-start budget of 29: one
global inventory, one source document for each of the seven identities, and
three signed relays per identity. Candidate proof and promotion retest consume
the immutable `base-audit-report.json` snapshot and therefore start zero
additional Algumon requests. Freshness is checked against the recorded,
canonical relay acquisition time, not by refetching a signed relay later.
Manual dispatch is allowed for an operator, but no workflow self-dispatches
`watch-dom.yml`; remaining drift waits for the next bounded scheduled pass.

The semantic oracle generates candidates only. Runtime never falls back to it.

The oracle explores bounded complete tuples `Projection(title, product?, body, comments)`. It rejects disconnected roles, multiple equally valid tuples, escaped comment items, body noise, unstable empty mounts, candidate-budget overflow, or ambiguous route wildcards.

A candidate can be promoted only when:

1. The current release failed closed with zero visible nodes and zero flash frames.
2. `proofProfiles` equals `applicableProfiles` exactly.
3. Each applicable desktop/mobile profile has at least three fresh-at-acquisition, distinct Algumon relay article proofs with the same semantic shape.
4. New routes have at least three exact redirect-chain proofs and one delimiter-bounded wildcard contract.
5. Title identity, role containment/order, purchase cardinality, and exhaustive comment classification pass fixed thresholds.
6. Historical June/July fixtures, all previously passing siblings, direct-negative samples, network fidelity, tamper, and zero-leak tests remain valid.
7. The isolated draft and proven release bytes recompute exactly.
8. The queue, result, evidence, and promotion objects satisfy their canonical digest-bound sealed schemas.

One candidate failing or timing out cannot starve another matrix member. The aggregator rejects duplicate, missing, extra, out-of-batch, malformed, or hash-mismatched evidence and selects at most the first proven candidate in canonical order. Uncertainty can reduce availability, but cannot expose noise.

## Release and update contract

The schema-v2 public manifest has one executable artifact:

```json
{
  "schemaVersion": 2,
  "status": "release-ready",
  "installUrl": "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js",
  "artifacts": {
    "hotdeal-focus.user.js": {
      "version": "x.y.z",
      "bytes": 1,
      "sha256": "…",
      "canonicalTextSha256": "…"
    }
  }
}
```

Pages publishes exactly the Userscript and manifest. Before deployment, the pipeline reads the live Pages bundle:

- identical script bytes require the same version;
- different bytes require a strictly higher version;
- a downgrade or same-version replacement is rejected.

After deployment, bounded cache-busting HTTPS polling must observe exact manifest and Userscript SHA-256 values before the job succeeds. The exact schema-v1 predecessors `0.3.6` (current Pages bytes) and `0.5.5` (default-branch source predecessor) are accepted only through a one-time migration contract that pins both full manifest bytes and Userscript bytes; every other v1 bundle is rejected.

Rollback is forward-only. A last-known-good body must pass the current desktop/mobile live suite again and is then republished under a higher version with `rollback_of` evidence. Clients are never pointed to a lower version or mutable historical URL.

The real updater trust boundary is the protected GitHub workflow plus the HTTPS Pages origin. Internal SHA-256 objects are described as digest-bound or sealed, not cryptographic signatures. An optional GitHub OIDC artifact attestation can strengthen audit evidence, but AdGuard itself does not validate that attestation during extension update.

## GitHub control plane

The Python JSON-only CLI is the agent control surface for build, verification, evidence, cloud configuration, deployment, and rollback. It invokes fixed argument-vector commands, separates logs from stdout, rejects ambiguous paths and archives, and binds releases to exact clean Git commits.

Protected automation retains only the authorities needed by the single-artifact design:

- default-branch PR/verified-CI and fast-forward history rules,
- the `hdf-main-automation` deploy-key environment for one-parent promotions,
- the `github-pages` environment for Pages publication,
- exact workflow and enable-variable state.

The former `publish-gate` workflow, immutable-filter tag creation, tag-freeze rulesets, and filter-release publisher are not part of the active cloud contract. An existing old tag/release may remain untouched as archival compatibility for old subscribers.

Live-browser proof and secret-bearing push run on separate fresh runners. The push runner revalidates the Git bundle, parent, changed-path allowlist, committed hashes, manifest, and current remote-head lease before exposing the repository-scoped Ed25519 deploy key. Pages writers share the release mutex and recheck the head before and after deployment.

## Windows deployment boundary

Normal Windows `deploy` and `verify` are Userscript-only. They:

1. validate strict UTF-8 source, exact metadata, schema-v2 manifest, raw and canonical hashes;
2. inspect global protection and capture a durable backup;
3. install or update the one exact manual Userscript;
4. verify enabled state, code hash, GM-properties hash, version, URL, and grants;
5. prove the complete User filter and every non-target subscription inventory remained byte-for-byte and rule-hash identical.

Normal deployment never calls legacy domain-scope migration, never disables User rules, and never installs a filter subscription. Any failure rolls the target Userscript back from the journaled backup. Secrets used for the local AdGuard IPC session remain in memory and never enter JSON, logs, or evidence.

## Security and availability posture

- **Auth and permissions:** least-privilege GitHub job permissions, protected environments, one repository-scoped deploy key, no committed secrets.
- **Hosting and CDN:** GitHub Pages HTTPS, monotonic preflight, live post-deploy byte attestation.
- **CI/CD:** pinned Actions, fixed runner images, reproducible builds, serialized writers, exact head leases.
- **Rate limiting:** bounded relay fetches, candidates, retries, screenshots, artifact bytes, and retention.
- **Caching:** cache-busting release attestation; stale safe versions remain fail-closed.
- **Error tracking:** deterministic JSON evidence and drift issues without article/comment/account content.
- **Availability and recovery:** uncertainty locks the page; rollback is a higher fully reverified release; local installation is transactional.
