# AdGuard Hotdeal Focus architecture

## Ubiquitous language and boundaries

- **Standalone Reader Gate** — the only installed runtime and public executable artifact: `hotdeal-focus.user.js`.
- **Content Contract** — one atomic site/layout/profile variant defining the page root, title, optional purchase boundary, body, comment mount, comment items, controls, and ignored comment chrome.
- **Projection** — the exact original DOM node identities that a Content Contract owns and may reveal.
- **Profile-complete proof** — live evidence for every applicable profile. A desktop/mobile layout is not promotable until both profiles independently satisfy the sample contract.
- **Release Gate** — the GitHub-hosted deterministic build, proof, promotion, and Pages attestation pipeline.

Runtime, content configuration, candidate discovery, release publication, and Windows deployment are separate bounded contexts. Canonical JSON and exact DTOs cross those boundaries; browser or infrastructure objects do not.

The configured Algumon source catalog contains seven identities: Clien, Ppomppu, Ruliweb, QuasarZone, Eomisae, ZOD, and Arca Live. Cloud collection checks this inventory explicitly. Desktop and mobile contracts remain distinct proof profiles even when they share selectors.

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
  PREFLIGHT -- one complete projection --> VALIDATING -- atomic release --> ACTIVE
      |                                       |                            |
      +-- unresolved -------------------------+-- cannot retain content ---+
      v
  ORIGINAL CONTENT + STATIC NOISE FILTERING -- valid preflight --> VALIDATING
```

The bootstrap lock is temporary, never a terminal error presentation. Failed
preflight restores the original content with static noise filtering inside the
same Userscript. Preflight remains debounced and can activate a later complete
projection. Runtime failures retain an intact verified projection when possible;
otherwise they restore original content and remove the reader UI and lock.

1. An inline `!important` bootstrap lock is claimed at `document-start`, before page paint.
2. `GM_addElement` installs a nonce-bound runtime stylesheet that remains effective under strict CSP.
3. A two-frame standalone cascade proof checks stylesheet identity, CSSOM, computed visibility, and an unowned adversarial probe. There is no external ExtendedCSS callback.
4. The known layouts must resolve one distinct complete Projection. If they do not, bounded independent semantic discovery may resolve the current document instead; it does not edit the installed contract or publish an update.
5. Releasing the bootstrap lock and forcing a full computed-style, top-layer, backdrop, and ownership scan occur in the same task. Containment failures cannot leave the article permanently hidden.
6. Mutation, stylesheet, URL-change, shadow-root, animation-frame, and top-layer sentinels continuously revalidate the active document.

`window.onurlchange`, native `hashchange`/`popstate`, and a bounded URL poll
revalidate the article identity. A different identity is not silently granted
the previous article's projection authority. A valid retained projection may
resume; an invalid projection returns to readable publisher content.

Static recovery is not a successful zero-noise proof. It hides known structural
noise without hiding matching title, purchase, body, or comment roots and their
ancestors/descendants. Unknown noise can remain in recovery; diagnostics report
`recovery`, not `ready`. No separate user filter is required.

## Original DOM preservation

The gate marks existing nodes; it does not clone, flatten, replace, or rewrite article and comment content. Preserved nodes retain their event listeners, links, images, tables, nested replies, and layout semantics.

Ancestor shells stay hidden. Only nonce-owned descendants become visible, and every unowned sibling remains suppressed. Direct ancestor text, pseudo-content, advertisements, sidebars, recommendations, headers, footers, and later injected widgets therefore stay unavailable.

A known-layout resolution starts from the publisher's currently rendered page
root, title, body, and comment mount. Hidden responsive copies and textless title
decorations are not competing visible articles. A nonempty visible title within
that unique structure is accepted even when it is one word, or when social
metadata is missing or stale after an edit. Metadata disagreement alone is not
a reason to hide a structurally identified article. Independent discovery of an
unknown structure retains its separate title and structural evidence checks.

Within the comment mount, nodes selected for preservation are classified as:

- a preserved comment/reply item,
- an approved comment control,
- explicitly ignored comment chrome that remains hidden.

Every observed loaded comment/reply must be accounted for; a real reply outside
the selected item set is not silently omitted. Unrelated publisher children can
remain unowned and hidden without disqualifying an otherwise complete article.
The known-layout comment count comes from the loaded DOM, not from equality with
a header, crawler snapshot, or aggregate total. Such totals may include deleted
comments, hidden replies, or other pages. Native pagination and continuation
controls are preserved, and permitted stable empty mounts are valid. The
independent semantic and cloud discovery paths keep their own stricter evidence
checks; these are not additional count requirements on a known-layout reader.

Purchase information is resolved according to the layout's declared boundary
and cardinality; genuinely competing purchase roots remain ambiguity. Original
article links and product content are not rewritten into a separate reader copy.

## Runtime entry and cloud Algumon provenance

The installed script matches the seven destination sites, not Algumon. It does
not intercept Algumon clicks, fetch signed relays, create a popup, attach a
fragment seed, or make its own network requests. Normal navigation follows the
publisher and Algumon links unchanged.

A registered hot-deal route with an article identity can start runtime discovery
without an Algumon referrer, including direct visits and mobile redirects that
drop the referrer. An unregistered route requires an exact HTTPS Algumon referrer
before bounded discovery is attempted. Entry eligibility does not itself reveal
the page: one complete projection and the rendering checks must still pass.

Signed relay provenance is instead a **cloud collection and promotion** boundary
in `scripts/audit_pages.mjs`. Collection reads server-rendered documents with
page JavaScript blocked. A missing interactive source picker is recorded as
`source-picker-unavailable`, not mistaken for a broken seven-source inventory.
When a picker is present, its inventory is checked; either way, all seven
configured sources require their own validated filtered feeds. Unknown or
contradictory source identities are rejected.

The collector accepts the current
`/n/d/<id>?v=<32-hex>&t=<13-digits>&enc=v1.<base64url>.<base64url>.<base64url>`
and the earlier `/l/d/<id>?v=<32-hex>&t=<13-digits>` relay forms. It records the
response hash, destination, acquisition time, and profile landing. Only cookies
from the ephemeral collection context are passed in memory to the private
resolver; no user browser session is read, and cookies are not logged or included
in evidence. A bounded successful relay response must name one accepted HTTPS
destination consistently. Redirects are not followed: an HTTP 302 to an internal
detail page, malformed content, ambiguity, or an out-of-site destination is
rejected. These observations and audit-only seed data are evidence for the
independent cloud oracle, not a fragment or authorization token required by an
installed reader.

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

Runtime and cloud discovery have different purposes. When registered selectors
do not resolve the page, runtime can call `resolveIndependentSemanticDocument`
to obtain a bounded complete projection for that document. It neither contacts
GitHub nor saves new selectors. The cloud audit runs the verified script's
semantic discovery independently in an isolated execution world, adds the
recorded source/profile evidence, and may propose a persistent contract update.

The oracle explores bounded complete tuples `Projection(title, product?, body, comments)`. It rejects disconnected roles, multiple equally valid tuples, escaped comment items, body noise, unstable empty mounts, candidate-budget overflow, or ambiguous route wildcards.

A candidate can be promoted only when:

1. The registered contract does not resolve an approved projection, the audit records a failed or previously unregistered route, and the independent proposal resolves exactly one candidate projection. A blank page or zero visible publisher content is not a prerequisite for discovery.
2. `proofProfiles` equals `applicableProfiles` exactly.
3. Each applicable desktop/mobile profile has at least three fresh-at-acquisition, distinct Algumon relay article proofs with the same semantic shape.
4. New routes have at least three exact redirect-chain proofs and one delimiter-bounded wildcard contract.
5. Title identity, role containment/order, purchase cardinality, and exhaustive comment classification pass fixed thresholds.
6. Historical June/July fixtures, all previously passing siblings, direct-negative samples, network fidelity, tamper, and zero-leak tests remain valid.
7. The isolated draft and proven release bytes recompute exactly.
8. The queue, result, evidence, and promotion objects satisfy their canonical digest-bound sealed schemas.

One candidate failing or timing out cannot starve another matrix member. The aggregator rejects duplicate, missing, extra, out-of-batch, malformed, or hash-mismatched evidence and selects at most the first proven candidate in canonical order. A rejected candidate does not replace the public release. This promotion boundary is separate from runtime's content-first recovery, where unknown noise can remain visible and is not reported as a successful reader projection.

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
- **Caching:** cache-busting release attestation; the last fully verified release remains active until a replacement passes verification.
- **Error tracking:** deterministic JSON evidence and drift issues without article/comment/account content.
- **Availability and recovery:** uncertain structure restores native article/comment readability with guarded static noise filtering, without claiming zero-noise coverage; rollback is a higher fully reverified release; local installation is transactional.
