# AdGuard Hotdeal Focus architecture

## Contract

The public contract is deliberately narrower than an ad-blocking list:

- **Reader Gate** is the browser-side state machine. It starts before page paint, validates one complete site/layout contract, projects only `title`, optional purchase information, `body`, and the complete comment/reply tree, and continuously revalidates the projection.
- **Content Contract** is one atomic layout variant. A title selector from one variant can never be combined with a body or comment selector from another.
- **Release Gate** is the GitHub-hosted proof pipeline. It may generate a candidate variant without AI, but it can publish that candidate only after every deterministic proof passes.

Seven Algumon sources are in scope: Clien, Ppomppu, Ruliweb, QuasarZone, Eomisae, ZOD, and Arca Live. Ppomppu desktop and mobile are separate layout families. Every configured layout must preserve the site's original DOM nodes; cloning, replacing, rewriting, or flattening article and comment nodes is forbidden.

## Browser state machine

```text
document-start
    |
    v
  LOCKED  -- one complete exact variant -->  VALIDATING  -- integrity proof -->  ACTIVE
    ^                                             |                              |
    |                                             +-- ambiguity / missing role --+
    +---------------- URL, marker, style, or ownership mutation ----------------+
```

`LOCKED` is the default and the error state. The AdGuard protocol filter prelocks every page on each target domain, including list, home, unknown, and unapproved routes. `ACTIVE` is reached only when one semantic projection class satisfies its exact route owner, page root, required-role cardinality, configured optional-role cardinality, containment, title and article identity, comment mount, full item/control/ignored classification, and ownership rules. Syntactically different variants that resolve to the exact same node identities and projection policy are aliases of one projection; two distinct projections are ambiguity and stay blank. An unknown route can be considered only on the initial navigation with a fresh validated Algumon seed and one exact additive path contract. Referrer and `window.name` are never authority.

Once active, the document is sealed. An exact new comment/reply subtree, an exact approved comment control, an exact ignored comment root, or an allowed lazy-media attribute on an already owned media element can be processed. Every other meaningful element or text insertion, character-data change, role identity/class/ID/data/ARIA/style/hidden/href mutation, role-root removal, SPA article change, marker removal, or style replacement synchronously enters a terminal lock. The same document never returns from terminal lock to discovery; only a fresh navigation document can attempt authorization again.

The filter is a small, stable protocol layer; it does not duplicate site selectors. The userscript owns selector meaning. This makes an old-filter/new-script or new-filter/old-script race either valid or blank, never an unfiltered page.

## DOM preservation and noise exclusion

The gate annotates original elements with private marker attributes. It does not insert wrappers into titles, replace text nodes, or reconstruct comments. Kept role roots remain in their original document position with their original event listeners, media, tables, links, computed layout, and nested replies.

Ancestor shells use `visibility: hidden`; only exact nonce-owned descendants are restored with `visibility: visible`. Unowned element children are `display: none`. This suppresses direct ancestor text, pseudo-elements, sidebars, advertisements, recommendations, and future sibling widgets without changing the source DOM. Title uses a seeded shallow projection; body and a separate purchase block use their exact atomic content boundaries; comments use exhaustive classified children. A purchase block may be required, absent because the purchase link is already inside the article body, or explicitly configured as zero-or-one. The null and one-node cases are different projection identities, so an unexpected second block is ambiguity rather than an accidental merge.

Comment mounts, items, controls, and explicitly ignored comment chrome are separate concepts. Ignored nodes participate in completeness and overlap checks but never receive ownership or keep markers. Any meaningful mount content outside those three classifications fails closed even when known items also exist, so a newly shaped reply cannot be silently hidden from an otherwise visible thread.

## Algumon provenance carrier

The current Algumon source picker is an exact global inventory contract: Clien, Ppomppu, Ruliweb, QuasarZone, Eomisae, ZOD, and Arca Live, each exactly once. The card root must expose one matching `/site-icon/<slug>.png` machine signal (and any explicit site-type signal must agree). A missing, duplicate, eighth, unknown, or contradictory source invalidates discovery and emits no draft.

On an activation of one exact signed `/l/d/<id>?v=<32-hex>&t=<13-digits>` URL, the userscript synchronously reserves the requested browsing context and performs one credentialed same-origin fetch of that exact URL. It accepts only a 200 response whose inertly parsed document contains exactly one whole-string redirect script and exactly one anchor, both naming the same external destination. The destination must be HTTPS, carry no credentials, non-default port, or fragment, and match the exact host allowlist for the card's site type. Only then is a bounded, expiring seed appended as a fragment to the verified final destination. Parser, network, popup, signature-shape, or host failure closes the reserved child and leaves Algumon in place; there is no secondary carrier.

The destination removes the seed fragment at `document-start`. Authorization requires the seed site type, exact URL route, initial non-null article identity, current article identity, source-title core, unique consistent article metadata, and full structural projection to agree. Same-identity query/hash normalization may revalidate. A different or null article identity clears pending authorization and terminally locks that document, including back navigation. The seed contains no body, comments, account state, cookies, or tokens and is insufficient by itself.

## Deterministic adaptation without AI

The scheduled GitHub workflow uses a side-effect-free semantic oracle only as a **candidate generator**, never as a runtime fallback. A candidate is eligible for promotion only when all of these hold:

1. A committed exact variant failed closed; no noisy page was exposed.
2. The same role boundaries and structural selectors are reproduced across at least three recent article URLs in each affected route/profile family.
3. Each affected layout/profile must provide its own three-URL proof. A failed desktop or mobile sibling is never treated as evidence for the candidate profile.
4. New routes have at least three distinct full Algumon `/l/d/<id>?…` redirect-chain proofs and derive exactly one nonempty delimiter-bounded wildcard token; runtime, builder, and auditor use the same non-crossing wildcard semantics.
5. Algumon title consistency, role containment, comment/reply structure, selector stability, and cardinality meet fixed thresholds. If Algumon has no source-qualified original-site comment count, the evidence records `countComparable:false` and requires stable exact comment selectors with at least two nonempty URLs per profile or three exact-empty proofs; it never substitutes a neutral score.
6. The immutable June/July regression corpus and every profile that passed in the frozen full audit remain non-regressed. Every already-failed sibling on the candidate site is also retested after materialization and must remain zero-leak—either safely readable under an exact contract or fully fail-closed; it does not block this single-profile promotion and is handled by the next serialized run.
7. Differential browser tests prove that the candidate exposes no node outside the approved role set and does not shrink or replace preserved DOM nodes.
8. The candidate payload, base configuration, generated files, and manifest hashes recompute exactly.

Only then does the builder append an atomic variant. Existing variants are not deleted automatically. Discovery freezes a canonical queue manifest binding the audited base commit, full-audit report hash, ordered candidate index/fingerprint, every draft hash, and the GitHub run number. The full queue remains signed, but one run exposes only an eight-item circular matrix batch derived from that run number. Consecutive run numbers cover the entire queue in finite rounds without unbounded job growth. Each selected candidate is proved in an independent matrix job, so timeout or failure cannot starve another member of the batch. The always-running aggregator completes each absent or unselected result as a canonical queue-bound `infrastructure-missing` non-proof, while any present duplicate, extra, out-of-batch, malformed, or hash-mismatched artifact blocks the entire promotion. It then selects exactly the first proven candidate in canonical queue order and creates one atomic promotion package.

The candidate is rebuilt in an isolated directory, checked against the frozen complete audit and all local regression fixtures, then live-retested on at least three Algumon URLs for exactly its affected layout/profile together with every sibling layout/profile on that site. Previously passing siblings must still pass; previously failed siblings may remain semantically failed only while the real post-candidate gate is zero-leak and either safely readable or fully blocked. After a successful candidate commit, the workflow serially dispatches one audit from the new head so the next site, layout, or profile can be promoted; this continuation depends on promotion state, not on Pages availability. Any missing, conflicting, ambiguous, noisy, rate-limited, or structurally unprovable evidence leaves the current release untouched and opens or updates a DOM-drift issue until a clean full audit closes it.

This design automatically handles the common June-to-July class/id/path churn when stable repeated structure remains. No deterministic system can prove the meaning of an arbitrary semantic redesign from markup alone. The security guarantee is therefore strict: uncertainty can reduce availability, but it cannot re-expose navigation, recommendations, ads, or other noise.

## Release, update, and rollback

- Builds are canonical, timestamp-free, and byte-reproducible.
- Third-party GitHub Actions are pinned to full commit SHAs; jobs use explicit minimal permissions and fixed runner images.
- The fourteen-rule marker gate is a byte-fixed asset of the repository's immutable `gate-v1.0.0` GitHub Release. AdGuard subscribes to that exact release URL. A normal semantic release cannot change the gate bytes or URL; a protocol change requires a separately versioned and explicitly migrated `gate-v2`.
- GitHub Pages receives only artifacts whose manifest and SHA-256 values passed the same run's gates. The manifest separately fixes each public file's raw bytes, the Userscript's canonical-text digest, and the filter's ordered non-comment installed-rule digest. Pages contains exactly `filter.txt`, `hotdeal-focus.user.js`, and `release-manifest.json`; its `filter.txt` is a verified mirror, not the subscription authority.
- The installed userscript updates through its HTTPS `@downloadURL` and `@updateURL`. Before Pages publication or Windows deployment, the machine CLI proves that the manifest's gate URL resolves to the exact published immutable release asset and verifies its release and asset attestations.
- Rollback is a newly versioned, fully verified release with `rollback_of`; clients are never pointed to a lower version or mutable historical file.
- A successful cloud audit writes a rate-limited heartbeat so GitHub does not disable the public scheduled workflow after repository inactivity.
- Normal audit artifacts contain bounded JSON and hashes with short retention. Screenshots are generated only for failures and candidate proof, with deterministic file-count and byte caps. The promotion package is mandatory evidence and has a longer bounded retention.

The public userscript uses `@grant none`, no external dependency, no dynamic code execution, and no privileged storage. Its only network action is the user-activated, same-origin fetch of one exact signed Algumon relay described above; it performs no background prefetch or retry storm. Published diagnostics contain only fixed tokens, counts, booleans, modes, versions, and hashes—never article text, query strings, account data, or comment content.

## Local deployment boundary

The Windows deployment CLI is transactional: inspect, write a schema-v2 atomic backup, install the userscript, disable the current-snapshot UI-blocking rules scoped exclusively to the seven target domains only after a separate explicit migration approval, install the URL filter, and verify the complete state. Domain scope does not claim historical provenance; the dry-run exposes only ordered indices and hashes for review. Every mutation records an append-only journal. `restore-backup -BackupPath <directory> -Apply` validates the complete marker, every raw payload hash, the unchanged ordered User-filter digest, and the exact authorized before/after objects before restoring filter, migration delta, and userscript in reverse order. Restore is idempotent and refuses unrelated or ambiguous changes. Schema-v1 backups remain preserved but are not automatically restorable because they predate payload hashes and the complete marker. Remote filter mutation requires both the raw release hash and the expected installed canonical rules hash. Secrets discovered for the local AdGuard IPC session are held only in memory and are never printed or written; any post-backup failure emits the backup path and a credential-free recovery command.

The stdlib-only Python orchestrator is the repository's machine control surface. It invokes only fixed argument-vector commands, emits one JSON value on stdout, separates logs to stderr, binds release evidence to a clean exact Git SHA, validates exact GitHub Pages ownership and artifact hashes, and rejects ZIP traversal, symlinks, duplicate paths, and overwrite destinations. Cloud and local mutations are dry-run unless explicitly authorized. This makes build, verification, cloud execution/evidence retrieval, deployment, post-install proof, and rollback reproducible without remembered GUI state; the public command contract is documented in `CLI.md`.

Repository activation is also typed and post-verified against GitHub API `2026-03-10`. Before and after mutation, the cloud configurator requires the exact public repository plus admin authority. Its target state is the two promotion/publication variables enabled, Pages `build_type=workflow`, repository Actions enabled with `allowed_actions=selected` and `sha_pinning_required=true`, selected actions limited to GitHub-owned actions (`verified_allowed=false`, empty patterns), default `GITHUB_TOKEN` permission `read` with pull-request approval disabled, and all three allowlisted workflows `active`. Typed booleans and the empty array are sent as canonical JSON through a private temporary file. Variables and workflows use enable-only operations; action and token permissions only narrow. If Actions starts disabled, every permission is independently read back and proven exact before the final enable operation. If an already-enabled state is incomparable with or stricter than the required action allowlist and reaching the target would broaden it, configuration stops before any mutation. Ambiguous client outcomes are successful only when a bounded post-read proves the entire exact state; otherwise the confirmed/unknown mutation state is retained as terminal evidence. Workflow dispatches carry a fresh correlation nonce in both the input and run title; observing only a same-SHA concurrent run is insufficient attribution.

## 요약 · 日本語 · 中文

**한국어:** 정확히 검증된 제목·구매정보·본문·댓글/답글 원본 DOM만 공개합니다. DOM 변경을 반복 관측으로 증명할 수 있으면 GitHub가 AI 없이 새 원자적 변형을 자동 승격합니다. 증명이 부족하면 빈 화면을 유지하며 노이즈를 다시 노출하지 않습니다.

**日本語:** 検証済みのタイトル・購入情報・本文・コメント/返信の元 DOM だけを表示します。DOM 変更を反復観測で証明できる場合のみ、GitHub が AI なしで新しい原子的バリアントを自動昇格します。不確実な場合は空白のままとし、ノイズを再表示しません。

**中文:** 仅显示经过验证的标题、购买信息、正文以及完整评论/回复的原始 DOM。只有当重复观测能够确定性证明 DOM 变更时，GitHub 才会在不使用 AI 的情况下自动提升新的原子布局变体；证据不足时保持空白，绝不重新暴露噪声。
