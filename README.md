# AdGuard Hotdeal Focus

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

AdGuard Hotdeal Focus는 Algumon에서 핫딜 글로 이동했을 때 제목, 상품·구매 정보, 본문, 댓글·답글만 원래 DOM 그대로 남기는 fail-closed 리더 게이트입니다. 대상은 클리앙, 뽐뿌(PC/모바일), 루리웹, 퀘이사존, 어미새, ZOD, 아카라이브입니다.

## 한국어

### 설치: URL 두 개가 모두 필요합니다

다음 두 URL을 설치하십시오.

1. AdGuard 사용자 정의 필터:

   `https://github.com/heelee912/adguard-hotdeal-focus/releases/download/gate-v1.0.0/filter.txt`

2. AdGuard 확장(Userscript):

   `https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js`

AdGuard에서 첫 URL은 **필터 → 사용자 정의 필터 → URL로 추가**, 두 번째 URL은 **확장/Userscripts → URL로 추가**에 등록합니다. 사용자 정의 필터는 **활성화 및 Trusted(신뢰함)**, Userscript는 **활성화** 상태인지 반드시 확인하십시오. Windows, macOS, Android 등 `#?#` ExtendedCSS와 Userscript 확장을 지원하는 AdGuard 제품이 대상입니다. 기존에 같은 목적의 User rules가 있다면 백업 후 비활성화하여 충돌을 막으십시오.

`filter-static.txt`는 DOM 분석과 회귀 비교용입니다. 기본 필터로 구독하지 마십시오.

Windows에서는 저장소의 재현 가능한 CLI로 백업·설치·사후 검증을 한 번에 수행할 수도 있습니다. 관리자 PowerShell에서 아래처럼 공개 매니페스트의 **정확한 설치용 해시 필드**를 넘기십시오. `sha256`은 내려받은 필터 원본, `canonicalTextSha256`은 줄바꿈을 정규화한 Userscript, `installedRulesSha256`은 AdGuard에 전달할 비주석 규칙 14개의 순서를 각각 고정합니다.

```powershell
$releaseBase = 'https://heelee912.github.io/adguard-hotdeal-focus'
$manifest = Invoke-RestMethod "$releaseBase/release-manifest.json"
.\scripts\adguard_windows_cli.ps1 deploy `
  -UserscriptSource "$releaseBase/hotdeal-focus.user.js" `
  -FilterUrl $manifest.filterSubscriptionUrl `
  -ReleaseManifestSource "$releaseBase/release-manifest.json" `
  -ExpectedUserscriptSha256 $manifest.artifacts.'hotdeal-focus.user.js'.canonicalTextSha256 `
  -ExpectedFilterSha256 $manifest.artifacts.'filter.txt'.sha256 `
  -ExpectedInstalledFilterRulesSha256 $manifest.artifacts.'filter.txt'.installedRulesSha256 `
  -ApproveExclusiveTargetMigration `
  -Apply
```

`-ApproveExclusiveTargetMigration`은 현재의 안정적인 API snapshot에서 **7개 대상 도메인에만 적용되는 모든** cosmetic/ExtendedCSS/CSS-injection/scriptlet 규칙을 비활성화해도 된다는 별도 승인입니다. 도메인 scope만으로 그 규칙이 이 프로젝트의 구형 필터였다는 출처까지 증명되지는 않습니다. 먼저 `migrate-legacy -WhatIf`의 plaintext 없는 인덱스·SHA-256 계획을 검토하고, 이 승인이 맞을 때만 switch를 사용하십시오. 규칙은 삭제되지 않고 backup과 transaction delta로 복구할 수 있습니다.

### 왜 필터와 Userscript가 모두 필요한가

- `filter.txt`는 7개 대상 도메인 전체를 즉시 잠급니다. 목록·홈·미승인 경로도 기본값은 빈 화면이며, 정확한 프로토콜 버전과 ready 마커가 없으면 계속 숨깁니다.
- Userscript는 `document-start`에 실행되어 승인된 사이트 레이아웃 하나를 원자적으로 확인합니다.
- 승인된 variant 하나만 경로에 맞고, 그 variant의 page root·제목·본문·댓글 mount와 해당 사이트에서 별도 영역인 구매정보가 각각 허용된 cardinality·포함관계·문서 순서를 만족해야 열립니다. 별도 구매영역이 없는 글은 본문 안의 구매 링크를 그대로 보존하며 정상 글을 오탐 차단하지 않습니다. 런타임은 점수나 추정 fallback을 사용하지 않습니다.
- 댓글 mount 안의 모든 의미 있는 내용은 기존 댓글 item, 승인된 control, 또는 명시적으로 숨길 comment chrome(`ignored`)으로 전부 분류되어야 합니다. `ignored`는 분류에는 참여하지만 keep 마커를 절대 받지 않습니다. 알려진 댓글 하나와 새 형태 답글 하나가 섞여도 일부 댓글만 보여주지 않고 전체를 잠급니다.
- 의미 점수는 CI에서 새 candidate를 발견하는 감사 oracle로만 쓰이며 공개 런타임의 승인 근거가 아닙니다.
- 새 광고·추천·사이드바는 keep 마커가 없으므로 자동으로 사라집니다. 승인 후 새 댓글·답글 또는 허용된 lazy-media 속성 외의 의미 있는 DOM/텍스트/식별 속성 변경이 생기면 같은 문서에서는 다시 열지 않는 terminal lock으로 전환합니다.
- 원래 제목·본문·댓글 노드와 텍스트를 복제하거나 교체하지 않습니다. shell 가시성, role/deep 마커만으로 직접 텍스트와 pseudo-content 누출을 막습니다.

Algumon에서는 사용자가 현재 카드의 정확한 signed `/l/d/<id>?v=…&t=…` 링크를 작동시킨 그 순간에만 같은 출처로 한 번 가져옵니다. 응답이 `200`이고, 문서 전체가 허용된 단일 redirect script와 동일 URL의 단일 anchor만 가지며, 최종 HTTPS host가 그 카드의 정확한 사이트 allowlist와 일치할 때에만 relay를 우회해 최종 URL로 이동합니다. 일반 클릭, `_blank`, Ctrl/Cmd/Shift-click, 중클릭, Enter를 같은 검증 경로로 처리합니다. fetch·응답 구조·URL·팝업 검증 중 하나라도 실패하면 새 창을 닫고 Algumon에 그대로 남으며 다른 전달 경로로 추측하지 않습니다.

검증된 최종 URL에는 사이트 유형, 글 ID, 제목, 명시적으로 존재할 때만 원문 댓글 수, 시각을 담은 최대 1KB·10분의 base64url fragment를 붙입니다. fragment는 서버로 전송되지 않고 대상 문서가 `document-start`에 즉시 제거합니다. `window.name`과 referrer는 권한 근거로 사용하지 않습니다. 목적지에서는 seed 글 ID·현재 URL 글 ID·제목 core·원문 article metadata·전체 DOM 계약이 모두 맞아야 열리며, seed 하나만으로는 절대 충분하지 않습니다. 본문·댓글·계정·쿠키·토큰은 수집하거나 저장하지 않습니다.

과거 User rules가 23줄인지 170줄인지 여부는 새 시스템의 커버리지 지표가 아닙니다. 구형 규칙은 정확히 일치하는 항목만 마이그레이션·회귀 목록으로 사용합니다. 공개 `filter.txt`는 의도적으로 도메인당 2개, 총 14개의 안정적인 잠금 규칙만 가지며, 실제 사이트별 의미 계약과 자동 적응은 Userscript·검증 설정·GitHub 증거에 있습니다.

14개 잠금 규칙은 GitHub의 불변 `gate-v1.0.0` 릴리스 자산입니다. 일반 의미 릴리스가 올라가도 이 바이트와 구독 URL은 바뀌지 않으며, Pages의 `filter.txt`는 검증용 미러일 뿐 설치 기준이 아닙니다. 사이트 DOM 변경은 Pages의 Userscript와 승인 상태만 더 높은 의미 버전으로 갱신합니다. 잠금 프로토콜 자체를 바꿔야 할 때만 별도 `gate-v2` 마이그레이션으로 발행하므로 자동 적응 도중 보호막이 약해지지 않습니다. 공개 설치·배포에는 저장소의 Python CLI가 GitHub 불변 릴리스와 자산 증명을 먼저 확인한 뒤 내부 PowerShell 배포기를 호출하는 경로를 권장합니다.

### PC가 꺼져 있어도 동작하는 자동화

GitHub Actions가 클라우드에서 6시간마다 라이브 DOM과 적용 가능한 PC/모바일 계약을 검사합니다. 로컬 데몬이나 켜진 PC가 필요 없습니다. 새 구조는 먼저 배포 불가 draft bundle과 base commit·audit report·순서·fingerprint·draft SHA-256을 묶은 canonical queue manifest를 고정합니다. 전체 queue는 그대로 서명하되 한 실행의 matrix는 `github.run_number`에 결합된 8개 circular batch로 제한하여 작업 시간을 고정하고, 연속 실행이 남은 후보를 유한 횟수 안에 모두 선택합니다. 후보별 검증은 독립 matrix job으로 실행되므로 한 후보의 timeout이 뒤 후보를 굶기지 않습니다. 집계기는 누락·미실행 결과를 queue에 결합된 `infrastructure-missing` 비승인 상태로 명시적으로 완성해 현재 batch의 proven 후보 검증을 계속하되, 추가·중복·변조 artifact가 하나라도 있으면 전체 승격을 차단합니다. 그 뒤 queue 순서상 첫 proven 후보 하나만 원자적으로 승격합니다.

그 정확한 candidate 바이트로 profile별 서로 다른 글 3개 이상과 fixture를 다시 검증합니다. Algumon이 원문 댓글 수를 제공하지 않으면 값을 꾸며내지 않고, 동일한 댓글 mount/item selector와 최소 2개 nonempty 표본 또는 3개 exact-empty 증거를 요구합니다. 누출 0, 기존 노출 증가 없음, selector 안정성 1, 단일 semantic projection, 다른 projection co-match 0을 모두 만족한 proven 증거만 더 높은 버전으로 자동 승격합니다. 정상 실행은 작은 JSON/hash 증거만 남기고 screenshot은 실패·후보 증명에만 용량 상한과 짧은 보존기간을 적용합니다. 자동 커밋은 저장소 변수 `ENABLE_STATE_COMMITS=true`, Pages 배포는 `ENABLE_PAGES_PUBLISH=true`로 명시적으로 활성화합니다.

초기 GitHub 설정도 GUI에 의존하지 않습니다. `python scripts/hotdeal_focus_cli.py cloud configure --repo heelee912/adguard-hotdeal-focus --workflow verify.yml --apply --json --evidence-dir outputs/cloud-configure-001`은 변경 전후에 정확한 공개 저장소·관리자 권한을 확인하고, 위 두 변수를 `true`로, Pages를 `build_type=workflow`로 설정합니다. 동시에 Actions를 활성화하고 `allowed_actions=selected`, `sha_pinning_required=true`, GitHub 소유 Action만 허용(`verified_allowed=false`, 빈 pattern), 기본 `GITHUB_TOKEN` 읽기 전용·PR 승인 금지, 세 워크플로 모두 `active`인 상태를 GitHub API `2026-03-10`으로 정확히 재검증합니다. 변경은 enable 전용 endpoint와 권한 축소만 사용하며, 이미 활성화된 정책을 넓혀야 목표에 도달하는 상태는 변경 전에 거부합니다. Workflow dispatch는 실행마다 nonce를 input과 run title에 묶어 동시 실행을 잘못 귀속하지 않습니다.

### 빌드와 검증

Python 3.10+와 Node.js 20+를 사용합니다.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
npm run build
npm run verify
npm run test:behavior
```

에이전트용 JSON-only 통합 CLI로 위 검증, GitHub Actions 실행·증거 다운로드, Windows AdGuard 배포·롤백을 GUI 없이 재현할 수 있습니다. 명령 계약과 종료 코드는 [CLI.md](CLI.md)에 있습니다.

단일 빌드는 저장소 루트의 `filter.txt`, 분석용 `filter-static.txt`, `release-manifest.json`을 결정론적으로 생성합니다. 공개 artifact 해시는 필터와 Userscript만 포함하고, 설정·fixture·분석 필터는 별도 `sourceIntegrity`로 고정합니다.

검증된 새 variant는 루트 릴리스를 직접 수정하지 않고 격리 출력으로 만듭니다.

```bash
state_args=()
if [[ -f state/approved-variants.json ]]; then
  state_args=(--merge-approved-state state/approved-variants.json)
fi
python scripts/build_filter.py \
  --candidate-draft discovered.json \
  --output-dir candidate-draft \
  "${state_args[@]}"
# candidate-draft의 실제 실행 증거로 proven.json을 만든 뒤
python scripts/build_filter.py \
  --candidate proven.json \
  --output-dir candidate-release \
  "${state_args[@]}"
```

롤백도 과거 파일이나 낮은 버전으로 되감지 않습니다. 반드시 더 높은 `@version`을 발행하고 `rollback_of`에 이전 릴리스 버전과 SHA-256을 기록합니다.

## English

### Install both URLs

1. Custom AdGuard filter: `https://github.com/heelee912/adguard-hotdeal-focus/releases/download/gate-v1.0.0/filter.txt`
2. AdGuard Userscript extension: `https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js`

Add the first URL under **Filters → Custom filters → Add by URL** and the second under **Extensions/Userscripts → Add by URL**. Confirm that the custom filter is **enabled and Trusted**, and that the Userscript is **enabled**. The target clients are AdGuard products for Windows, macOS, and Android that support `#?#` ExtendedCSS and Userscript extensions. Back up and disable older rules with the same purpose. Do not subscribe to `filter-static.txt`; it is an analysis-only artifact.

On Windows, the repository CLI can perform a reversible backup, deploy, and post-install verification. Run it from an elevated PowerShell and pass the release manifest fields exactly:

```powershell
$releaseBase = 'https://heelee912.github.io/adguard-hotdeal-focus'
$manifest = Invoke-RestMethod "$releaseBase/release-manifest.json"
.\scripts\adguard_windows_cli.ps1 deploy `
  -UserscriptSource "$releaseBase/hotdeal-focus.user.js" `
  -FilterUrl $manifest.filterSubscriptionUrl `
  -ReleaseManifestSource "$releaseBase/release-manifest.json" `
  -ExpectedUserscriptSha256 $manifest.artifacts.'hotdeal-focus.user.js'.canonicalTextSha256 `
  -ExpectedFilterSha256 $manifest.artifacts.'filter.txt'.sha256 `
  -ExpectedInstalledFilterRulesSha256 $manifest.artifacts.'filter.txt'.installedRulesSha256 `
  -ApproveExclusiveTargetMigration `
  -Apply
```

`-ApproveExclusiveTargetMigration` is a separate authorization to disable every current-snapshot cosmetic, ExtendedCSS, CSS-injection, and scriptlet rule scoped exclusively to the seven target domains. Domain scope alone does not prove that a rule came from an older release of this project. Review the plaintext-free index/SHA-256 plan from `migrate-legacy -WhatIf` first and use the switch only when that scope is intended. Rules are disabled, never deleted, and the backup plus exact transaction delta can restore them.

The marker filter locks every page on all seven target domains; list, home, unknown, and unapproved routes therefore remain blank by default. The document opens only when exactly one approved semantic projection resolves one page root, title, body, complete comment mount, and the configured zero-or-one or required purchase-information boundary with exact cardinality, containment, and document order. A site with no separate purchase block keeps an in-body purchase link without rejecting the article. Every meaningful node inside the comment mount must be classified as an approved item, approved control, or explicitly hidden comment chrome (`ignored`). Ignored nodes participate in completeness checks but never receive keep markers. One known comment plus one newly shaped reply fails closed instead of exposing an incomplete thread. After approval, any meaningful mutation other than an exactly classified new comment/reply or an allowed lazy-media attribute causes a terminal same-document lock. Runtime approval never uses semantic scores or a guessed fallback; scoring exists only in the CI discovery oracle. Unmarked ads, sidebars, recommendations, and later injected siblings remain hidden. Original content nodes, text nodes, and event identity are not replaced.

Only a user activation of the card's exact signed `/l/d/<id>?v=…&t=…` URL triggers one same-origin Algumon fetch. The gate requires HTTP 200, one whole-document redirect script, one anchor with the identical destination, and an HTTPS destination host matching the card's exact site allowlist. Normal, new-tab, modified, middle-click, and Enter activations all use this path. A fetch, parser, URL, host, signature-shape, or popup failure closes the child and leaves Algumon in place; there is no guessed carrier. The validated destination receives a capped ten-minute public seed in a base64url fragment, then removes it at `document-start`. Neither `window.name` nor referrer is authority. The destination still requires matching URL article identity, title core, consistent article metadata, and the complete DOM contract. No body, comments, account data, cookies, or tokens are collected or stored.

The old User-rule count—whether 23 or roughly 170—is not a coverage target. Exact old rules are only migration and regression inventory. The public filter intentionally contains two stable lock rules per domain, fourteen total; site meaning and adaptation live in the Userscript contract and GitHub proof pipeline.

Those fourteen lock rules are the byte-fixed asset of the immutable GitHub `gate-v1.0.0` release. Semantic releases do not change its bytes or subscription URL; the Pages `filter.txt` is only a verified mirror, not the installation authority. DOM adaptations update only the Pages Userscript and approved state at a higher semantic version. A lock-protocol change requires a separately migrated `gate-v2`, so automatic adaptation cannot silently weaken the safety curtain. For public installation and deployment, the recommended Python CLI verifies the immutable GitHub release and asset attestations before invoking the internal PowerShell deployer.

GitHub Actions performs six-hour cloud audits, so no local daemon or powered-on PC is required. Discovery freezes non-promotable drafts and a canonical queue manifest binding the base commit, audit report, order, fingerprint, and draft hashes. The full queue remains signed, while each run exposes only an eight-item circular matrix batch bound to `github.run_number`; consecutive runs therefore cover every queued candidate in finite rounds without unbounded job growth. Each selected candidate runs in an independent matrix job, so one timeout cannot starve later candidates. The aggregator completes a missing or unselected result as a queue-bound, non-promotable `infrastructure-missing` status and may still select a proven candidate from the current batch; any extra, duplicate, or tampered artifact blocks the entire promotion. It atomically selects only the first proven candidate in queue order. The exact bytes must pass at least three distinct URLs per applicable profile, structural comment proof when Algumon has no source count, fixtures, zero visible leaks, no new baseline exposure, selector stability 1, exactly one semantic projection, and zero conflicting projections before a higher release is promoted. Normal runs retain only bounded JSON/hash evidence; screenshots are capped and reserved for failures and candidate proof. Set `ENABLE_STATE_COMMITS=true` to permit bot commits and `ENABLE_PAGES_PUBLISH=true` to publish verified artifacts.

The dry-run-by-default `cloud configure` command proves the exact public/admin repository before and after mutation. In addition to the two variables and Pages `build_type=workflow`, it requires Actions enabled with `allowed_actions=selected`, mandatory SHA pinning, GitHub-owned actions only (`verified_allowed=false`, no patterns), a read-only default `GITHUB_TOKEN` that cannot approve pull requests, and all three repository workflows in `active` state. It uses GitHub API `2026-03-10`, enable-only endpoints, and permission narrowing; an already-enabled policy that would have to be broadened is rejected before mutation. Dispatches bind a fresh nonce to both the workflow input and run title, preventing attribution to a concurrent run on the same commit.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
npm run build
npm run verify
npm run test:behavior
```

The JSON-only agent CLI reproduces verification, GitHub Actions/evidence operations, and Windows AdGuard deployment/rollback without remembered GUI state. See [CLI.md](CLI.md) for its command and exit-code contract.

The single release build deterministically produces root `filter.txt`, `filter-static.txt`, and `release-manifest.json`. Rollbacks are forward releases: use a higher `@version` and record the previous version/hash in `rollback_of`.

## 日本語

### 2つのURLを両方インストールしてください

1. AdGuard カスタムフィルター: `https://github.com/heelee912/adguard-hotdeal-focus/releases/download/gate-v1.0.0/filter.txt`
2. AdGuard Userscript 拡張: `https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js`

1つ目は **フィルター → カスタムフィルター → URLから追加**、2つ目は **拡張/Userscripts → URLから追加** に登録します。カスタムフィルターが **有効かつ Trusted（信頼済み）**、Userscript が **有効** であることを必ず確認してください。`#?#` ExtendedCSS と Userscript に対応する Windows、macOS、Android 向け AdGuard が対象です。`filter-static.txt` は解析専用なので購読しないでください。

フィルターは7つの対象ドメインの全ページを直ちにロックするため、一覧・ホーム・未知または未承認のパスも既定では空白です。Userscript が承認済みの semantic projection を1つだけ解決し、その page root・タイトル・本文・完全なコメント mount・設定済みの必須または0〜1個の購入情報の cardinality、包含関係、文書順序を確認した場合だけ表示します。独立した購入ブロックがない記事では、本文内の購入リンクをそのまま保ちます。コメント mount 内の意味ある内容は承認済み item/control または明示的に非表示にする `ignored` chrome に完全分類される必要があり、`ignored` には keep marker を付与しません。新形式の返信が1件でも混在すれば不完全表示せず fail-closed になります。承認後の未知の意味的 mutation は同一文書を terminal lock にし、実行時の承認にスコアや推測 fallback は使いません。

Algumon でユーザーが正確な signed `/l/d/<id>?v=…&t=…` リンクを操作した時だけ、同一オリジンへ1回 fetch します。HTTP 200、単一の厳密な redirect script、同じ URL の単一 anchor、カードのサイト種別と一致する HTTPS host をすべて確認してから、最終 URL に有効期限付き fragment seed を付けて移動します。失敗時は子ウィンドウを閉じて Algumon に残り、`window.name` や referrer に切り替えません。移動先でも記事ID、タイトル core、一意で整合する article metadata、完全な DOM 契約が必要です。

旧 User rules が23行でも約170行でも、それは新設計の coverage 指標ではありません。旧ルールは厳密な migration／regression inventory に限って使います。公開フィルターは意図的に1ドメイン2規則、合計14規則だけを持ち、サイト固有の意味契約は Userscript と GitHub の証明パイプラインが担当します。

この14規則は GitHub の不変 `gate-v1.0.0` リリース資産としてバイト固定されます。通常の意味バージョン更新では購読 URL とゲートのバイトを変えず、Pages の `filter.txt` は検証済みミラーとしてのみ扱います。DOM 変更時は Pages の Userscript と承認状態だけを更新し、ロックプロトコル自体の変更は別の `gate-v2` 移行として公開します。

GitHub Actions が6時間ごとにクラウド監査を行うため、ローカル常駐処理や起動中のPCは不要です。全 canonical queue はハッシュ固定したまま、各実行は `github.run_number` に結合した8件の circular batch だけを独立 matrix job で検証します。連続実行は有限回で全候補を選択するため、1件の timeout や大量候補が後続候補を恒久的に停止させません。欠落・未実行結果は queue に結合された非昇格 `infrastructure-missing` 状態として補完しますが、余分・重複・改ざん済み artifact が1件でもあれば全昇格を拒否します。aggregator は queue 順で最初の proven candidate 1件だけを原子的に昇格します。原文コメント数が取得できない場合は値を偽装せず、安定したコメント構造を別途証明します（`ENABLE_STATE_COMMITS=true`、Pages は `ENABLE_PAGES_PUBLISH=true`）。

`cloud configure` は変更前後に正確な公開リポジトリと管理者権限を確認します。2変数と Pages の `build_type=workflow` に加え、Actions を有効化し、`allowed_actions=selected`、SHA pin 必須、GitHub 所有 Action のみ許可（verified creator と pattern は不許可）、既定 `GITHUB_TOKEN` は read-only・PR 承認不可、3つの workflow はすべて `active` であることを API `2026-03-10` で厳密に再検証します。変更は enable-only endpoint と権限縮小に限定し、有効中のポリシーを拡大しなければ到達できない場合は変更前に拒否します。dispatch は nonce を workflow input と run title の両方に結合し、同時実行の誤帰属を防ぎます。

```bash
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
npm run build
npm run verify
npm run test:behavior
```

JSON-only エージェント CLI により、GUI 状態に依存せず検証、GitHub Actions／証拠取得、Windows AdGuard の配布／ロールバックを再現できます。コマンドと終了コードは [CLI.md](CLI.md) を参照してください。

ロールバックも過去ファイルへ戻しません。より高い `@version` を発行し、`rollback_of` に以前のバージョンと SHA-256 を記録します。

## 简体中文

### 必须同时安装两个 URL

1. AdGuard 自定义过滤器：`https://github.com/heelee912/adguard-hotdeal-focus/releases/download/gate-v1.0.0/filter.txt`
2. AdGuard Userscript 扩展：`https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js`

第一个 URL 添加到 **过滤器 → 自定义过滤器 → 通过 URL 添加**，第二个添加到 **扩展/Userscripts → 通过 URL 添加**。请务必确认自定义过滤器处于 **已启用且 Trusted（受信任）** 状态，并确认 Userscript **已启用**。目标客户端是支持 `#?#` ExtendedCSS 和 Userscript 的 Windows、macOS、Android 版 AdGuard。`filter-static.txt` 仅供分析，请勿订阅。

过滤器会立即锁定七个目标域名的全部页面，因此列表、首页、未知及未批准路径默认均为空白。只有 Userscript 恰好解析出一个已批准的 semantic projection，并确认 page root、标题、正文、完整评论 mount，以及配置为必需或0至1个的购买信息满足 cardinality、包含关系与文档顺序后，页面才会显示。没有独立购买区块时，正文中的购买链接仍会原样保留。评论 mount 内所有有意义的内容必须完整归类为已批准 item/control 或明确隐藏的 `ignored` chrome；`ignored` 永远不会获得 keep marker。即使仅混入一个新形态回复也会 fail-closed。批准后出现未知的有意义 mutation 会使同一文档进入 terminal lock；运行时批准不使用语义分数或猜测 fallback。

只有用户在 Algumon 激活精确的 signed `/l/d/<id>?v=…&t=…` 链接时，才会向同源发送一次 fetch。系统必须同时验证 HTTP 200、唯一且严格匹配的 redirect script、指向同一 URL 的唯一 anchor，以及与卡片站点类型一致的 HTTPS host，然后才把限时 fragment seed 添加到最终 URL。任何失败都会关闭子窗口并留在 Algumon，不会改用 `window.name` 或 referrer。目标页面仍须同时匹配文章 ID、标题 core、唯一一致的 article metadata 和完整 DOM 契约。

旧 User rules 无论是23行还是约170行，都不是新架构的覆盖率指标。旧规则仅作为精确 migration／regression inventory。公开过滤器有意保持每个域名2条、合计14条稳定锁定规则；站点语义与自动适配由 Userscript 契约和 GitHub 证据流水线负责。

这14条锁定规则是 GitHub 不可变 `gate-v1.0.0` 发布中的字节固定资产。普通语义版本更新不会改变其订阅 URL 或字节；Pages 上的 `filter.txt` 只作为已验证镜像，不是安装权威。DOM 变化仅更新 Pages Userscript 与已批准状态；只有锁定协议本身变化时，才通过单独的 `gate-v2` 迁移发布。

GitHub Actions 每6小时在云端审计，不需要本地守护进程，也不要求电脑保持开机。完整 canonical queue 保持哈希绑定，每次运行仅在相互独立的 matrix job 中验证与 `github.run_number` 绑定的8项 circular batch。连续运行会在有限轮次内选中所有候选项，因此单个 timeout 或大量候选项不会永久饿死后续项。缺失或未运行结果会被补全为与队列绑定、不可提升的 `infrastructure-missing` 状态；但任何额外、重复或遭篡改的 artifact 都会阻止整次提升。aggregator 只原子提升队列中第一个 proven candidate。Algumon 无法提供原站评论数时不会伪造分数，而会独立证明稳定的评论结构（`ENABLE_STATE_COMMITS=true`；Pages 发布另设 `ENABLE_PAGES_PUBLISH=true`）。AdGuard 通过上述两个 URL 获取验证后的更新。

`cloud configure` 会在变更前后核对精确的公开仓库与管理员权限。除两个变量和 Pages `build_type=workflow` 外，它还要求启用 Actions、设置 `allowed_actions=selected`、强制 SHA 固定、仅允许 GitHub 自有 Action（不允许 verified creator，pattern 为空）、默认 `GITHUB_TOKEN` 只读且不能批准 PR，并确保三个工作流全部为 `active`；这些状态均通过 API `2026-03-10` 精确复验。变更只使用启用型端点和权限收窄；若已启用策略必须扩大权限才能达到目标，则在任何变更前拒绝。dispatch 将随机 nonce 同时绑定到 workflow input 和 run title，避免把同一 commit 的并发运行误认为自己的运行。

```bash
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
npm run build
npm run verify
npm run test:behavior
```

JSON-only 智能体 CLI 可在不依赖 GUI 状态的情况下重现验证、GitHub Actions／证据下载以及 Windows AdGuard 部署／回滚。命令与退出码契约见 [CLI.md](CLI.md)。

回滚也必须作为更高版本向前发布，并在 `rollback_of` 中记录旧版本和 SHA-256；禁止降低版本或把 latest 指向旧文件。

## License

[MIT](LICENSE)
