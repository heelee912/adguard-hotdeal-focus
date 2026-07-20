# Hotdeal Focus machine CLI

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

`scripts/hotdeal_focus_cli.py` 는 에이전트가 GUI 상태나 수동 조작을 기억하지 않고 빌드, 검증, GitHub Actions, 릴리스 증거, Windows AdGuard 배포와 롤백을 재현하는 JSON-only CLI입니다. 표준 출력은 항상 JSON 한 개이고, 실행 로그는 표준 오류로 분리됩니다. 외부 명령은 고정 allowlist와 인자 배열로만 실행하며 shell 문자열을 평가하지 않습니다.

필수 런타임은 Python 3.10+, Node.js 20+, npm, Git입니다. 클라우드와 불변 게이트 검증 명령은 인증된 `gh`가 필요합니다. Windows AdGuard의 `inspect`는 Windows PowerShell 5.1과 실행 중인 AdGuard for Windows만 필요하지만, `plan`·`deploy`·`verify`는 설치 URL이 실제 GitHub 불변 릴리스 자산인지 증명하기 위해 인증된 `gh`도 필요합니다.

```powershell
python scripts/hotdeal_focus_cli.py doctor --json
python scripts/hotdeal_focus_cli.py build --check --json --evidence-dir outputs/build-check-001
python scripts/hotdeal_focus_cli.py verify --profile release --json --evidence-dir outputs/verify-release-001
```

`verify` profile은 `fast`, `release`, `live`입니다. `live`는 Algumon 전체 discovery를 강제하고 Arca Live를 GitHub-hosted runner에서만 접속하므로, 로컬에서 일부만 검증한 뒤 성공으로 보고하지 않습니다.

깨끗한 HEAD의 전체 40자 SHA에 릴리스 증거를 고정합니다. 출력 디렉터리는 기존 경로를 덮어쓰지 않고 항상 새로 생성됩니다.

```powershell
$sourceSha = git rev-parse HEAD
python scripts/hotdeal_focus_cli.py release-evidence `
  --source-ref $sourceSha `
  --output-dir outputs/release-evidence-001 `
  --json
```

GitHub 명령에서 `dispatch`와 증거 다운로드는 명시적 `--apply`가 필요합니다. `status`/`watch`는 읽기 전용입니다. 다운로드는 GitHub artifact digest, ZIP 크기, 경로 이탈, symlink, 중복 경로를 검사한 뒤에만 새 디렉터리로 승격합니다.

```powershell
$sourceSha = git rev-parse HEAD
python scripts/hotdeal_focus_cli.py cloud configure --repo heelee912/adguard-hotdeal-focus --workflow verify.yml --source-ref $sourceSha --apply --json --evidence-dir outputs/cloud-configure-001
python scripts/hotdeal_focus_cli.py cloud dispatch --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --apply --json
python scripts/hotdeal_focus_cli.py cloud status --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --run-id 123456789 --json
python scripts/hotdeal_focus_cli.py cloud watch --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --run-id 123456789 --json
python scripts/hotdeal_focus_cli.py cloud download-evidence --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --run-id 123456789 --output-root outputs/cloud-evidence --apply --json
```

`cloud configure`는 기본이 dry-run이며, 변경 전후에 정확한 공개 저장소와 관리자 권한을 검증합니다. `--apply`는 `ENABLE_STATE_COMMITS=true`, `ENABLE_PAGES_PUBLISH=true`, Pages `build_type=workflow`뿐 아니라 다음 Actions 보안 계약을 GitHub API `2026-03-10`으로 설정·재검증합니다: Actions 활성화, `allowed_actions=selected`, `sha_pinning_required=true`, `github_owned_allowed=true`, `verified_allowed=false`, `patterns_allowed=[]`, `default_workflow_permissions=read`, `can_approve_pull_request_reviews=false`, 그리고 `verify.yml`·`watch-dom.yml`·`publish-gate.yml` 모두 `active`. JSON boolean과 빈 배열은 임시 canonical JSON payload로 전달되며, 임시 경로와 출력에는 비밀값을 담지 않습니다. 설정기는 변수·Actions·workflow에는 enable-only endpoint를 사용하고 권한은 좁히기만 합니다. Actions가 꺼져 있으면 나머지 권한이 원격에서 정확히 고정됐음을 별도로 읽어 증명한 뒤 마지막 단계에서만 활성화합니다. 이미 활성화된 `local_only` 또는 GitHub 소유 Action 금지 정책처럼 목표 상태가 권한 확대를 요구하면 아무것도 변경하지 않고 무결성 오류로 종료합니다. 일부 요청 결과가 모호하면 원격 전체 상태를 최대 6회 다시 읽어 정확히 일치할 때만 성공하고, 그렇지 않으면 `mutationApplied`/`mutationState`에 확인된 부분 변경 또는 불명 상태를 보존한 채 종료 코드 8을 반환합니다. `dispatch`는 매번 128-bit correlation nonce를 workflow input과 run title에 결합하므로 같은 commit을 동시에 실행한 다른 사용자의 run을 자신의 실행으로 오인하지 않습니다.

`cloud configure --apply`는 clean default-head full SHA, GitHub의 세 workflow blob, integration `15368`의 정확한 `verify` job/check를 먼저 증명하고 mutation 단계마다 head lease를 갱신합니다. 세 보호 환경은 default branch 하나만 허용합니다. Ed25519 개인키는 `hdf-main-automation` environment secret에만 두고 같은 이름의 repository secret은 금지합니다. 세 ruleset은 PR/verify, no-bypass fast-forward history, 그리고 integration `15368`만 우회 가능한 `refs/tags/gate-v2.0.2` 생성·수정·삭제 금지를 강제합니다. local `gate-release publish`는 직접 발행하지 않고 보호된 publisher workflow를 nonce-bound dispatch합니다.

잠금 필터는 의미 릴리스와 분리된 protocol-2 `gate-v2.0.2` 불변 GitHub Release입니다. protocol-1 릴리스는 롤백 증거로만 보존하며 v2의 호환 경로나 fallback으로 인정하지 않습니다. `enable-policy`는 정확한 공개 저장소에 대한 관리자 권한을 확인한 뒤 immutable releases를 enable-only로 설정합니다. 기본은 dry-run이며 실제 변경에는 `--apply`가 필요합니다. 그 뒤 깨끗한 기본 브랜치 HEAD에서 수동 전용 워크플로 또는 아래 명령으로 게이트를 딱 한 번 발행합니다. 이미 게시된 게이트의 재실행은 관리자 전용 정책 API 대신 해당 릴리스의 불변 메타데이터와 증명을 직접 확인하며, 게이트가 없거나 초안이면 정책이 읽기 가능하고 활성화됐음을 먼저 증명하기 전에는 어떤 변경도 시작하지 않습니다. `verify`는 릴리스 메타데이터의 `immutable: true`, 유일한 `filter.txt` 자산, 크기·SHA-256·URL, 릴리스 및 자산 attestation, 실제 다운로드 바이트를 모두 확인합니다.

```powershell
$sourceSha = git rev-parse HEAD
python scripts/hotdeal_focus_cli.py gate-release enable-policy --repo heelee912/adguard-hotdeal-focus --apply --json --evidence-dir outputs/gate-policy-enable-001
python scripts/hotdeal_focus_cli.py gate-release publish --repo heelee912/adguard-hotdeal-focus --source-ref $sourceSha --apply --json --evidence-dir outputs/gate-release-publish-001
python scripts/hotdeal_focus_cli.py gate-release verify --repo heelee912/adguard-hotdeal-focus --json --evidence-dir outputs/gate-release-verify-001
```

AdGuard 배포는 기본이 dry-run입니다. 실제 배포에는 `--apply`와, 7개 대상 도메인에만 적용되는 기존 UI 차단 규칙을 비활성화하는 별도 권한 `--approve-exclusive-target-migration`이 둘 다 필요합니다. 규칙은 삭제하지 않고 transaction backup으로 되돌립니다.

```powershell
$manifestUrl = 'https://heelee912.github.io/adguard-hotdeal-focus/release-manifest.json'
python scripts/hotdeal_focus_cli.py adguard inspect --json
python scripts/hotdeal_focus_cli.py adguard plan --manifest-source $manifestUrl --json --evidence-dir outputs/adguard-plan-001
python scripts/hotdeal_focus_cli.py adguard deploy --manifest-source $manifestUrl --approve-exclusive-target-migration --apply --json --evidence-dir outputs/adguard-deploy-001
python scripts/hotdeal_focus_cli.py adguard verify --manifest-source $manifestUrl --json --evidence-dir outputs/adguard-verify-001
python scripts/hotdeal_focus_cli.py adguard rollback --backup-path 'C:\absolute\backup-directory' --apply --json --evidence-dir outputs/adguard-rollback-001
python scripts/hotdeal_focus_cli.py adguard csp-probe --json --evidence-dir outputs/csp-probe-dry-run
python scripts/hotdeal_focus_cli.py adguard csp-probe --apply --json --evidence-dir outputs/csp-probe-actual
```

`adguard csp-probe`는 일반 설치에 필요하지 않은 선택형 Windows 진단입니다. 고정 소스와 SHA-256을 인증한 뒤 `IsCustom=true` 수동 확장으로 잠시 설치하고, nonce 값을 노출하지 않은 채 공식 strict-CSP 페이지의 정확한 CSP와 브라우저 삽입을 증명한 다음 실행 전 코드·GM 설정·활성 상태·분류를 정확히 복원합니다. 관리 상태가 먼저 읽히고 filtering proxy 재적용이 늦을 수 있으므로, 상한이 있는 새 격리 브라우저 context로만 재시도하며 한 번의 시도가 전체 계약을 모두 만족해야 합니다. 여러 시도의 부분 증거를 합쳐 성공 처리하지 않습니다.

종료 코드는 `0` 성공, `2` 사용법, `3` 선행 조건, `4` 검증, `5` 무결성, `6` 일시적 외부 오류, `7` 변경 실패·롤백 완료, `8` 롤백 미완료입니다. 자동화는 문자열 로그가 아니라 이 코드와 JSON의 `ok`, `status`, `sourceSha`, `artifacts`, `evidence`를 판정해야 합니다.

## English

`scripts/hotdeal_focus_cli.py` is the JSON-only control surface for reproducible builds, verification, release evidence, GitHub Actions, evidence downloads, immutable-gate publication/proof, and Windows AdGuard deployment/rollback. It emits exactly one JSON value on stdout and logs on stderr. Authenticated `gh` is required for cloud, immutable-gate, and AdGuard plan/deploy/verify commands; AdGuard inspect additionally requires Windows PowerShell 5.1 and a running AdGuard for Windows. Mutating cloud/download/gate-policy/gate-publish/deploy/rollback commands require `--apply`; AdGuard deployment additionally requires `--approve-exclusive-target-migration`. `cloud configure` is dry-run by default and post-verifies the exact public/admin repository, both enable variables, workflow-hosted Pages, Actions enabled with selected GitHub-owned-only actions and mandatory SHA pinning, a read-only/non-approving default token, and all three workflows active. It uses enable-only endpoints and monotonic permission narrowing; an active policy that would need broader access is rejected before mutation. `gate-release enable-policy` is an admin-scoped, enable-only, post-verified operation. `gate-release publish` binds the byte-fixed protocol-2 `gate-v2.0.2/filter.txt` only from the clean current default-branch head; protocol 1 remains rollback evidence and is rejected as a v2 compatibility path or fallback. A rerun for an already-published gate verifies that release's immutable metadata and attestations directly without the admin-only policy endpoint; an absent or draft gate cannot begin any mutation until the policy is readable and enabled. `gate-release verify` proves the exact immutable release metadata, sole asset, digests, attestations, URL, and downloaded bytes. Evidence destinations are create-new, never overwrite existing directories, and release evidence is bound to a clean exact Git commit. Exit codes are: `0` success, `2` usage, `3` prerequisite, `4` verification, `5` integrity, `6` transient external failure, `7` mutation failed and rolled back, and `8` rollback incomplete. The commands above are locale-independent.

Cloud apply requires a clean full default-head SHA, byte-identical local/remote workflow blobs, and the exact successful `verify` job/check from integration `15368`. It configures three default-branch-only environments and three reserved rulesets, including immutable creation/update/deletion protection for `refs/tags/gate-v2.0.2` bypassed only by integration `15368`. The private key is environment-scoped to `hdf-main-automation`; proof and push use separate fresh runners. Local gate publication dispatches the protected publisher workflow, and all dispatches are accepted only after bounded nonce/path/head/event/title observation.

`adguard csp-probe` is an optional Windows diagnostic, not an installation requirement. It authenticates the repository's fixed probe source and SHA-256, temporarily installs it with the executable manual `IsCustom=true` classification on AdGuard's official strict-CSP page, verifies exact origin/effective CSP and browser injection without exposing nonce values, then restores and twice verifies the exact pre-probe userscript state. Because AdGuard's management state can become readable before the filtering proxy reload finishes, the proof retries only with bounded fresh isolated browser contexts; one attempt must satisfy the complete contract, and partial evidence is never merged. Existing owned entries with a false classification are transactionally replaced with durable intent and bounded convergence; rollback preserves their original code, GM settings, enabled state, and classification exactly.

## 日本語

`scripts/hotdeal_focus_cli.py` は、ビルド、検証、リリース証拠、GitHub Actions、証拠ダウンロード、不変ゲートの公開／証明、Windows AdGuard の配布／ロールバックを再現する JSON-only CLI です。stdout には JSON を1個だけ出力し、ログは stderr に分離します。クラウド、不変ゲート、AdGuard の plan／deploy／verify には認証済み `gh` が必要です。`cloud configure` は既定で dry-run であり、正確な公開／管理者リポジトリ、2つの enable 変数、workflow Pages、selected かつ GitHub 所有 Action のみ・SHA pin 必須の Actions、read-only／PR 承認不可の既定 token、3 workflow の `active` 状態を変更後に厳密検証します。enable-only endpoint と単調な権限縮小だけを行い、権限拡大が必要な有効ポリシーは変更前に拒否します。`gate-release enable-policy` は管理者権限を確認する enable-only 操作で、`gate-release publish` は clean な現在の default branch HEAD だけから byte-fixed の protocol-2 `gate-v2.0.2/filter.txt` を一度だけ公開します。protocol 1 は rollback 証拠としてのみ保存し、v2 の互換経路や fallback として拒否します。公開済みゲートの再実行では管理者専用のポリシー API を使わず、そのリリース自身の不変メタデータと attestation を直接検証します。ゲートが存在しないかドラフトの場合は、ポリシーが読み取り可能かつ有効であることを証明するまで変更を開始しません。`gate-release verify` はメタデータ、唯一の資産、digest、attestation、URL、実ダウンロードを検証します。状態を変更する操作には `--apply`、AdGuard の実配布にはさらに `--approve-exclusive-target-migration` が必要です。証拠ディレクトリは新規作成のみで、リリース証拠は clean な Git commit に固定されます。終了コードは `0` 成功、`2` 使用法、`3` 前提条件、`4` 検証、`5` 整合性、`6` 外部の一時障害、`7` 変更失敗／ロールバック完了、`8` ロールバック未完了です。上記のコマンドはそのまま使用できます。

クラウド apply は clean な default-head full SHA、local/remote の3 workflow byte、integration `15368` の正確な `verify` job/check を要求します。default branch 限定の3 environment と、`refs/tags/gate-v2.0.2` の作成・更新・削除を integration `15368` 以外に禁止するものを含む3 ruleset を設定します。秘密鍵は `hdf-main-automation` environment のみに置き、proof と push は別 runner です。local gate publish は保護 publisher workflow を dispatch します。

`adguard csp-probe` は通常のインストールに不要な任意の Windows 診断です。固定ソースと SHA-256 を認証して `IsCustom=true` の手動拡張として一時導入し、nonce 値を公開せずに公式 strict-CSP ページ上の正確な CSP とブラウザー注入を検証した後、実行前のコード、GM 設定、有効状態、分類を正確に復元します。管理状態が読めても filtering proxy の reload が未完了の場合があるため、上限付きで毎回新しい隔離 browser context を使い、単一の試行が完全な証明を満たした場合だけ成功とします。試行間の部分証拠は結合しません。

## 简体中文

`scripts/hotdeal_focus_cli.py` 是用于可重现构建、验证、发布证据、GitHub Actions、证据下载、不可变网关发布／证明以及 Windows AdGuard 部署／回滚的 JSON-only CLI。stdout 仅输出一个 JSON 值，日志单独写入 stderr。云端、不可变网关及 AdGuard plan／deploy／verify 命令需要已认证的 `gh`。`cloud configure` 默认 dry-run，并在变更后精确验证公开／管理员仓库、两个启用变量、workflow Pages、仅允许 GitHub 自有 Action 且强制 SHA 固定的 selected Actions、只读且不能批准 PR 的默认 token，以及三个工作流全部 `active`。它只使用启用型端点和单调的权限收窄；若已启用策略需要扩大权限，则在变更前拒绝。`gate-release enable-policy` 是需要管理员权限、只能启用不能关闭并会事后验证的操作；`gate-release publish` 仅允许从干净且当前的默认分支 HEAD 一次性发布字节固定的 protocol-2 `gate-v2.0.2/filter.txt`。protocol 1 仅作为 rollback 证据保存，并拒绝作为 v2 的兼容路径或 fallback。对于已发布网关，重跑时无需管理员专用策略 API，而是直接验证该发布自身的不可变元数据与 attestation；若网关不存在或仍为草稿，则在证明策略可读且已启用之前不会开始任何变更。`gate-release verify` 会验证元数据、唯一资产、摘要、attestation、URL 和实际下载字节。会改变状态的操作必须显式使用 `--apply`；AdGuard 实际部署还必须使用 `--approve-exclusive-target-migration`。证据目录只能新建，不会覆盖现有目录，发布证据与干净且精确的 Git commit 绑定。退出码为：`0` 成功，`2` 用法，`3` 前置条件，`4` 验证，`5` 完整性，`6` 外部临时故障，`7` 变更失败但回滚完成，`8` 回滚未完成。上述命令与语言区域无关，可直接使用。

云端 apply 要求干净的默认分支完整 SHA、本地与远端三个 workflow 字节一致，以及 integration `15368` 的精确成功 `verify` job/check。它配置三个仅限默认分支的 environment 和三个保留 ruleset，其中 `refs/tags/gate-v2.0.2` 的创建、更新、删除仅 integration `15368` 可 bypass。私钥只存于 `hdf-main-automation` environment；证明与 push 使用不同 runner。本地 gate publish 只 dispatch 受保护的 publisher workflow。

`adguard csp-probe` 是普通安装不需要的可选 Windows 诊断。它先认证固定源码及 SHA-256，再以 `IsCustom=true` 的手动扩展临时安装，在不泄露 nonce 值的前提下验证官方 strict-CSP 页面上的精确 CSP 与浏览器注入，随后精确恢复运行前的代码、GM 设置、启用状态和分类。由于管理状态可在 filtering proxy 完成重载前变为可读，证明过程只在有上限的全新隔离浏览器 context 中重试；必须由单次尝试满足完整契约，绝不拼接多次尝试的部分证据。
