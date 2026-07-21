# Hotdeal Focus machine CLI

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [中文](#中文)

## 한국어

`scripts/hotdeal_focus_cli.py`는 빌드, 검증, GitHub Actions/Pages 운영, 릴리스 증거, Windows AdGuard 유저스크립트 설치를 재현 가능하게 제어하는 JSON-only CLI입니다. stdout에는 JSON 값 하나만 출력하고 로그는 stderr로 분리합니다. 공개 설치 산출물은 아래 유저스크립트 하나뿐입니다.

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

사용자 필터, `filter.txt`, 별도 잠금 필터, 필터 마이그레이션은 현재 배포 계약에 포함되지 않습니다. Windows 배포는 기존 사용자 필터와 모든 표준 구독의 순서·메타데이터·규칙·비활성 규칙을 배포 전후 두 번 안정적으로 읽어 완전 동일함을 증명합니다. 차이가 생기면 새 유저스크립트만 롤백하고 성공으로 보고하지 않습니다.

```powershell
python scripts/hotdeal_focus_cli.py doctor --json
python scripts/hotdeal_focus_cli.py build --check --json --evidence-dir outputs/build-check-001
python scripts/hotdeal_focus_cli.py verify --profile release --json --evidence-dir outputs/verify-release-001

$sourceSha = git rev-parse HEAD
python scripts/hotdeal_focus_cli.py release-evidence `
  --source-ref $sourceSha `
  --output-dir outputs/release-evidence-001 `
  --json
```

`verify` 프로필은 `fast`, `release`, `live`입니다. `live`는 실제 대상 페이지를 검사하며, 접근할 수 없는 사이트를 부분 성공이나 추정 fallback으로 바꾸지 않습니다. 증거 디렉터리는 새 경로만 허용하고 기존 경로를 덮어쓰지 않습니다.

GitHub 운영 명령은 인증된 `gh`를 사용합니다. `configure`, `dispatch`, 증거 다운로드처럼 외부 상태를 바꾸는 작업은 명시적인 `--apply`가 필요합니다. `configure`는 정확한 저장소·기본 브랜치 HEAD·원격 workflow 바이트·성공한 CI를 먼저 증명한 뒤 `verify.yml`, `watch-dom.yml`, workflow 기반 Pages, 최소 권한 Actions, 기본 브랜치 보호를 설정하고 다시 검증합니다. 오래된 필터 게시 workflow와 게이트 태그는 활성 계약이 아니며 새로 쓰거나 지우지 않습니다.

```powershell
$sourceSha = git rev-parse HEAD
python scripts/hotdeal_focus_cli.py cloud configure --repo heelee912/adguard-hotdeal-focus --source-ref $sourceSha --apply --json --evidence-dir outputs/cloud-configure-001
python scripts/hotdeal_focus_cli.py cloud dispatch --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --apply --json
python scripts/hotdeal_focus_cli.py cloud status --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --run-id 123456789 --json
python scripts/hotdeal_focus_cli.py cloud watch --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --run-id 123456789 --json
python scripts/hotdeal_focus_cli.py cloud download-evidence --repo heelee912/adguard-hotdeal-focus --workflow watch-dom.yml --run-id 123456789 --output-root outputs/cloud-evidence --apply --json
```

Windows AdGuard 배포는 `.user.js` 한 개만 계획·설치·검증합니다. `plan`은 dry-run이고 실제 설치에만 `deploy --apply`를 사용합니다. `verify`는 읽기 전용입니다. `rollback`은 이 CLI가 만든 정확한 백업만 받습니다. `csp-probe`는 선택적인 실행 환경 진단이며 설치 필수 조건이 아닙니다.

```powershell
$manifestUrl = 'https://heelee912.github.io/adguard-hotdeal-focus/release-manifest.json'
python scripts/hotdeal_focus_cli.py adguard inspect --json
python scripts/hotdeal_focus_cli.py adguard plan --manifest-source $manifestUrl --json --evidence-dir outputs/adguard-plan-001
python scripts/hotdeal_focus_cli.py adguard deploy --manifest-source $manifestUrl --apply --json --evidence-dir outputs/adguard-deploy-001
python scripts/hotdeal_focus_cli.py adguard verify --manifest-source $manifestUrl --json --evidence-dir outputs/adguard-verify-001
python scripts/hotdeal_focus_cli.py adguard rollback --backup-path 'C:\absolute\backup-directory' --apply --json --evidence-dir outputs/adguard-rollback-001
python scripts/hotdeal_focus_cli.py adguard csp-probe --json --evidence-dir outputs/csp-probe-dry-run
```

종료 코드는 `0` 성공, `2` 사용법, `3` 실행 조건, `4` 검증, `5` 무결성, `6` 일시적 외부 오류, `7` 변경 실패·롤백 완료, `8` 롤백 미완료입니다.

## English

`scripts/hotdeal_focus_cli.py` is a JSON-only control surface for reproducible builds, verification, GitHub Actions/Pages operations, release evidence, and Windows AdGuard userscript deployment. It emits one JSON value on stdout and sends logs to stderr. The sole public install artifact is `hotdeal-focus.user.js` at the Pages URL above. Custom filters, `filter.txt`, a separate lock filter, and filter migration are outside the active release contract.

Windows deployment plans, installs, and verifies one userscript. It proves that the complete User filter and Standard subscription inventory—including order, metadata, rules, and disabled rules—is identical before and after deployment. Any difference rolls back only the newly installed userscript and cannot be reported as success. The command examples above are locale-independent.

Cloud configuration first proves the exact repository, default-branch head, remote workflow bytes, and successful CI. It then configures only `verify.yml`, `watch-dom.yml`, workflow-hosted Pages, least-privilege Actions, and default-branch protection, followed by exact post-verification. Old filter-publishing workflows and gate tags are archival, not active authority, and are neither created nor deleted.

Verification profiles are `fast`, `release`, and `live`. Live failures are never converted into partial success or an inferred fallback. Evidence directories are create-new and never overwrite existing evidence. Mutating operations require `--apply`; `adguard plan` and `adguard verify` are read-only.

## 日本語

`scripts/hotdeal_focus_cli.py` は、ビルド、検証、GitHub Actions／Pages、リリース証拠、Windows AdGuard への Userscript 配布を再現可能に制御する JSON-only CLI です。公開インストール成果物は上記 Pages URL の `hotdeal-focus.user.js` 1個だけです。カスタムフィルター、`filter.txt`、別のロックフィルター、フィルター移行は現行契約に含まれません。

Windows 配布では Userscript 1個だけを計画・インストール・検証し、既存の User filter と全 Standard subscription の順序、メタデータ、ルール、無効ルールが配布前後で完全一致することを証明します。差分があれば新しい Userscript だけをロールバックし、成功扱いしません。クラウド側は `verify.yml`、`watch-dom.yml`、workflow Pages、最小権限 Actions、default branch 保護だけを設定・再検証します。旧フィルター公開 workflow と gate tag は保存された履歴であり、現行の権威ではありません。

## 中文

`scripts/hotdeal_focus_cli.py` 是用于可重现构建、验证、GitHub Actions／Pages 运维、发布证据以及 Windows AdGuard Userscript 部署的 JSON-only CLI。唯一的公开安装产物是上述 Pages URL 中的 `hotdeal-focus.user.js`。自定义过滤器、`filter.txt`、独立锁定过滤器和过滤器迁移均不属于当前发布契约。

Windows 部署仅规划、安装并验证一个 Userscript，同时证明现有 User filter 与全部 Standard subscription 的顺序、元数据、规则及禁用规则在部署前后完全一致。若出现任何差异，只回滚新 Userscript，且绝不报告成功。云端只配置并复核 `verify.yml`、`watch-dom.yml`、workflow Pages、最小权限 Actions 和默认分支保护。旧过滤器发布 workflow 与 gate tag 仅为历史存档，不是当前权威。
