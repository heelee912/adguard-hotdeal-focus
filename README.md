# AdGuard Hotdeal Focus

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

AdGuard Hotdeal Focus는 알구몬에서 핫딜 글로 이동했을 때 **제목, 구매 정보, 본문, 전체 댓글과 답글만 원래 DOM 그대로 남기는** fail-closed 리더 게이트입니다. 광고, 헤더, 푸터, 사이드바, 인기글, 추천글, 다른 게시물, 회원 위젯 등 나머지는 모두 공개하지 않습니다.

지원 대상은 PC·모바일의 클리앙, 뽐뿌, 루리웹, 퀘이사존, 어미새, ZOD, 아카라이브입니다.

### 설치 — URL 하나

AdGuard의 **확장 프로그램 / Userscripts / URL로 추가**에서 다음 URL 하나만 설치하고 활성화하십시오.

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

사용자 필터나 별도 사용자 규칙은 필요하지 않습니다. `filter.txt`, `filter-static.txt`, 과거 `gate-v2.0.2` URL은 설치하지 마십시오. `gate-v2.0.2`는 구버전 구독자를 깨뜨리지 않기 위해 원격에만 보존된 레거시 증거이며 현재 릴리스·업데이트·검증 권위가 아닙니다.

구버전 Hotdeal Focus 규칙을 이미 쓰고 있다면 새 Userscript를 먼저 검증한 뒤 그 **7개 대상 전용 구버전 규칙만** 비활성화하거나 제거하십시오. 두 방식을 함께 실행하면 과거 CSS·scriptlet이 본문과 댓글을 다시 훼손할 수 있습니다. 새 설치에는 Userscript 외 항목이 없습니다.

AdGuard 공식 문서는 Windows·Android·Mac의 Userscript, `@downloadURL`, `@updateURL`, `GM_addElement`, `window.onurlchange` 지원과 URL 설치 방식을 설명합니다: [AdGuard Extensions](https://adguard.com/kb/general/extensions/).

Userscript의 `@downloadURL`과 `@updateURL`은 위 설치 URL과 동일합니다. 기기가 켜진 뒤 AdGuard가 확장 업데이트를 확인하면 더 높은 `@version`을 자동으로 받습니다.

알구몬 광고를 DNS에서 살리고 다른 사이트에서는 계속 차단하려면 [ALGUMON_ADS_NETWORK_POLICY.md](ALGUMON_ADS_NETWORK_POLICY.md)를 따르십시오. NextDNS의 전역 DNS 허용과 $domain=algumon.com AdGuard 웹 예외를 의도적으로 분리하며, Reader Gate 설치 항목을 늘리지 않습니다.

### 동작 원리

- `document-start`에서 페이지 전체를 먼저 잠가 초기 노출을 막습니다.
- 알구몬의 서명된 relay 응답, 공개 단기 seed, 현재 글 ID·제목·메타데이터를 함께 검증하며 seed 하나만 신뢰하지 않습니다.
- 사이트·경로·레이아웃 variant 하나가 정확히 결정되고 제목·구매정보·본문·댓글 경계가 완전할 때만 해당 원본 노드를 공개합니다.
- 댓글 mount 안의 의미 있는 모든 노드는 댓글/답글, 허용된 조작부, 숨김 chrome 중 하나로 완전히 분류되어야 합니다.
- DOM, CSSOM, shadow DOM, top layer, pseudo-content 또는 SPA URL이 바뀌면 다시 검증합니다. 불명확하거나 변조되면 같은 task에서 즉시 전체를 다시 잠급니다.
- 휴리스틱 fallback이나 부분 공개는 없습니다. 모르면 빈 화면으로 닫힙니다.

### PC가 꺼져 있어도 자동 대응

GitHub Actions가 매주 월요일 03:17 KST(일요일 18:17 UTC)에 알구몬의 정확한 7개 사이트 inventory를 한 번만 다시 수집합니다. 이 원본 수집은 global inventory 1회, 사이트 문서 7회, 사이트별 서명 relay 3회로 **최대 29회 시작**하도록 하드 캡이 걸려 있습니다. 후보 증명과 승격 재검증은 봉인된 source snapshot만 재사용하므로 알구몬을 다시 방문하지 않으며, 워크플로가 자기 자신을 재호출하지도 않습니다. 공유 레이아웃은 PC와 모바일 각각 최신 relay 표본 3개 이상이 동일한 semantic shape를 증명해야 승격됩니다. 후보는 과거 fixture, 현재 live DOM, zero-leak, 변조, 네트워크 충실도 테스트를 통과한 뒤에만 one-parent fast-forward 커밋으로 `main`에 승격됩니다.

Pages 배포 전에는 현재 공개 버전보다 낮거나 같은 버전의 다른 바이트를 거부합니다. 배포 후에는 cache-busting HTTPS 요청으로 실제 Userscript와 manifest 바이트가 예상 SHA-256과 같아질 때까지 확인합니다. PC가 꺼져 있어도 이 감지·검증·승격·배포는 GitHub에서 계속됩니다.

### Windows 자동 설치·검증

관리자 PowerShell에서 저장소 CLI를 실행하면 공개 manifest의 해시를 검증하고 Userscript 하나만 백업 가능한 transaction으로 설치합니다. 일반 User filter와 모든 비대상 필터 구독은 읽기 전·후 바이트/규칙 해시가 같아야 성공합니다.

```powershell
$releaseBase = 'https://heelee912.github.io/adguard-hotdeal-focus'
$manifest = Invoke-RestMethod "$releaseBase/release-manifest.json"
.\scripts\adguard_windows_cli.ps1 deploy `
  -UserscriptSource $manifest.installUrl `
  -ReleaseManifestSource "$releaseBase/release-manifest.json" `
  -ExpectedUserscriptSha256 $manifest.artifacts.'hotdeal-focus.user.js'.canonicalTextSha256 `
  -Apply
```

JSON-only 통합 CLI와 복구 명령은 [CLI.md](CLI.md), 경계와 자동 승격 설계는 [ARCHITECTURE.md](ARCHITECTURE.md)를 참고하십시오.

### 개발과 검증

Python 3.10+, Node.js 20+가 필요합니다.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
npm run build
npm run verify
npm run test:behavior
```

공개 Pages artifact는 `hotdeal-focus.user.js`와 감사용 `release-manifest.json` 두 파일뿐입니다. `filter-static.txt`는 내부 분석 산출물이며 구독 대상이 아닙니다. 롤백도 이전 버전으로 내리지 않고, 현재 live 검증을 다시 통과한 마지막 정상 내용을 더 높은 버전으로 재발행합니다.

## English

AdGuard Hotdeal Focus is a fail-closed reader gate for links opened from Algumon. It preserves the original DOM for the **title, purchase information, article body, and every comment/reply**, while withholding ads, headers, footers, sidebars, recommendations, popular posts, unrelated posts, and account widgets.

It covers desktop and mobile layouts for Clien, Ppomppu, Ruliweb, Quasarzone, Eomisae, ZOD, and Arca Live.

### Install one URL

Add and enable this single URL under **AdGuard → Extensions / Userscripts → Add by URL**:

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

No custom filter or user rule is required. Do not install `filter.txt`, `filter-static.txt`, or the old `gate-v2.0.2` URL. The old remote gate remains immutable only for existing subscribers and is not part of the current release, update, or verification authority.

When upgrading from old Hotdeal Focus rules, verify the new Userscript first, then disable or remove only the old rules scoped to these seven targets. Running both authorities can let obsolete CSS or scriptlets damage the article or comments. Fresh installations contain only the Userscript.

The Userscript locks the document at `document-start`, proves one exact semantic projection, then reveals only owned original nodes. DOM/CSSOM/shadow/top-layer/SPA changes are revalidated. Any ambiguity or tamper synchronously returns the page to a terminal blank state; there is no heuristic fallback or partial reveal.

For the separate policy that permits the needed Algumon ad DNS hosts while web filtering still blocks them on other sites, see [ALGUMON_ADS_NETWORK_POLICY.md](ALGUMON_ADS_NETWORK_POLICY.md). It deliberately separates global NextDNS resolution from $domain=algumon.com AdGuard web exceptions and adds no Reader Gate runtime.

GitHub Actions runs once each Monday at 03:17 KST (Sunday 18:17 UTC) without a local PC. The one source collection has a hard cap of **29 starts**: one global inventory, seven source documents, and three signed relays per source. Candidate proof and promotion retest reuse a sealed source snapshot and make zero additional Algumon requests; no workflow self-dispatches another Algumon audit. A shared layout requires at least three fresh Algumon relay proofs for **each** applicable desktop and mobile profile. Historical fixtures, current live DOM, zero-leak, tamper, and network-fidelity tests must all pass before a one-parent fast-forward promotion. Pages rejects downgrade or same-version byte replacement and verifies the live HTTPS bytes after deployment.

The Windows command shown in the Korean section installs only the Userscript and requires all unrelated User-filter and subscription hashes to remain unchanged. See [CLI.md](CLI.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for machine-readable operations and the trust model.

## 日本語

AdGuard Hotdeal Focus は、Algumon から開いた特価記事で **タイトル、購入情報、本文、すべてのコメント／返信だけ**を元の DOM のまま表示する fail-closed リーダーゲートです。広告、ヘッダー、フッター、サイドバー、人気記事、関連記事などは表示しません。

AdGuard の **拡張機能 / Userscripts / URL から追加**で、次の URL だけをインストールして有効化してください。

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

カスタムフィルターは不要です。`filter.txt`、`filter-static.txt`、旧 `gate-v2.0.2` はインストールしないでください。Userscript は `document-start` でページを先にロックし、PC・モバイル双方の意味的境界を完全に証明できた場合だけ元ノードを公開します。不明確な変更や改変を検出すると即座に全体を再ロックし、部分表示や推測 fallback は行いません。

旧 Hotdeal Focus ルールから移行する場合は、新 Userscript の検証後にこの7対象専用の旧ルールだけを無効化または削除してください。新規インストールは Userscript 1個だけです。

GitHub Actions は毎週月曜日 03:17 KST（日曜日 18:17 UTC）に一度だけ監視・検証・昇格・Pages 配布を実行するため、PC がオフでも自動対応は継続します。Algumon の原本収集は最大 29 開始に固定され、候補証明と再検証は封印済み snapshot を再利用して Algumon を再訪しません。ワークフロー自身の再起動も行いません。

## 简体中文

AdGuard Hotdeal Focus 是一个 fail-closed 阅读门控脚本。通过 Algumon 打开优惠文章时，它只保留原始 DOM 中的**标题、购买信息、正文以及全部评论/回复**；广告、页眉页脚、侧栏、热门文章、推荐文章和其他噪声均不公开。

请在 **AdGuard → 扩展 / Userscripts → 通过 URL 添加**中只安装并启用以下地址：

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

无需自定义过滤器。请勿安装 `filter.txt`、`filter-static.txt` 或旧的 `gate-v2.0.2`。Userscript 在 `document-start` 阶段先锁住整页，只有在桌面端和移动端的语义边界都得到完整证明后才显示原始节点。遇到未知结构或篡改时会立即重新锁定整页，不进行猜测式 fallback，也不会部分显示。

从旧版 Hotdeal Focus 规则升级时，请先验证新 Userscript，再仅禁用或删除作用于这七个目标站点的旧规则。全新安装只有一个 Userscript。

GitHub Actions 每周一 03:17 KST（周日 18:17 UTC）仅在云端执行一次监测、验证、自动晋升和 Pages 发布，因此即使本地电脑关机，自动响应仍会继续运行。Algumon 源采集硬性限制为最多 29 次启动；候选证明和复验只复用密封 snapshot，不会再次访问 Algumon，工作流也不会自行再次调度。

## License

[MIT](LICENSE)
