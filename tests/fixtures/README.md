# DOM fixtures

Fixtures are sanitized, deterministic DOM contracts. Live acceptance runs only on GitHub-hosted runners through `scripts/audit_pages.mjs`.

- `dom-regressions.json` covers the June and July structures of every supported site/layout.
- `behavior-baseline.json` is the immutable released visible-node allow-set. Any newly exposed node or missing allowed node fails the audit.
- Executable synthetic cases in the auditor cover delayed rendering/no-flash, empty comments, image/table-only bodies, dynamic nested replies and media, marker/style tampering, SPA navigation, profile-independent runtime variant matching, and legitimate `.header`/`.related` descendants inside preserved content.

When adding a fixture:

1. Keep only the smallest DOM needed to reproduce the decision.
2. Remove names, account identifiers, cookies, tokens, and real post text.
3. Preserve structural attributes and use neutral placeholder content.
4. Record source site, layout, capture date, profile, and expected roles.
5. Never update a released baseline from an unproven DOM-drift candidate.

Evidence under `outputs/evidence/` is gitignored and uploaded as a short-lived CI artifact.

## 한국어

fixture는 개인정보와 실제 글 내용을 제거한 최소 DOM 계약입니다. 모든 사이트·레이아웃의 PC/모바일 동작, 본문·댓글 보존, 노이즈 0노출, 첫 화면 무노출을 GitHub 호스팅 러너에서 실행 검증합니다. 검증되지 않은 변조 후보가 기준 fixture를 자동으로 바꾸는 일은 없습니다.

## 日本語

fixture は個人情報と実投稿を除去した最小 DOM 契約です。本文・コメントの保持、不要要素のゼロ表示、初回描画時の非表示、PC/モバイル差分を GitHub ホストランナーで実行検証します。未検証候補が基準を自動更新することはありません。

## 中文

fixture 是移除个人信息和真实帖子内容后的最小 DOM 契约。GitHub 托管运行器会验证桌面端与移动端、正文与评论完整性、噪声零暴露以及首帧无闪现。未经验证的候选规则绝不会自动修改基线。
