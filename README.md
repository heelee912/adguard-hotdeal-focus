# AdGuard Hotdeal Focus

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

알구몬에서 **일반 클릭으로 연 핫딜 글**만 읽기 화면으로 만듭니다. 제목·상품 정보·본문·댓글·대댓글은 원래 DOM 그대로 보존하고, 그 밖의 광고·헤더·푸터·사이드바·인기글·추천글·계정 UI·다른 글은 모두 숨깁니다. PC와 모바일에서 클리앙, 뽐뿌, 루리웹, 퀘이사존, 에누리/에오미새, ZOD, 아카라이브의 등록된 글 경로를 지원합니다.

### 설치

AdGuard의 **확장 프로그램 → Userscripts → URL로 추가**에서 아래 주소 하나만 추가하고 켜십시오.

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

이전 Hotdeal Focus를 쓰셨다면, 새 Userscript가 켜진 것을 확인한 뒤에만 예전의 7개 대상 사이트 전용 사용자 규칙을 지우거나 끄십시오. `filter.txt`나 `filter-static.txt`는 설치하지 않습니다.

### 사용

알구몬의 핫딜 링크를 평소처럼 클릭하십시오. 대상 사이트 주소를 직접 열면 의도적으로 빈 화면으로 잠깁니다. 이 방식이 일반 게시판·검색 결과·다른 링크에 필터가 오작동하지 않게 합니다.

### 자동 업데이트와 안전장치

AdGuard가 업데이트를 확인할 때 이 URL의 새 버전을 받습니다. 스크립트는 네트워크 요청을 만들지 않으며, 알구몬의 원래 클릭 동작도 바꾸지 않습니다. 대상 문서에 실제로 전달된 `algumon.com` referrer와 제목·본문·댓글의 완전한 의미 구조가 모두 확인될 때만 해제합니다. 직접 접속·모호한 구조·DOM 변경은 일부만 보여 주지 않고 잠긴 상태를 유지합니다.

GitHub Actions는 PC가 꺼져 있어도 매주 제한된 양의 공개 DOM 검증을 수행합니다. 알구몬 요청은 한 실행에 최대 29회로 고정되며, 실패한 결과를 바탕으로 추가 트래픽을 만들지 않습니다. 데스크톱·모바일 검증과 무노출·변조·네트워크 검사가 모두 통과한 경우에만 변경 후보가 승격됩니다.

개발·복구용 명령은 [CLI.md](CLI.md), 설계와 검증 경계는 [ARCHITECTURE.md](ARCHITECTURE.md)를 보십시오.

## English

This creates a reader view only for hot-deal articles opened through a normal click from Algumon. It preserves the original title, product information, body, comments, and replies, while hiding every other surface: ads, headers, footers, sidebars, popular/recommended posts, account UI, and unrelated articles. Supported registered routes cover desktop and mobile layouts for Clien, Ppomppu, Ruliweb, Quasarzone, Eomisae, ZOD, and Arca Live.

### Install

In **AdGuard → Extensions → Userscripts → Add by URL**, add and enable only:

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

If you used an earlier Hotdeal Focus version, first confirm this Userscript is enabled, then remove or disable only the old rules dedicated to the seven target sites. Do not install `filter.txt` or `filter-static.txt`.

### Use

Open a deal through Algumon normally. Direct visits to a target article intentionally remain blank, so the reader gate cannot affect ordinary boards, search results, or unrelated links.

### Updates and safeguards

AdGuard receives newer versions from this URL when it checks for updates. The script makes no network requests and does not alter Algumon's native click behavior. A target is released only when the document carries an actual `algumon.com` referrer and its title, body, and comments form one complete semantic projection. Direct visits, ambiguity, and DOM drift stay locked rather than revealing a partial page.

GitHub Actions performs a bounded public DOM audit every week even when the local PC is off. Each run is capped at 29 Algumon request starts and never creates follow-up traffic from a failed result. A change can be promoted only after desktop/mobile, zero-leak, tamper, and network checks pass.

See [CLI.md](CLI.md) for reproducible operations and [ARCHITECTURE.md](ARCHITECTURE.md) for the design and verification boundaries.

## 日本語

Algumon から通常クリックで開いたホットディール記事だけを読書表示にします。タイトル・商品情報・本文・コメント・返信は元の DOM のまま保持し、広告、ヘッダー、フッター、サイドバー、人気・おすすめ記事、アカウント UI、その他の記事はすべて非表示にします。Clien、Ppomppu、Ruliweb、Quasarzone、Eomisae、ZOD、Arca Live の登録済み PC/モバイル経路に対応します。

### インストール

AdGuard の **拡張機能 → Userscripts → URL から追加**で、次の URL だけを追加して有効にしてください。

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

旧版を使っていた場合は、この Userscript が有効であることを確認してから、7 対象サイト専用の旧ルールだけを削除または無効化してください。`filter.txt` と `filter-static.txt` はインストールしません。

### 使い方

Algumon のホットディールリンクを通常どおり開いてください。対象記事を直接開いた場合は意図的に空白のままになります。通常の掲示板、検索結果、無関係なリンクに影響しないためです。

AdGuard の更新確認時にこの URL から最新版を受け取ります。スクリプトはネットワーク要求を発生させず、Algumon の通常クリックも変更しません。タイトル・本文・コメントがすべて正確に確認できた場合だけ表示し、曖昧さや DOM 変更があれば一部表示ではなくロックを維持します。

## 简体中文

它只会把从 Algumon 正常点击打开的优惠文章变成阅读视图。标题、商品信息、正文、评论和回复保持原始 DOM；广告、页眉、页脚、侧栏、热门/推荐文章、账户界面和其他文章都会隐藏。支持 Clien、Ppomppu、Ruliweb、Quasarzone、Eomisae、ZOD、Arca Live 已登记的桌面与移动端路径。

### 安装

在 AdGuard 的 **扩展 → Userscripts → 通过 URL 添加**中，只添加并启用以下地址：

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

如曾使用旧版 Hotdeal Focus，请先确认新 Userscript 已启用，再仅删除或关闭这七个目标站点的旧规则。不要安装 `filter.txt` 或 `filter-static.txt`。

### 使用

按平时方式从 Algumon 打开优惠链接。直接打开目标文章会故意保持空白，以免影响普通版块、搜索结果或无关链接。

AdGuard 检查更新时会从此 URL 获取新版本。脚本不会发起网络请求，也不会改变 Algumon 的原生点击行为。只有标题、正文和评论都被准确确认后才会显示；遇到歧义或 DOM 改动时会保持锁定，而不是显示不完整页面。

## License

[MIT](LICENSE)
