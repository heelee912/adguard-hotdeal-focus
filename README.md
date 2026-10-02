# AdGuard Hotdeal Focus

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

등록된 **핫딜 글**을 읽기 화면으로 만듭니다. 알구몬에서 평소처럼 열거나 글 주소로 직접 접근해도 적용됩니다. 제목·상품 정보·본문·댓글·대댓글은 원래 DOM 그대로 보존하고, 광고·헤더·푸터·사이드바·인기글·추천글·계정 UI·다른 글은 숨깁니다. 클리앙, 뽐뿌, 루리웹, 퀘이사존, 어미새, ZOD, 아카라이브의 등록된 PC·모바일 글 경로를 지원합니다.

### 설치

AdGuard의 **확장 프로그램 → Userscripts → URL로 추가**에서 아래 URL 하나만 추가하고 켜십시오.

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

일반 설치는 이 독립형 Userscript 하나로 끝납니다. 별도의 규칙이나 필터 목록은 필요하지 않습니다.

이전 핫딜 전용 필터 목록을 사용 중이면 해당 목록을 제거하고 이 스크립트만 사용하십시오.

### 사용

알구몬의 핫딜 링크를 평소처럼 여십시오. 읽기 화면 위쪽의 **알구몬으로 돌아가기 · 본문 · 댓글** 버튼으로 이동할 수 있습니다. 등록된 핫딜 글은 PC·모바일 전환 뒤에도 읽기 화면이 적용됩니다. 같은 핫딜 주소를 직접 열어도 적용되며, 일반 게시판·목록에는 적용하지 않습니다.

### 동작 범위와 업데이트

스크립트는 등록된 구조를 먼저 확인하고, 선택자나 글 경로가 바뀌었으면 제한된 독립 의미 판정으로 제목·본문·댓글이 하나의 완전한 글인지 다시 확인합니다. 본문·상품 정보·댓글 안팎 어디에 있든 광고·인기글·추천글·관련글·사이드바는 소유하지 않고 숨깁니다. 로딩 뒤 DOM이 바뀌어도 같은 판정을 반복하며, 기존 본문·댓글 DOM의 객체와 텍스트는 그대로 유지합니다.

AdGuard는 위 URL에서 새 버전을 받습니다. GitHub Actions는 PC가 꺼져 있어도 주기적으로 7개 사이트의 데스크톱·모바일 구조를 제한된 트래픽으로 검사합니다. 변경 후보는 반복 가능한 구조 증거, 무노출, 본문·댓글 보존, 변조 및 네트워크 검사를 모두 통과한 경우에만 자동 승격됩니다. Userscript 자체는 네트워크 요청을 만들거나 알구몬의 기본 클릭 동작을 바꾸지 않습니다.

개발·복구용 명령은 [CLI.md](CLI.md), 설계와 검증 경계는 [ARCHITECTURE.md](ARCHITECTURE.md)를 보십시오.

## English

This creates a reader view for registered hot-deal articles, opened through Algumon or visited directly. It preserves the original title, product information, body, comments, and replies, while hiding ads, headers, footers, sidebars, popular/recommended posts, account UI, and unrelated articles. Registered desktop and mobile article routes are supported for Clien, Ppomppu, Ruliweb, Quasarzone, Eomisae, ZOD, and Arca Live.

### Install

In **AdGuard → Extensions → Userscripts → Add by URL**, add and enable only:

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

This standalone Userscript is the complete normal installation. No separate rule or filter list is required.

If an older hot-deal filter list is installed, remove that list and use this Userscript instead.

### Use

Open a deal through Algumon normally. The reader toolbar provides **Return to Algumon · Body · Comments** navigation (displayed in Korean). Registered hot-deal articles retain reader mode across desktop/mobile redirects and direct address-bar visits. Ordinary boards and list pages are not filtered.

### Scope and updates

The script checks the registered structure first. If selectors or an article route changed, a bounded independent semantic proof must still identify one complete title/body/comment projection. Ads, popular/recommended/related posts, and sidebars are excluded wherever they are nested. The same classification runs after DOM updates while preserving the original article and comment nodes and text.

AdGuard receives new versions from the URL above. GitHub Actions continues bounded desktop/mobile checks for all seven sites while the PC is off, and promotes a candidate only after reproducible structure, zero-leak, content-preservation, tamper, and network gates pass. The Userscript itself makes no network requests and does not alter Algumon's native click behavior.

See [CLI.md](CLI.md) for reproducible operations and [ARCHITECTURE.md](ARCHITECTURE.md) for design and verification boundaries.

## 日本語

登録済みのホットディール記事を読書表示にします。Algumon の通常クリックでも直接アクセスでも適用されます。タイトル・商品情報・本文・コメント・返信は元の DOM のまま保持し、広告、ヘッダー、フッター、サイドバー、人気・おすすめ記事、アカウント UI、その他の記事は非表示にします。Clien、Ppomppu、Ruliweb、Quasarzone、Eomisae、ZOD、Arca Live の登録済み PC/モバイル記事経路に対応します。

### インストール

AdGuard の **拡張機能 → Userscripts → URL から追加**で、次の URL だけを追加して有効にしてください。

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

通常のインストールは、この単体 Userscript だけで完了します。別のルールやフィルタリストは不要です。

以前のホットディール専用フィルタリストを使用している場合は、そのリストを削除し、この Userscript に置き換えてください。

### 使い方

Algumon のホットディールリンクを通常どおり開いてください。記事の上部に Algumon に戻る・本文・コメントへの移動ボタンが表示されます（韓国語表示）。登録済みのホットディール記事は PC/モバイル転送後や直接アクセスでも読書表示になります。通常の掲示板や一覧には適用しません。

### 動作範囲と更新

登録済み構造を先に確認し、セレクタや記事経路が変わった場合は、制限付きの独立した意味判定でタイトル・本文・コメントが一つの完全な記事を構成することを再確認します。広告、人気・おすすめ・関連記事、サイドバーは入れ子の位置に関係なく除外されます。DOM の更新後も同じ判定を続け、元の本文・コメントのノードとテキストを保持します。

AdGuard は上記 URL から新しい版を取得します。GitHub Actions は PC が停止中でも 7 サイトのデスクトップ・モバイル構造を制限された通信量で検査し、再現可能な構造、無露出、本文・コメント保持、改変、ネットワークの各検査を通過した候補だけを昇格します。Userscript 自体はネットワーク要求を発生させず、Algumon の通常クリックも変更しません。

開発・復旧用のコマンドは [CLI.md](CLI.md)、設計と検証の境界は [ARCHITECTURE.md](ARCHITECTURE.md) を参照してください。

## 简体中文

已登记的优惠文章会变成阅读视图；从 Algumon 正常点击或直接访问都适用。标题、商品信息、正文、评论和回复保持原始 DOM；广告、页眉、页脚、侧栏、热门/推荐文章、账户界面和其他文章都会隐藏。支持 Clien、Ppomppu、Ruliweb、Quasarzone、Eomisae、ZOD、Arca Live 已登记的桌面与移动端文章路径。

### 安装

在 AdGuard 的 **扩展 → Userscripts → 通过 URL 添加**中，只添加并启用以下地址：

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

独立 Userscript 就是完整的常规安装；无需另加规则或过滤列表。

如果已安装旧版优惠专用过滤列表，请移除该列表，改用这个 Userscript。

### 使用

按平时方式从 Algumon 打开优惠链接。文章上方提供返回 Algumon、正文和评论的导航按钮（韩文显示）。已登记的优惠文章在桌面/移动端跳转或直接访问时都会启用阅读视图；普通论坛和列表页不适用。

### 范围与更新

脚本先验证已登记结构；如果选择器或文章路径发生变化，则通过有界的独立语义证明重新确认唯一完整的标题、正文和评论投影。无论广告、热门/推荐/相关文章或侧栏嵌套在什么位置，都会被排除。DOM 更新后会继续执行同一分类，同时保留原始正文和评论节点及文本。

AdGuard 会从上述 URL 获取新版本。即使 PC 关机，GitHub Actions 仍会以受限流量检查全部七个网站的桌面和移动结构；只有通过可复现结构、零泄漏、正文/评论保留、篡改和网络检查的候选才会晋升。Userscript 本身不会发起网络请求，也不会改变 Algumon 的原生点击行为。

开发与恢复命令见 [CLI.md](CLI.md)，设计与验证边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## License

[MIT](LICENSE)
