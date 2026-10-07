# AdGuard Hotdeal Focus

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

**핫딜만 보러 갔다가 인기글로 새지 않도록.** 핫딜 글에서 광고·사이드바·인기글·추천글·다른 글 목록을 숨기고, 상품 정보와 본문·댓글을 읽는 데 필요한 화면만 남기는 유저스크립트입니다.

- 가격·구매 링크·사진·영상·댓글·대댓글은 원래 페이지 그대로 보존합니다.
- **알구몬으로 돌아가기 · 본문 · 댓글** 버튼으로 필요한 곳에 바로 이동합니다.
- 클리앙·뽐뿌·루리웹·퀘이사존·어미새·ZOD·아카라이브의 지원 핫딜 글에 적용됩니다. 일반 게시판과 목록은 바꾸지 않습니다.
- 알구몬에서 열거나 같은 글 주소로 직접 들어가도 동작합니다.

### 설치

브라우저 확장 프로그램만으로는 설치할 수 없습니다. 다음 **AdGuard 독립 실행형 앱**을 먼저 설치해 주세요.

- [Windows용 AdGuard 공식 다운로드](https://adguard.com/ko/adguard-windows/overview.html)
- [Android용 AdGuard 공식 다운로드](https://adguard.com/ko/adguard-android/overview.html)

이 프로젝트와 유저스크립트는 무료입니다. AdGuard 독립 실행형 앱은 별도 제품이며, 유저스크립트 기능을 사용하려면 유효한 체험판 또는 라이선스가 필요합니다. 자세한 구분은 [AdGuard 라이선스 안내](https://adguard.com/kb/ko/general/license/what-is/)와 [Android 무료·정식 버전 비교](https://adguard.com/kb/ko/adguard-for-android/features/free-vs-full/)에서 확인할 수 있습니다.

GitHub 가입이나 코드 수정은 필요 없습니다. 아래 주소를 복사해 AdGuard 앱의 **확장**에 추가하면 됩니다. **DNS 필터나 광고 차단 필터에 추가하는 주소가 아닙니다.**

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

- **PC(Windows):** AdGuard 앱에서 **보호 → 확장 프로그램 → 확장 프로그램 추가 → 파일 또는 URL에서 가져오기**를 열고 위 주소를 붙여넣어 설치한 뒤, 확장 프로그램 전체 스위치와 **AdGuard Hotdeal Focus Reader Gate** 항목을 모두 켭니다.
- **휴대폰(Android):** AdGuard 앱 하단 맨 오른쪽의 **설정 → 필터링 → 확장 → 확장 프로그램 추가 → 파일 또는 URL에서 가져오기 → 다음 → URL 붙여넣기 → 추가 → 정보 확인 → 추가** 순서로 설치한 뒤, 확장 전체 스위치와 **AdGuard Hotdeal Focus Reader Gate** 항목을 모두 켭니다.

이미 열어 둔 핫딜 글은 새로고침합니다.

이전 핫딜 전용 필터·사용자 규칙은 제거하고 이 유저스크립트만 사용해 주세요.

메뉴 명칭은 [AdGuard 공식 유저스크립트 안내](https://adguard.com/kb/ko/general/extensions/#userscripts)와 [Android 확장 안내](https://adguard.com/kb/ko/adguard-for-android/features/settings/#extensions)에서 확인할 수 있습니다.

### 보호 확인

- **Windows:** AdGuard 보호를 켠 뒤 **설정 → 앱 설정 → 네트워크 설정 → HTTPS 필터링**을 켭니다. **앱 관리**에서 사용하는 브라우저의 라우팅·필터링·HTTPS 필터링 표시가 모두 녹색인지 확인합니다.
- **Android:** 홈 화면의 보호를 켠 뒤 **설정 → 필터링 → 네트워크 → HTTPS 필터링 → 보안 인증서**를 엽니다. Android 11 이상에서는 [AdGuard 공식 인증서 설치 안내](https://adguard.com/kb/ko/adguard-for-android/solving-problems/manual-certificate/)에 따라 AdGuard CA 인증서를 사용자 저장소에 수동 설치합니다.

### 사용

알구몬에서 지원 사이트의 핫딜 글을 엽니다. 가격·구매 링크·사진·영상·본문·전체 댓글과 답글은 원래 모습 그대로 보이고, 광고·사이드바·인기글·추천글·다른 글 목록은 보이지 않아야 합니다. 글 위쪽에 **알구몬으로 돌아가기 · 본문 · 댓글** 버튼이 보이면 적용된 상태입니다. 페이지 로딩 뒤 추가되거나 위치가 바뀐 요소도 다시 검사합니다.

### 업데이트와 제거

새 버전은 같은 설치 주소로 배포됩니다. Windows에서는 AdGuard의 **업데이트 확인**으로 앱·필터·확장 프로그램 업데이트를 함께 확인할 수 있습니다. Android에서 바로 최신판으로 바꾸려면 같은 URL을 다시 추가하고, 같은 이름이 이미 설치되어 있다는 안내가 나오면 **교체**를 선택합니다. 기존 Android 항목을 먼저 제거할 필요는 없습니다.

제거할 때 Windows에서는 **확장 프로그램** 목록에서 해당 스크립트 행의 **⋮** 메뉴를 사용합니다. Android에서는 목록에서 해당 스크립트를 탭해 상세 화면을 연 뒤 제거합니다. 잠시 끄기만 하려면 스크립트 스위치를 끄고 페이지를 새로고침합니다.

### 문제 해결

- 아무 변화가 없으면 독립 실행형 AdGuard 앱, 앱 보호, HTTPS 필터링, 그리고 Windows의 **확장 프로그램** 또는 Android의 **확장** 화면에서 전체 스위치와 스크립트 항목이 모두 켜져 있는지 확인하고 글을 다시 여십시오.
- `DNS_PROBE_FINISHED_NXDOMAIN`이 뜨면 **DNS 필터**에 이 `.user.js` 주소를 잘못 등록하지 않았는지 확인합니다. 잘못 등록된 항목만 끄고, 기존 DNS 서버와 DNS 보호는 그대로 유지합니다.
- 내용이 잘리거나 불필요한 요소가 남으면 이전 핫딜 필터가 제거됐는지 확인한 뒤 [문제 제보](https://github.com/heelee912/adguard-hotdeal-focus/issues)에 **글 주소·운영체제·브라우저**를 남겨 주세요.
- Windows 실제 최신 Chrome과 최신 Chrome의 모바일 UA·터치·390px 조건으로 7개 지원 사이트를 확인했습니다. **2026-10-03 실제 Android 기기의 Chrome에서 지원 7개 사이트의 대표 글을 열어 본문·댓글과 이동 버튼, 주변 요소 숨김을 확인했습니다.**

개발·복구 명령은 [CLI.md](CLI.md), 자동 점검과 설계는 [ARCHITECTURE.md](ARCHITECTURE.md)에 정리되어 있습니다.

## English

**Read the deal without getting sidetracked by popular posts.** This userscript hides ads, sidebars, recommendations, and unrelated post lists on supported hot-deal articles. It preserves the original prices, purchase links, photos, videos, comments, and replies. It supports hot-deal article routes on Clien, Ppomppu, Ruliweb, Quasarzone, Eomisae, ZOD, and Arca Live, both through Algumon links and direct visits. Ordinary boards and list pages are unchanged.

### Install

Use the **AdGuard app for Windows or Android**. This is a userscript, not a filter-list subscription, and the AdGuard browser extension alone does not install it.

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

1. Open the app's import menu:
   - **Windows:** Extensions → Add extension → Import from file or URL
   - **Android:** Settings → Filtering → Extensions → Add extension → Import from file or URL
2. Paste the URL, install the script, and enable it.
3. Reload any already-open deal articles.

Only this script is needed. If an older hot-deal filter list is installed, remove that list and use this script instead.

See the [AdGuard userscript guide](https://adguard.com/kb/general/extensions/#userscripts) and [Android extension settings](https://adguard.com/kb/adguard-for-android/features/settings/#extensions) if the menu differs.

### Use

Open deal links normally. The **Return to Algumon · Body · Comments** controls above the article indicate that reader mode is active (displayed in Korean). To turn it off, disable this script in AdGuard and reload the page.

### Scope and updates

The script rechecks elements that appear or move after loading and can accommodate some structural changes. New versions arrive from the same URL according to AdGuard's update settings. Major site changes can still need a fix; automatic handling of every future change is not guaranteed. If the article structure cannot be confirmed, original content is restored so the article and comments remain accessible.

Checks use real Chrome on Windows and mobile-width layouts. **On 2026-10-03, representative articles from all seven supported sites were opened in Chrome on a physical Android device, confirming the article body, comments, navigation controls, and hiding of surrounding elements.**

If it does not apply, check that the script is enabled and that AdGuard protection and HTTPS filtering cover the browser. For missing content or remaining clutter, [report the article URL, device, and browser](https://github.com/heelee912/adguard-hotdeal-focus/issues).

Developer commands: [CLI.md](CLI.md). Automated checks and design: [ARCHITECTURE.md](ARCHITECTURE.md).

## 日本語

**セール情報を見に来たのに、人気記事を読み続けてしまう。その寄り道を減らします。** 対応するホットディール記事の広告・サイドバー・おすすめ記事・ほかの記事一覧を隠し、価格・購入リンク・写真・動画・本文・コメント・返信は元のページのまま保持します。Clien、Ppomppu、Ruliweb、Quasarzone、Eomisae、ZOD、Arca Live の対応する記事で、Algumon のリンクからでも直接アクセスでも動作します。通常の掲示板や一覧は変更しません。

### インストール

**Windows または Android 用の AdGuard アプリ**で追加してください。フィルタリストではなく、ブラウザー用 AdGuard 拡張機能だけではインストールできません。

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

1. アプリでインポート画面を開きます。
   - **Windows:** 拡張機能 → 拡張機能を追加 → ファイルまたは URL からインポート
   - **Android:** 設定 → フィルタリング → 拡張機能 → 拡張機能を追加 → ファイルまたは URL からインポート
2. URL を貼り付け、インストールして有効にします。
3. 開いている記事を再読み込みします。

このスクリプト一つで利用できます。旧ホットディール専用フィルタリストを使用している場合は、そのリストを削除して置き換えてください。

メニューが異なる場合は [AdGuard のユーザースクリプト案内](https://adguard.com/kb/general/extensions/#userscripts)と [Android の拡張機能設定](https://adguard.com/kb/adguard-for-android/features/settings/#extensions)をご確認ください。

### 使い方

いつもどおり記事を開くだけで適用されます。記事上部の **Algumon に戻る・本文・コメント**への移動ボタンが動作中の目印です（韓国語表示）。停止するには、AdGuard でこのスクリプトを無効にして記事を再読み込みしてください。

### 動作範囲と更新

読み込み後に追加・移動された要素も再確認し、一部の構造変更には自動対応します。修正版は AdGuard の更新設定に従って同じ URL から取得します。大幅な変更には修正が必要になることがあり、今後のすべての変更への自動対応は保証しません。構造を確認できない場合は、本文とコメントを読めるよう元の内容を復元します。

検証は Windows の実際の Chrome とモバイル幅で行っています。**2026-10-03、Android 実機の Chrome で対応 7 サイトの代表記事を開き、本文・コメントと移動ボタンが保持され、周辺要素が非表示になることを確認しました。**

適用されない場合は、スクリプトが有効で、ブラウザーに AdGuard の保護と HTTPS フィルタリングが適用されているかご確認ください。内容の欠落や不要な表示は、[記事 URL・端末・ブラウザーを添えてご報告ください](https://github.com/heelee912/adguard-hotdeal-focus/issues)。

開発用コマンドは [CLI.md](CLI.md)、自動検査と設計は [ARCHITECTURE.md](ARCHITECTURE.md)をご覧ください。

## 简体中文

**看优惠，不再被热门帖子带跑。** 这个用户脚本隐藏支持的优惠文章中的广告、侧栏、推荐内容和其他帖子列表，保留原网页的价格、购买链接、图片、视频、正文、评论和回复。支持 Clien、Ppomppu、Ruliweb、Quasarzone、Eomisae、ZOD、Arca Live 的指定文章路径，从 Algumon 打开或直接访问都适用；不改动普通论坛和列表页。

### 安装

请使用 **Windows 或 Android 版 AdGuard 应用**。这是用户脚本，不是过滤列表订阅；仅安装 AdGuard 浏览器扩展无法完成此安装。

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

1. 在应用中打开导入菜单：
   - **Windows：** 扩展 → 添加扩展 → 从文件或 URL 导入
   - **Android：** 设置 → 过滤 → 扩展 → 添加扩展 → 从文件或 URL 导入
2. 粘贴地址，安装并启用脚本。
3. 刷新已经打开的优惠文章。

只需安装这个脚本。使用旧版优惠专用过滤列表的用户，请移除该列表并改用本脚本。

菜单不同时，可查看 [AdGuard 用户脚本说明](https://adguard.com/kb/general/extensions/#userscripts)和 [Android 扩展设置](https://adguard.com/kb/adguard-for-android/features/settings/#extensions)。

### 使用

照常打开优惠链接即可。文章上方出现**返回 Algumon、正文、评论**三个导航按钮，表示阅读模式已生效（韩文显示）。临时停用时，在 AdGuard 中关闭本脚本并刷新页面。

### 范围与更新

脚本会重新检查加载后新增或移动的元素，并自动适应部分结构变化。新版本根据 AdGuard 的更新设置从同一地址获取。网站大幅改版仍可能需要修复，不保证自动处理所有未来变化。无法确认文章结构时，会恢复原始内容，让正文和评论保持可读。

目前使用 Windows 上的真实 Chrome 和移动屏幕宽度检查。**2026-10-03，我们在 Android 实机的 Chrome 中打开了全部 7 个支持站点的代表文章，确认正文、评论和导航按钮得到保留，周边元素被隐藏。**

未生效时，请检查脚本是否开启，以及 AdGuard 保护和 HTTPS 过滤是否作用于所用浏览器。发现内容缺失或多余元素时，请[提供文章地址、设备和浏览器](https://github.com/heelee912/adguard-hotdeal-focus/issues)。

开发命令见 [CLI.md](CLI.md)，自动检查和设计见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## License

[MIT](LICENSE)
