# Optional NextDNS ad-host guidance

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

### 기본 설치

Reader Gate의 일반 설치는 [README](README.md)에 있는 독립형 Userscript 하나입니다. NextDNS 설정은 설치에 포함되지 않으며 필요하지도 않습니다.

### DNS의 한계

NextDNS는 DNS 호스트 이름만 보고, 요청을 만든 페이지·탭·referrer는 보지 못합니다. 따라서 “알구몬에서만 광고 네트워크를 허용하고 다른 사이트에서는 차단”하는 DNS 규칙은 만들 수 없습니다. 특정 호스트를 Allowlist에 넣으면 그 호스트를 쓰는 다른 사이트에도 영향을 줄 수 있습니다.

### 고급 웹 필터 경계

이는 일반 Reader Gate 설치에 포함되지 않습니다. 별도 웹 정책을 의도적으로 사용할 때의 정확한 원본은
`https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt`입니다.
예외는 모두 `$domain=algumon.com`으로 한정되어 실패 시 허용하지 않는 방식으로 유지됩니다. NextDNS만으로는 이 요청 출처 범위를 만들 수 없습니다.

### 꼭 필요할 때만 정확한 호스트 허용

알구몬 광고 전달 호스트를 일부러 허용해야 하는 경우에만 다음 순서로 설정하십시오.

1. 알구몬 글을 평소처럼 한 번 열고 NextDNS Logs에서 실제로 차단되어 필요한 정확한 호스트를 확인합니다.
2. 확인한 정확한 호스트만 NextDNS Allowlist에 추가합니다. 상위 도메인 전체는 추가하지 않습니다.
3. 같은 호스트를 쓰는 다른 사이트에도 허용 효과가 생길 수 있음을 감수하고, 필요 없어지면 해당 항목을 제거합니다.

아래는 과거에 관찰된 후보이며, 모두를 미리 추가하는 설치 목록이 아닙니다.

    safeframe.googlesyndication.com
    pagead2.googlesyndication.com
    tpc.googlesyndication.com
    securepubads.g.doubleclick.net
    pubads.g.doubleclick.net
    googleads.g.doubleclick.net
    googletagservices.com
    googleadservices.com
    beacons.gvt2.com

### Userscript의 경계

페이지가 브라우저에 로드된 뒤 Userscript는 DOM만 다룹니다. DNS 해석이나 네트워크 필터의 허용·차단을 바꾸지 못하며, 차단되어 도착하지 않은 광고 자산이나 검증하지 못한 DOM 변화를 임의로 복구하지 않습니다.

## English

### Normal installation

The normal Reader Gate installation is the one standalone Userscript in the [README](README.md). NextDNS configuration is neither part of nor required for installation.

### DNS boundary

NextDNS sees only a DNS hostname, not the page, tab, or referrer that caused the lookup. It therefore cannot create a DNS rule that allows an ad network only on Algumon while blocking it elsewhere. An Allowlist entry for one host can also affect other sites that use that host.

### Advanced web-filter boundary

This is not part of normal Reader Gate installation. If the separately maintained
web policy is deliberately used, its exact source is
`https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt`.
It is fail-closed: every exception remains `$domain=algumon.com` scoped. NextDNS alone cannot provide that initiator-aware page scope.

### Allow an exact host only when necessary

Use this optional path only when you deliberately need an Algumon ad-delivery host to be allowed.

1. Open an Algumon article once in the normal way and use NextDNS Logs to identify the exact host that is both blocked and required.
2. Add only that exact host to the NextDNS Allowlist. Do not allow a whole parent domain.
3. Accept that the entry can permit the same host on other sites, and remove it when it is no longer needed.

The following are previously observed candidates, not a list to install wholesale.

    safeframe.googlesyndication.com
    pagead2.googlesyndication.com
    tpc.googlesyndication.com
    securepubads.g.doubleclick.net
    pubads.g.doubleclick.net
    googleads.g.doubleclick.net
    googletagservices.com
    googleadservices.com
    beacons.gvt2.com

### Userscript boundary

After a page is loaded in the browser, the Userscript changes only its DOM. It cannot change DNS resolution or network-filter allow/block decisions, and it does not arbitrarily restore blocked ad assets or unverified DOM changes.

## 日本語

### 通常のインストール

Reader Gate の通常のインストールは、[README](README.md) にある単体 Userscript だけです。NextDNS の設定はインストールの一部ではなく、必要もありません。

### DNS の境界

NextDNS が見られるのは DNS ホスト名だけであり、名前解決を発生させたページ、タブ、referrer は見られません。そのため「Algumon だけで広告ネットワークを許可し、他サイトではブロックする」DNS ルールは作れません。あるホストを Allowlist に追加すると、そのホストを使う他サイトにも影響する可能性があります。

### 高度な Web フィルタ境界

これは通常の Reader Gate インストールには含まれません。別途 Web ポリシーを意図して使う場合の正確な原本は
`https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt` です。
例外はすべて `$domain=algumon.com` に限定され、失敗時に許可へ倒れないよう維持されます。NextDNS だけでは、このリクエスト発生元の範囲は作れません。

### 必要な場合だけ正確なホストを許可

Algumon の広告配信ホストを意図的に許可する必要がある場合だけ、次の手順を使用してください。

1. Algumon の記事を通常どおり一度開き、NextDNS Logs で実際にブロックされ、かつ必要な正確なホストを確認します。
2. 確認した正確なホストだけを NextDNS Allowlist に追加します。親ドメイン全体は許可しません。
3. 同じホストを使う他サイトにも許可の影響が及ぶ可能性を受け入れ、不要になったら項目を削除します。

次は過去に観測された候補であり、まとめて追加するための一覧ではありません。

    safeframe.googlesyndication.com
    pagead2.googlesyndication.com
    tpc.googlesyndication.com
    securepubads.g.doubleclick.net
    pubads.g.doubleclick.net
    googleads.g.doubleclick.net
    googletagservices.com
    googleadservices.com
    beacons.gvt2.com

### Userscript の境界

ページがブラウザに読み込まれた後、Userscript が扱えるのは DOM だけです。DNS 解決やネットワークフィルタの許可・ブロック判断は変更できず、ブロックされて届かなかった広告アセットや未検証の DOM 変更を任意に復元することもありません。

## 简体中文

### 常规安装

Reader Gate 的常规安装只有 [README](README.md) 中的独立 Userscript。NextDNS 配置不属于安装步骤，也不是必需的。

### DNS 的边界

NextDNS 只能看到 DNS 主机名，看不到触发解析的页面、标签页或 referrer。因此无法用 DNS 规则实现“只在 Algumon 放行广告网络、在其他网站拦截”。将某个主机加入 Allowlist 也可能影响使用该主机的其他网站。

### 高级 Web 过滤边界

这不属于 Reader Gate 的常规安装。若有意使用单独维护的 Web 策略，其准确来源是
`https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt`。
所有例外均限定为 `$domain=algumon.com`，并保持失败时不放行的行为。仅靠 NextDNS 无法实现这一请求发起页面范围。

### 仅在必要时放行精确主机

只有在您明确需要放行 Algumon 广告投放主机时，才采用以下可选步骤。

1. 按正常方式打开一次 Algumon 文章，并在 NextDNS Logs 中确认实际被拦截且必需的精确主机。
2. 仅将确认的精确主机加入 NextDNS Allowlist；不要放行整个父域名。
3. 接受该条目可能也会放行其他网站上的同一主机；不再需要时将其删除。

以下是此前观察到的候选主机，不是应当一次性安装的列表。

    safeframe.googlesyndication.com
    pagead2.googlesyndication.com
    tpc.googlesyndication.com
    securepubads.g.doubleclick.net
    pubads.g.doubleclick.net
    googleads.g.doubleclick.net
    googletagservices.com
    googleadservices.com
    beacons.gvt2.com

### Userscript 的边界

页面加载到浏览器后，Userscript 只能处理其 DOM。它不能改变 DNS 解析或网络过滤的放行/拦截决定，也不会任意恢复被拦截而未到达的广告资源或未经验证的 DOM 变化。
