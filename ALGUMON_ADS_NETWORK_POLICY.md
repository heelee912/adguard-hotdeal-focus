# Algumon ad-network policy

[한국어](#한국어) · [English](#english) · [日本語](#日本語) · [简体中文](#简体中文)

## 한국어

### 결론

NextDNS만으로는 “알구몬에서만 광고 허용, 다른 모든 사이트에서는 계속
차단”을 만들 수 없습니다. NextDNS는 요청을 일으킨 페이지가 아니라 DNS
호스트만 보며, Allowlist 항목은 그 호스트와 모든 하위 호스트에 전역으로
우선합니다.

이 문서는 Reader Gate와 별개의 **알구몬 광고 네트워크 정책**입니다.
hotdeal-focus.user.js의 설치 수나 권한을 늘리지 않으며, 핫딜 대상 7개
사이트의 본문/댓글 판정에도 관여하지 않습니다.

### 강제하는 두 계층

1. **NextDNS DNS 계층** — 아래의 정확한 호스트만 Allowlist에 둡니다.
   루트 도메인 전체(doubleclick.net, googlesyndication.com 등)를
   허용하지 않습니다.
2. **AdGuard 웹 요청 계층** — 일반 광고 차단과 HTTPS 필터링을 켠 채,
   아래 URL의 전용 웹 필터를 추가합니다.

   https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt

웹 필터의 모든 예외에는 $domain=algumon.com이 명시되어 있습니다.
즉 DNS는 호스트를 해석할 수 있게 하되, 그 호스트를 요청한 페이지가
algumon.com 또는 하위 도메인이 아닌 한 AdGuard의 일반 차단 규칙이
계속 적용됩니다.

PC에서 AdGuard의 **로컬 DNS 필터링**도 켜져 있으면 그 DNS 차단이
NextDNS Allowlist와 웹 요청 예외보다 먼저 적용됩니다. 이 경우에는
로컬 DNS 필터링만 끄고 NextDNS는 그대로 유지합니다. Android에서
AdGuard의 DNS 모듈 자체가 NextDNS 연결 수단인 경우에는 그 모듈을
끄지 말고, 웹/HTTPS 필터링 계층을 유지합니다.

NextDNS에 넣을 호스트는 다음과 같습니다.

    safeframe.googlesyndication.com
    pagead2.googlesyndication.com
    tpc.googlesyndication.com
    securepubads.g.doubleclick.net
    pubads.g.doubleclick.net
    googleads.g.doubleclick.net
    googletagservices.com
    googleadservices.com
    beacons.gvt2.com

### 절대 넣지 않는 규칙

- @@||algumon.com^$document처럼 알구몬 전체 필터링을 끄는 규칙
- @@||doubleclick.net^ 또는 @@||googlesyndication.com^처럼 루트
  도메인 전체를 허용하는 규칙
- DNS 필터에 $domain=algumon.com을 붙이는 규칙
  DNS에는 페이지 출처 정보가 없어 이것은 사이트별 예외가 되지 않습니다.

Android에서 일반 AdGuard 웹 필터/HTTPS 필터링이 꺼져 있으면 이 정책의
두 번째 계층이 없으므로, NextDNS Allowlist를 더 넓히지 않습니다. 이때는
다른 사이트 차단 보장을 지키기 위해 fail-closed로 유지합니다.

### 검증과 변경

알구몬을 크롤링하거나 반복 요청하지 않습니다. 사용자가 평소처럼 글 하나를
열었을 때만 NextDNS Logs와 AdGuard Filtering Log를 확인합니다. 새 호스트가
실제로 보이면, 먼저 전용 웹 필터에 $domain=algumon.com 예외가 있는지
검증하고 그 후에만 해당 정확한 호스트를 NextDNS Allowlist에 추가합니다.
GitHub는 전용 웹 필터의 변경을 공개·검증·배포할 수 있지만, NextDNS는
페이지 출처를 식별할 수 없으므로 무검증 자동 전역 허용은 하지 않습니다.

되돌리려면 전용 웹 필터와 NextDNS의 같은 호스트 항목을 함께 제거하면 됩니다.

## English

### Decision

NextDNS alone cannot implement “allow ads only on Algumon while blocking them
everywhere else.” It sees a DNS hostname, not the page that initiated the
lookup, and each Allowlist entry takes global precedence for that host and its
subdomains.

This is a separate **Algumon ad-network policy**. It adds no Reader Gate
runtime or permission and does not participate in the seven hot-deal sites'
article/comment projection.

### Required composition

1. Put only the exact hostnames below in the NextDNS Allowlist. Never allow a
   whole parent such as doubleclick.net or googlesyndication.com.
2. Keep ordinary AdGuard web filtering and HTTPS filtering enabled, then add
   this scoped web-filter subscription:

   https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt

Every exception in that list uses $domain=algumon.com. DNS can therefore
resolve the required delivery host, while ordinary AdGuard request rules still
block the same host when the initiator is not Algumon.

If AdGuard for Windows also has its local DNS filtering enabled, that local
DNS block happens before either the NextDNS Allowlist or the scoped web
exception. Disable only that local DNS module and keep NextDNS active. Do not
do this on Android when that AdGuard DNS module itself is the NextDNS transport;
keep the web/HTTPS filtering layer there instead.

    safeframe.googlesyndication.com
    pagead2.googlesyndication.com
    tpc.googlesyndication.com
    securepubads.g.doubleclick.net
    pubads.g.doubleclick.net
    googleads.g.doubleclick.net
    googletagservices.com
    googleadservices.com
    beacons.gvt2.com

Do not use a document-wide exception for Algumon, a root-domain exception for
Google ad infrastructure, or a DNS rule pretending to use $domain; DNS has no
initiator context. If normal AdGuard web/HTTPS filtering is unavailable, do not
broaden the NextDNS Allowlist: the safe result is to remain blocked.

Validation is deliberately low-traffic: inspect the two filtering logs after
one ordinary article visit. A newly observed host is added only after a
matching $domain=algumon.com web exception exists. GitHub can publish and
verify the scoped web list; it must not create an unreviewed global NextDNS
allow without an initiator-aware enforcement layer.

## 日本語

NextDNS 単体では「Algumon だけで広告を許可し、他サイトではブロック」を
実現できません。DNS は要求元ページを識別せず、Allowlist は対象ホストと
そのサブドメインに全体適用されます。

したがって、上記の **正確なホスト**だけを NextDNS で許可し、通常の
AdGuard Web/HTTPS フィルタを有効にしたまま、次の URL の専用フィルタを
追加してください。

https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt

各例外は $domain=algumon.com に限定されます。Algumon 以外から同じ
ホストへ送られた要求は通常の AdGuard ルールでブロックされ続けます。
Web/HTTPS フィルタが無効なら NextDNS の許可範囲を広げず、fail-closed を
維持します。この設定は Reader Gate の Userscript を追加しません。

## 简体中文

仅靠 NextDNS 无法实现“只在 Algumon 放行广告、其他网站继续拦截”。
DNS 看不到发起请求的页面；Allowlist 会对该主机及其子域全局生效。

因此，只将上列**精确主机**加入 NextDNS Allowlist，并保持 AdGuard 的
普通网页过滤和 HTTPS 过滤开启，再添加以下限定网页过滤订阅：

https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/algumon-ads-webfilter.txt

其中每条例外都使用 $domain=algumon.com。DNS 可以解析所需广告主机，
而非 Algumon 页面发起的相同请求仍由普通 AdGuard 规则拦截。若网页/HTTPS
过滤未启用，不扩大 NextDNS Allowlist，保持 fail-closed。此设置不会增加
Reader Gate Userscript。
