# 핫딜 보러 갔다가 인기글로 새는 게 싫어서, 본문·댓글만 남기는 스크립트를 만들었습니다

알구몬에서 핫딜 하나 눌렀다가, 옆에 있는 인기글이나 추천글을 더 오래 보고 있었던 적 있으신가요?

상품 정보와 댓글만 읽고 돌아오고 싶어서 만든 유저스크립트입니다. 가격을 보러 갔다가 불필요한 논쟁글까지 읽고 오는 일을 좀 줄여 보자는 생각으로 만들었습니다.

## 이렇게 달라집니다

- 광고·사이드바·인기글·추천글·다른 글 목록을 숨깁니다.
- 가격·구매 링크·본문 사진과 영상·댓글·대댓글은 원래 페이지 그대로 남깁니다.
- 글 위쪽에 **알구몬으로 돌아가기 / 본문 / 댓글** 버튼이 생깁니다.
- 설치한 다음에는 평소처럼 핫딜 링크를 열면 됩니다. 같은 글을 직접 열어도 적용됩니다.

클리앙·뽐뿌·루리웹·퀘이사존·어미새·ZOD·아카라이브의 지원 핫딜 글에 적용됩니다. 사이트 전체를 바꾸는 것은 아니고, 일반 게시판이나 목록은 그대로입니다.

## 설치

브라우저용 AdGuard 확장 프로그램만으로는 설치할 수 없습니다. [Windows용 AdGuard](https://adguard.com/ko/adguard-windows/overview.html) 또는 [Android용 AdGuard](https://adguard.com/ko/adguard-android/overview.html) 독립 실행형 앱을 먼저 설치해 주세요.

이 프로젝트와 유저스크립트는 무료입니다. AdGuard 독립 실행형 앱은 별도 제품이며, 유저스크립트 기능을 사용하려면 유효한 체험판 또는 라이선스가 필요합니다. 자세한 구분은 [AdGuard 라이선스 안내](https://adguard.com/kb/ko/general/license/what-is/)와 [Android 무료·정식 버전 비교](https://adguard.com/kb/ko/adguard-for-android/features/free-vs-full/)에서 확인할 수 있습니다.

GitHub 가입이나 코드 수정은 필요 없습니다. 아래 주소는 AdGuard의 **확장**에 추가하며, **DNS 필터나 광고 차단 필터에 넣는 주소가 아닙니다.**

- **PC(Windows):** AdGuard 앱에서 **보호 → 확장 프로그램 → 확장 프로그램 추가 → 파일 또는 URL에서 가져오기**를 열고 아래 주소를 붙여넣어 설치한 뒤, 확장 프로그램 전체 스위치와 **AdGuard Hotdeal Focus Reader Gate** 항목을 모두 켭니다.
- **휴대폰(Android):** AdGuard 앱 하단 맨 오른쪽의 **설정 → 필터링 → 확장 → 확장 프로그램 추가 → 파일 또는 URL에서 가져오기 → 다음 → URL 붙여넣기 → 추가 → 정보 확인 → 추가** 순서로 설치한 뒤, 확장 전체 스위치와 **AdGuard Hotdeal Focus Reader Gate** 항목을 모두 켭니다.

```text
https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
```

이미 열어 둔 핫딜 글은 새로고침해 주세요.

이전 핫딜 전용 필터·사용자 규칙은 제거하고 이 유저스크립트만 사용해 주세요.

보호 설정도 확인해 주세요.

- **Windows:** AdGuard 보호와 **설정 → 앱 설정 → 네트워크 설정 → HTTPS 필터링**을 켜고, **앱 관리**에서 사용하는 브라우저의 라우팅·필터링·HTTPS 필터링 표시가 모두 녹색인지 확인합니다.
- **Android:** 홈 화면의 보호를 켠 뒤 **설정 → 필터링 → 네트워크 → HTTPS 필터링 → 보안 인증서**를 엽니다. Android 11 이상에서는 [AdGuard 공식 안내](https://adguard.com/kb/ko/adguard-for-android/solving-problems/manual-certificate/)에 따라 AdGuard CA 인증서를 사용자 저장소에 수동 설치합니다.

## 동작 확인

알구몬에서 지원 사이트의 핫딜 글을 엽니다. 가격·구매 링크·사진·영상·본문·전체 댓글과 답글은 원래 모습 그대로 보이고, 광고·사이드바·인기글·추천글·다른 글 목록은 보이지 않아야 합니다. 글 위쪽에 **알구몬으로 돌아가기 / 본문 / 댓글** 버튼이 보이면 적용된 상태입니다. 페이지 로딩 뒤 추가되거나 위치가 바뀐 요소도 다시 검사합니다.

## 업데이트와 제거

새 버전은 같은 설치 주소로 배포됩니다. Windows에서는 AdGuard의 **업데이트 확인**으로 확장 프로그램 업데이트도 확인할 수 있습니다. Android에서 바로 최신판으로 바꾸려면 같은 URL을 다시 추가하고, 같은 이름이 이미 설치되어 있다는 안내가 나오면 **교체**를 선택합니다. 기존 Android 항목을 먼저 제거할 필요는 없습니다.

제거할 때 Windows에서는 **확장 프로그램** 목록에서 해당 스크립트 행의 **⋮** 메뉴를 사용합니다. Android에서는 목록에서 해당 스크립트를 탭해 상세 화면을 연 뒤 제거합니다.

## 문제 해결

아무 변화가 없으면 독립 실행형 AdGuard 앱, 앱 보호, HTTPS 필터링, 그리고 Windows의 **확장 프로그램** 또는 Android의 **확장** 화면에서 전체 스위치와 스크립트 항목이 모두 켜져 있는지 확인해 주세요. 내용이 잘리거나 불필요한 요소가 남으면 이전 핫딜 필터가 제거됐는지 확인한 뒤 [문제 제보](https://github.com/heelee912/adguard-hotdeal-focus/issues)에 **글 주소·운영체제·브라우저**를 남겨 주세요.

Windows 실제 최신 Chrome과 최신 Chrome의 모바일 UA·터치·390px 조건으로 7개 지원 사이트를 확인했습니다. **2026-10-03 실제 Android 기기의 Chrome에서 지원 7개 사이트의 대표 글을 열어 본문·댓글과 이동 버튼, 주변 요소 숨김을 확인했습니다.**

[AdGuard Hotdeal Focus — 설치 안내와 소스코드](https://github.com/heelee912/adguard-hotdeal-focus)
