# AFL++

**AFL**은 Mutational 방식의 coverage guided fuzzer로 많은 연구에서 사용되고 있었지만, 현재 제작자인 Michal Zalewski가 추가적인 관리를 하지 않는 것으로 보인다. 이런 상황에서 **AFL++**은 **AFL**과 관련한 다양한 추가 기능들을 더해 새로운 프로젝트로 만든 것으로, 현재 오픈 소스로 운영되고 있다.

## AFL++ 설치

### Dependency

```bash
sudo apt-get update
sudo apt-get install build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools -y
# ubuntu 22.04
sudo apt-get install lld-14 llvm-14 llvm-14-dev clang-14 -y
# ubuntu 20.04
sudo apt-get install lld-12 llvm-12 llvm-12-dev clang-12 -y
sudo apt-get install gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\\..*//')-dev -y 
sudo apt-get install ninja-build -y
```

### Install AFL++

```bash
cd $HOME
git clone <https://github.com/AFLplusplus/AFLplusplus> && cd AFLplusplus
# ubuntu 22.04
export LLVM_CONFIG="llvm-config-14"
# ubuntu 20.04
make distrib
sudo make install
```

## Persistent Mode

하나의 프로세스에 여러 번의 fuzzing을 시도하는 방법.

할 수만 있다면 가장 빠르다.

**예시 코드**

우리는 `target_function` 을 채널에서 user_input을 받는 함수로 할 것이다.

```c
#include "what_you_need_for_your_target.h"

__AFL_FUZZ_INIT();

main() {

  // anything else here, e.g. command line arguments, initialization, etc.

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

    if (len < 8) continue;  // check for a required/useful minimum input length

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    target_function(buf, len);
    /* Reset state. e.g. libtarget_free(tmp) */

  }

  return 0;

}
```

### FreeRDP에 Persistent mode적용하기

FreeRDP는 Client와 Server가 통신하는 과정에서 많은 시간을 잡아먹는다.

그런데 우리는 Channel에서 데이터를 파싱하고 처리해서 보내는 과정에서의 취약점을 찾아내는 것이 목표이기 때문에 Client와 Server를 연결할 필요 없이 채널에서 데이터를 받아서 파싱하고 처리하는 부분만 따로 떼서 처리하면, 속도가 매우 빨라진다. 다만 이를 위해서 몇 가지 코드를 수정해야 한다.

# Fuzz the ECHO channel

간단한 예시를 통해 FreeRDP에 Persistent mode를 적용하는 법을 알아보자.

다음은 echo 채널의 핵심이 되는 `echo_main.c` 파일이다.

이때 echo 채널에 데이터를 보내면, `echo_on_data_received` 함수에서 데이터를 처리하고 callback함수를 이용해서 Virtual Channel에 write해준다.

```c
/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Echo Virtual Channel Extension
 *
 * Copyright 2013 Christian Hofstaedtler
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     <http://www.apache.org/licenses/LICENSE-2.0>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>

#include <winpr/crt.h>
#include <winpr/stream.h>

#include "echo_main.h"
#include <freerdp/client/channels.h>
#include <freerdp/channels/log.h>
#include <freerdp/channels/echo.h>

#define TAG CHANNELS_TAG("echo.client")

typedef struct
{
	GENERIC_DYNVC_PLUGIN baseDynPlugin;
} ECHO_PLUGIN;

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT echo_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	BYTE* pBuffer = Stream_Pointer(data);
	UINT32 cbSize = Stream_GetRemainingLength(data);

	/* echo back what we have received. ECHO does not have any message IDs. */
	return callback->channel->Write(callback->channel, cbSize, pBuffer, NULL);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT echo_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;

	free(callback);

	return CHANNEL_RC_OK;
}

static const IWTSVirtualChannelCallback echo_callbacks = { echo_on_data_received, NULL, /* Open */
	                                                       echo_on_close };

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT echo_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints)
{
	return freerdp_generic_DVCPluginEntry(pEntryPoints, TAG, ECHO_DVC_CHANNEL_NAME,
	                                      sizeof(ECHO_PLUGIN), sizeof(GENERIC_CHANNEL_CALLBACK),
	                                      &echo_callbacks, NULL, NULL);
}
```

`echo_on_data_received` 함수는 `IWTSVirtualChannelCallback* pChannelCallback`, `wStream* data` 를 매개변수로 가지는 것을 확인할 수 있다. 그런데 `echo_on_data_received` 만 따로 떼어서 실행하므로 매개변수로 들어가는 ChannelCallback과 data를 직접 만들어 줘야 한다.

data는 user의 input이 들어가고 자료형이 `wStream*`으로 동일해서 코드를 재활용해도 상관없지만, ChannelCallback은 channel마다 굉장히 상이해서 직접 구조체를 보며 한땀 한땀 만들어 줘야 한다.

또한 ChannelCallback은 `GENERIC_CHANNEL_CALLBACK*`으로 캐스팅 되어서 `IWTSVirtualChannelCallback` 말고 `GENERIC_CHANNEL_CALLBACK` 을 보고 만들어야 한다.

```c
static UINT echo_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	BYTE* pBuffer = Stream_Pointer(data);
	UINT32 cbSize = Stream_GetRemainingLength(data);

	/* echo back what we have received. ECHO does not have any message IDs. */
	return callback->channel->Write(callback->channel, cbSize, pBuffer, NULL);
}
```

## ChannelCallback 만들기

`GENERIC_CHANNEL_CALLBACK` 구조체를 확인해보자. echo 채널에서는 channel 멤버 변수만 사용하는데 나중에 사용하지 않게 고칠거라 NULL을 넣어줘도 된다. (채널에 따라서 iface, plugin 등등은 만들어 줘야 한다.)

```c
typedef struct
{
	IWTSVirtualChannelCallback iface;
	IWTSPlugin* plugin;
	IWTSVirtualChannelManager* channel_mgr;
	IWTSVirtualChannel* channel;
} GENERIC_CHANNEL_CALLBACK;

struct s_IWTSVirtualChannelCallback
{
	/* Notifies the user about data that is being received. */
	UINT (*OnDataReceived)(IWTSVirtualChannelCallback* pChannelCallback, wStream* data);
	/* Notifies the user that the channel has been opened. */
	UINT (*OnOpen)(IWTSVirtualChannelCallback* pChannelCallback);
	/* Notifies the user that the channel has been closed. */
	UINT (*OnClose)(IWTSVirtualChannelCallback* pChannelCallback);
};
```

코드를 보거나 동적 디버깅을 해보면 iface에 다음과 같은 값이 들어가는 것을 확인할 수 있다.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ea6fece4-e317-43b0-a678-60d6a0e8088f/Untitled.png)

이를 코드로 옮기면 다음과 같다. (iface도 굳이 안 넣어도 상관없다.)

```c
IWTSVirtualChannel channel = (IWTSVirtualChannel*)calloc(1, sizeof(IWTSVirtualChannel));
channel

GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)calloc(1, sizeof(GENERIC_CHANNEL_CALLBACK));
callback->iface.OnDataReceived = echo_on_data_received;
callback->iface.OnOpen = NULL;
callback->iface.OnClose = echo_on_close;
callback->plugin = NULL; /* never used */
callback->channel_mgr = NULL; /* never used */
callback->channel = NULL; /* never used */
```

## data 만들기

data는 `wStream*` 형이다. `wStream` 구조체를 확인해보자.

```c
typedef struct
	{
		BYTE* buffer;
		BYTE* pointer;
		size_t length;
		size_t capacity;

		DWORD count;
		wStreamPool* pool;
		BOOL isAllocatedStream;
		BOOL isOwner;
	} wStream;
```

wStream 구조체는 일일히 설정해주기 보다는 FreeRDP에서 사용하는 Stream 관련 API들을 사용하는게 편하다. 아마 모든 채널에 다음과 같이 설정하면 잘 동작할 것이다.

```c
0x7fffe52dac60,wStream* s = Stream_New(NULL, len);
if (!Stream_EnsureRemainingCapacity(s, len))
{
		/* ERROR */
	  continue;
}

Stream_Write(s, buf, len);

if (Stream_Capacity(s) != Stream_GetPosition(s))
{
	  /* ERROR */
	  continue;
}

Stream_SealLength(s);
Stream_SetPosition(s, 0);
```

## Harness 만들기

위에 예시 코드를 그대로 가져다 쓰고 include 할 거 하고 매개변수를 설정하는 것과 target 함수만 바꿔주면 끝이다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>

#include <freerdp/client/channels.h>
#include <freerdp/channels/log.h>

#include "echo_main.h"

/* this lets the source compile without afl-clang-fast/lto */
#ifndef __AFL_FUZZ_TESTCASE_LEN

ssize_t       fuzz_len;
unsigned char fuzz_buf[1024000];

  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) \\
    ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()

#endif

#pragma clang optimize off
#pragma GCC            optimize("O0")

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    ssize_t        len;                        /* how much input did we read? */
    unsigned char *buf;                        /* test case buffer pointer    */

    /* The number passed to __AFL_LOOP() controls the maximum number of
     iterations before the loop exits and the program is allowed to
     terminate normally. This limits the impact of accidental memory leaks
     and similar hiccups. */

    buf = __AFL_FUZZ_TESTCASE_BUF;  // this must be assigned before __AFL_LOOP!

    GENERIC_CHANNEL_CALLBACK* callback = calloc(1, sizeof(GENERIC_CHANNEL_CALLBACK));
    

    while (__AFL_LOOP(UINT_MAX)) {  // increase if you have good stability
        /* input */
        len = __AFL_FUZZ_TESTCASE_LEN;  // do not use the macro directly in a call!
        /* initialize IWTSVirtualChannelCallback* pChannelCallback */
        memset(callback, 0, sizeof(GENERIC_CHANNEL_CALLBACK));
        callback->iface.OnDataReceived = echo_on_data_received;
        callback->iface.OnOpen = NULL;
        callback->iface.OnClose = echo_on_close;
        callback->plugin = NULL; /* never used */
        callback->channel_mgr = NULL; /* never used */
        callback->channel = NULL; /* never used */
        
        /* initialize wStream* s */
        wStream* s = Stream_New(NULL, len);
        if (!Stream_EnsureRemainingCapacity(s, len))
        {
            /* ERROR */
            continue;
        }

        Stream_Write(s, buf, len);

        if (Stream_Capacity(s) != Stream_GetPosition(s))
        {
            /* ERROR */
            continue;
        }

        Stream_SealLength(s);
        Stream_SetPosition(s, 0);
        
        /* target function */
        echo_on_data_received(callback, s);
    }

  return 0;
}
```

## Compile 하기

`echo_on_data_recevied` 함수 등을 harness(이하 main.c)에서 사용하기 위해서는 `echo_main.c`와 `echo_main.h`가 필요하다. 이때 `echo_main.h`에 `echo_on_data_recevied` 등의 함수들이 정의되지 않아서 따로 정의를 해줘야 하고, 반환 형에서 static을 빼주면 된다. (`echo_main.c`와 `echo_main.h` 모두)

그리고 `echo_main.c`에서 VirtualChannel에 write해주는 부분이 있는데 우리는 Server와 Client간의 연결이 없으므로 당연히 오류가 뜬다. 따라서 이 부분은 `/dev/null`에 값을 쓰는 걸로 대체하자.

바꿔준 `echo_main.c` 에서는 STATIC이 빠지고, `/dev/null`에 write하는 부분이 추가된 것을 확인할 수 있다.

```c
/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Echo Virtual Channel Extension
 *
 * Copyright 2013 Christian Hofstaedtler
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     <http://www.apache.org/licenses/LICENSE-2.0>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>

#include <winpr/crt.h>
#include <winpr/stream.h>

#include "echo_main.h"
#include <freerdp/client/channels.h>
#include <freerdp/channels/log.h>
#include <freerdp/channels/echo.h>

#include <unistd.h>
#include <fcntl.h>

#define TAG CHANNELS_TAG("echo.client")

typedef struct
{
	GENERIC_DYNVC_PLUGIN baseDynPlugin;
} ECHO_PLUGIN;

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT echo_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	BYTE* pBuffer = Stream_Pointer(data);
	UINT32 cbSize = Stream_GetRemainingLength(data);

	/* echo back what we have received. ECHO does not have any message IDs. */
	/* return callback->channel->Write(callback->channel, cbSize, pBuffer, NULL); */
	int fd = open("/dev/null", W_OK);
	write(fd, pBuffer, cbSize);
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT echo_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;

	free(callback);

	return CHANNEL_RC_OK;
}

static const IWTSVirtualChannelCallback echo_callbacks = { echo_on_data_received, NULL, /* Open */
	                                                       echo_on_close };

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT echo_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints)
{
	return freerdp_generic_DVCPluginEntry(pEntryPoints, TAG, ECHO_DVC_CHANNEL_NAME, sizeof(ECHO_PLUGIN), sizeof(GENERIC_CHANNEL_CALLBACK), &echo_callbacks, NULL, NULL);
}
```

바꾼 echo_main.h

```c
/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Echo Virtual Channel Extension
 *
 * Copyright 2013 Christian Hofstaedtler
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     <http://www.apache.org/licenses/LICENSE-2.0>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CHANNEL_ECHO_CLIENT_MAIN_H
#define FREERDP_CHANNEL_ECHO_CLIENT_MAIN_H

#include <freerdp/config.h>

#include <freerdp/dvc.h>
#include <freerdp/types.h>
#include <freerdp/addin.h>
#include <freerdp/channels/log.h>

#define DVC_TAG CHANNELS_TAG("echo.client")
#ifdef WITH_DEBUG_DVC
#define DEBUG_DVC(...) WLog_DBG(DVC_TAG, __VA_ARGS__)
#else
#define DEBUG_DVC(...) \\
	do                 \\
	{                  \\
	} while (0)
#endif

UINT echo_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data);
UINT echo_on_close(IWTSVirtualChannelCallback* pChannelCallback);

#endif /* FREERDP_CHANNEL_ECHO_CLIENT_MAIN_H */
```

이제 Makefile을 만들어보자.

컴파일러는 가장 빠른 afl-clang-lto를 사용하고

FreeRDP API를 사용하기 때문에 LDFLAGS에 관련 라이브러리를 넣어줬다.

CFLAGS는 -Wall이나, Sanitizer 옵션 같은 거 주면 된다.

```makefile
# for fuzzing
CC = ~/AFLplusplus/afl-clang-lto
LDFLAGS = -lfreerdp3 -lwinpr3 -lfreerdp-client3
CFLAGS = 
# for testing
# CC = gcc
# CFLAGS = -fsanitize=address -fno-sanitize-recover=all -g 
# TARGET = fuzzme_test

OBJS = echo_main.o main.o 
TARGET = fuzzme

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(CFLAGS)

echo_main.o: echo_main.h echo_main.c
	$(CC) -c -o echo_main.o echo_main.c $(LDFLAGS) $(CFLAGS)

main.o: echo_main.h main.c
	$(CC) -c -o main.o main.c $(LDFLAGS) $(CFLAGS)

clean:ls
	rm -f *.o 
	rm -f $(TARGET)
```

이제 마지막으로 libfreerdp에서 사용하는 header 파일들을 /usr/include 로 복사해주면 끝이다.