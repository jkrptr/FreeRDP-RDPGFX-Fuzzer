#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>

#include <freerdp/client/channels.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/channels/log.h>

#include "rdpgfx_main.h"


#pragma clang optimize off
#pragma GCC            optimize("O0")

#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif

#define TAG CHANNELS_TAG("rdpgfx.client")

__AFL_FUZZ_INIT();

int main(){
    __AFL_INIT();

    ssize_t input_len;
    unsigned char* input_buf = __AFL_FUZZ_TESTCASE_BUF;

    GENERIC_CHANNEL_CALLBACK* callback = calloc(1, sizeof(GENERIC_CHANNEL_CALLBACK));
    RdpgfxClientContext* context = (RdpgfxClientContext*)calloc(1, sizeof(RdpgfxClientContext));
    GENERIC_LISTENER_CALLBACK* listener_callback = (GENERIC_LISTENER_CALLBACK*)calloc(1, sizeof(GENERIC_LISTENER_CALLBACK));
    GENERIC_CHANNEL_CALLBACK* channel_callback = (GENERIC_CHANNEL_CALLBACK*)calloc(1, sizeof(GENERIC_CHANNEL_CALLBACK));
    rdpContext* rdpcontext = (rdpContext*)calloc(1, sizeof(rdpContext));
    rdpSettings* rdpsettings = (rdpSettings*)calloc(1, sizeof(rdpSettings));
    RDPGFX_PLUGIN* gfx = (RDPGFX_PLUGIN*)calloc(1, sizeof(RDPGFX_PLUGIN));
    char* dynvc_name = calloc(1, sizeof("Microsoft::Windows::RDS::Graphics"));

    while (__AFL_LOOP(UINT_MAX)) {
        /* read input */
        input_len = __AFL_FUZZ_TESTCASE_LEN;

        memset(callback, 0, sizeof(GENERIC_CHANNEL_CALLBACK));
        memset(context, 0, sizeof(RdpgfxClientContext));
        memset(listener_callback, 0, sizeof(GENERIC_LISTENER_CALLBACK));
        memset(channel_callback, 0, sizeof(GENERIC_CHANNEL_CALLBACK));
        memset(rdpcontext, 0, sizeof(rdpContext));
        memset(rdpsettings, 0, sizeof(rdpSettings));
        memset(gfx, 0, sizeof(RDPGFX_PLUGIN));
        memset(dynvc_name, 0, sizeof("Microsoft::Windows::RDS::Graphics"));

        /* initialize argument used in rdpgfx_on_data_received */
        /* initialize GENERIC_CHANNEL_CALLBACK* callback */
        /* callback->iface */
        callback->iface.OnDataReceived = rdpgfx_on_data_received;
        callback->iface.OnOpen = rdpgfx_on_open;
        callback->iface.OnClose = rdpgfx_on_close;

        /* callback->plugin */
        
        memcpy(dynvc_name, "Microsoft::Windows::RDS::Graphics", sizeof("Microsoft::Windows::RDS::Graphics"));
        context->handle = (void*)gfx;
        context->GetSurfaceIds = rdpgfx_get_surface_ids;
        context->SetSurfaceData = rdpgfx_set_surface_data;
        context->GetSurfaceData = rdpgfx_get_surface_data;
        context->SetCacheSlotData = rdpgfx_set_cache_slot_data;
        context->GetCacheSlotData = rdpgfx_get_cache_slot_data;
        context->CapsAdvertise = rdpgfx_send_caps_advertise_pdu;
        context->FrameAcknowledge = rdpgfx_send_frame_acknowledge_pdu;
        context->CacheImportOffer = rdpgfx_send_cache_import_offer_pdu;
        context->QoeFrameAcknowledge = rdpgfx_send_qoe_frame_acknowledge_pdu;

        channel_callback->iface.OnDataReceived = rdpgfx_on_data_received;
        channel_callback->iface.OnOpen = rdpgfx_on_open;
        channel_callback->iface.OnClose = rdpgfx_on_close;
        channel_callback->plugin = (IWTSPlugin*)gfx;
        channel_callback->channel_mgr = NULL; /* never used */
        channel_callback->channel = NULL; /* never used */

        listener_callback->iface.OnNewChannelConnection = NULL; /* never used */
        listener_callback->plugin = (IWTSPlugin*)gfx;
        listener_callback->channel_mgr = NULL; /* never used */
        listener_callback->channel = NULL; /* never used */
        listener_callback->channel_callback = channel_callback;

        rdpsettings->BitmapCachePersistEnabled = TRUE;
        rdpsettings->BitmapCachePersistFile = "/tmp/cache";
        rdpsettings->GfxSendQoeAck = TRUE;
        rdpsettings->GfxSmallCache = TRUE;

        rdpcontext->settings = rdpsettings;

        gfx->base.iface.Initialize = NULL; /* never used */
        gfx->base.iface.Connected = NULL; /* never used */
        gfx->base.iface.Disconnected = NULL; /* never used */
        gfx->base.iface.Terminated = NULL; /* never used */
        gfx->base.iface.Attached = NULL; /* never used */
        gfx->base.iface.Detached = NULL; /* never used */
        gfx->base.iface.pInterface = (IWTSPlugin*)context;
        gfx->base.listener_callback = listener_callback; 
        gfx->base.listener = NULL; 
        gfx->base.attached = TRUE; 
        gfx->base.initialized = TRUE; 
        gfx->base.log = WLog_Get(TAG);
        gfx->base.dynvc_name = dynvc_name;
        gfx->base.channelCallbackSize = 0x30;
        gfx->base.channel_callbacks = NULL; /* never used */
        gfx->base.terminatePluginFn = terminate_plugin_cb; 

        gfx->zgfx = zgfx_context_new(FALSE);

        gfx->SurfaceTable = HashTable_New(TRUE);

        gfx->rdpcontext = rdpcontext;

        gfx->MaxCacheSlots = freerdp_settings_get_bool(gfx->rdpcontext->settings, FreeRDP_GfxSmallCache) ? 4096 : 25600;

        gfx->context = context;

        gfx->sendFrameAcks = TRUE;

        gfx->log = NULL;  /* never used */

        callback->plugin = gfx;

        /* callback->channel_mgr */
        callback->channel_mgr = NULL; /* never used */

        /* callback->channel */
        callback->channel = NULL; /* never used */

        /* initialize wStream* s */
        wStream* s = Stream_New(NULL, input_len);
        if (!Stream_EnsureRemainingCapacity(s, input_len))
        {
            /* 
            WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!"); 
            return ERROR_INTERNAL_ERROR; 
            */
            continue;
        }
   
        Stream_Write(s, input_buf, input_len);

        if (Stream_Capacity(s) != Stream_GetPosition(s))
		{
            /*
            WLog_ERR(TAG, "encomsp_plugin_process_received: read error");
            return ERROR_INVALID_DATA;
            */
            continue;
		}
        
        Stream_SealLength(s);
		Stream_SetPosition(s, 0);

        /* target function */
        rdpgfx_on_data_received(callback, s);
    }

    free(dynvc_name);
    free(rdpsettings);
    free(rdpcontext);
    free(listener_callback);
    free(channel_callback);
    free(context);
    free(gfx);
    free(callback);
}