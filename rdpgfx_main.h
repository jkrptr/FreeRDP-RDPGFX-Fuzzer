/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Graphics Pipeline Extension
 *
 * Copyright 2013-2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CHANNEL_RDPGFX_CLIENT_MAIN_H
#define FREERDP_CHANNEL_RDPGFX_CLIENT_MAIN_H

#include <freerdp/dvc.h>
#include <freerdp/types.h>
#include <freerdp/addin.h>

#include <winpr/wlog.h>
#include <winpr/collections.h>

#include <freerdp/client/channels.h>
#include <freerdp/client/rdpgfx.h>
#include <freerdp/channels/log.h>
#include <freerdp/codec/zgfx.h>
#include <freerdp/cache/persistent.h>
#include <freerdp/freerdp.h>

typedef struct
{
	GENERIC_DYNVC_PLUGIN base;

	ZGFX_CONTEXT* zgfx;
	UINT32 UnacknowledgedFrames;
	UINT32 TotalDecodedFrames;
	UINT64 StartDecodingTime;
	BOOL suspendFrameAcks;
	BOOL sendFrameAcks;

	wHashTable* SurfaceTable;

	UINT16 MaxCacheSlots;
	void* CacheSlots[25600];
	rdpPersistentCache* persistent;

	rdpContext* rdpcontext;

	wLog* log;
	RDPGFX_CAPSET ConnectionCaps;
	RdpgfxClientContext* context;
} RDPGFX_PLUGIN;

UINT rdpgfx_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data);
UINT rdpgfx_on_open(IWTSVirtualChannelCallback* pChannelCallback);
UINT rdpgfx_on_close(IWTSVirtualChannelCallback* pChannelCallback);
UINT rdpgfx_get_surface_ids(RdpgfxClientContext* context, UINT16** ppSurfaceIds, UINT16* count_out);
UINT rdpgfx_set_surface_data(RdpgfxClientContext* context, UINT16 surfaceId, void* pData);
void* rdpgfx_get_surface_data(RdpgfxClientContext* context, UINT16 surfaceId);
void* rdpgfx_get_cache_slot_data(RdpgfxClientContext* context, UINT16 cacheSlot);
UINT rdpgfx_set_cache_slot_data(RdpgfxClientContext* context, UINT16 cacheSlot, void* pData);
UINT rdpgfx_send_caps_advertise_pdu(RdpgfxClientContext* context, const RDPGFX_CAPS_ADVERTISE_PDU* pdu);
UINT rdpgfx_send_frame_acknowledge_pdu(RdpgfxClientContext* context, const RDPGFX_FRAME_ACKNOWLEDGE_PDU* pdu);
UINT rdpgfx_send_cache_import_offer_pdu(RdpgfxClientContext* context, const RDPGFX_CACHE_IMPORT_OFFER_PDU* pdu);
UINT rdpgfx_send_qoe_frame_acknowledge_pdu(RdpgfxClientContext* context, const RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU* pdu);
UINT rdpgfx_recv_pdu(GENERIC_CHANNEL_CALLBACK* callback, wStream* s);
int terminate_plugin_cb(GENERIC_DYNVC_PLUGIN* base);

#endif /* FREERDP_CHANNEL_RDPGFX_CLIENT_MAIN_H */
