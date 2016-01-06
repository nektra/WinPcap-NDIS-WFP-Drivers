/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   Transport Inspect Proxy Callout Driver Sample.

   This sample callout driver intercepts all transport layer traffic (e.g. 
   TCP, UDP, and non-error ICMP) sent to or receive from a (configurable) 
   remote peer and queue them to a worker thread for out-of-band processing. 
   The sample performs inspection of inbound and outbound connections as 
   well as all packets belong to those connections.  In addition the sample 
   demonstrates special considerations required to be compatible with Windows 
   Vista and Windows Server 2008’s IpSec implementation.

   Inspection parameters are configurable via the following registry 
   values --

   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Inspect\Parameters
      
    o  BlockTraffic (REG_DWORD) : 0 (permit, default); 1 (block)
    o  RemoteAddressToInspect (REG_SZ) : literal IPv4/IPv6 string 
                                                (e.g. “10.0.0.1”)
   The sample is IP version agnostic. It performs inspection for 
   both IPv4 and IPv6 traffic.

Environment:

    Kernel mode

--*/

#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "inspect.h"

#define INITGUID
#include <guiddef.h>


// 
// Configurable parameters (addresses and ports are in host order)
//

BOOLEAN configPermitTraffic = TRUE;

UINT8*   configInspectRemoteAddrV4 = NULL;
UINT8*   configInspectRemoteAddrV6 = NULL;

IN_ADDR  remoteAddrStorageV4;
IN6_ADDR remoteAddrStorageV6;

// 
// Callout and sublayer GUIDs
//

// bb6e405b-19f4-4ff3-b501-1a3dc01aae01
DEFINE_GUID(
			TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4,
			0xbb6e405b,
			0x19f4,
			0x4ff3,
			0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x01
);
// cabf7559-7c60-46c8-9d3b-2155ad5cf83f
DEFINE_GUID(
			TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V6,
			0xcabf7559,
			0x7c60,
			0x46c8,
			0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x3f
);
// 07248379-248b-4e49-bf07-24d99d52f8d0
DEFINE_GUID(
			TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V4,
			0x07248379,
			0x248b,
			0x4e49,
			0xbf, 0x07, 0x24, 0xd9, 0x9d, 0x52, 0xf8, 0xd0
);
// 6d126434-ed67-4285-925c-cb29282e0e06
DEFINE_GUID(
			TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V6,
			0x6d126434,
			0xed67,
			0x4285,
			0x92, 0x5c, 0xcb, 0x29, 0x28, 0x2e, 0x0e, 0x06
);
// 76b743d4-1249-4614-a632-6f9c4d08d25a
DEFINE_GUID(
			TL_INSPECT_ALE_CONNECT_CALLOUT_V4,
			0x76b743d4,
			0x1249,
			0x4614,
			0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5a
);

// ac80683a-5b84-43c3-8ae9-eddb5c0d23c2
DEFINE_GUID(
			TL_INSPECT_ALE_CONNECT_CALLOUT_V6,
			0xac80683a,
			0x5b84,
			0x43c3,
			0x8a, 0xe9, 0xed, 0xdb, 0x5c, 0x0d, 0x23, 0xc2
);

// 7ec7f7f5-0c55-4121-adc5-5d07d2ac0cef
DEFINE_GUID(
			TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V4,
			0x7ec7f7f5,
			0x0c55,
			0x4121,
			0xad, 0xc5, 0x5d, 0x07, 0xd2, 0xac, 0x0c, 0xef
);

// b74ac2ed-4e71-4564-9975-787d5168a151
DEFINE_GUID(
			TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V6,
			0xb74ac2ed,
			0x4e71,
			0x4564,
			0x99, 0x75, 0x78, 0x7d, 0x51, 0x68, 0xa1, 0x51
);

// 2e207682-d95f-4525-b966-969f26587f03
DEFINE_GUID(
			TL_INSPECT_SUBLAYER,
			0x2e207682,
			0xd95f,
			0x4525,
			0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

// 
// Callout driver global variables
//

DEVICE_OBJECT* gWdmDevice;
WDFKEY gParametersKey;
HANDLE gEngineHandle;
UINT32 gAleConnectCalloutIdV4, gOutboundTlCalloutIdV4;
UINT32 gAleRecvAcceptCalloutIdV4, gInboundTlCalloutIdV4;
UINT32 gAleConnectCalloutIdV6, gOutboundTlCalloutIdV6;
UINT32 gAleRecvAcceptCalloutIdV6, gInboundTlCalloutIdV6;

HANDLE gInjectionHandle;

LIST_ENTRY gConnList;
KSPIN_LOCK gConnListLock;
LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;
UINT64 packetCount;
KEVENT gWorkerEvent;

BOOLEAN gDriverUnloading = FALSE;
void* gThreadObj;

// 
// Callout driver implementation
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TLInspectEvtDriverUnload;

NTSTATUS TLInspectLoadConfig(_In_ const WDFKEY key)// Chequea que la IP del registro de windows este bien puesta
{
   NTSTATUS status;
   DECLARE_CONST_UNICODE_STRING(valueName, L"RemoteAddressToInspect");
   DECLARE_UNICODE_STRING_SIZE(value, INET6_ADDRSTRLEN);
   
   status = WdfRegistryQueryUnicodeString(key, &valueName, NULL, &value); //The WdfRegistryQueryUnicodeString method retrieves the string data 
																		  // that is currently assigned to a specified registry string value and copies the string to a specified UNICODE_STRING structure
   if (NT_SUCCESS(status))
   {
      PWSTR terminator;													  //16bit char pointer
      // Defensively null-terminate the string
      value.Length = min(value.Length, value.MaximumLength - sizeof(WCHAR));
      value.Buffer[value.Length/sizeof(WCHAR)] = UNICODE_NULL;           

      status = RtlIpv4StringToAddressW(value.Buffer, TRUE, &terminator, &remoteAddrStorageV4); //RtlIpv4StringToAddress function converts a string representation of an IPv4 address to a binary IPv4 address.

      if (NT_SUCCESS(status))
      {
         remoteAddrStorageV4.S_un.S_addr = RtlUlongByteSwap(remoteAddrStorageV4.S_un.S_addr);// Da vuelta los cuatro chars que forman la direccion
         configInspectRemoteAddrV4 = &remoteAddrStorageV4.S_un.S_un_b.s_b1;
      }
      else
      {
         status = RtlIpv6StringToAddressW( value.Buffer, &terminator, &remoteAddrStorageV6);

         if (NT_SUCCESS(status))
         {
            configInspectRemoteAddrV6 = (UINT8*)(&remoteAddrStorageV6.u.Byte[0]);
         }
      }
   }

   return status;
}

NTSTATUS TLInspectAddFilter(  _In_ const wchar_t* filterName,
							  _In_ const wchar_t* filterDesc,
							  _In_reads_opt_(16) const UINT8* remoteAddr,
							  _In_ UINT64 context,
							  _In_ const GUID* layerKey,
							  _In_ const GUID* calloutKey
						   )
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPM_FILTER filter = {0};
   FWPM_FILTER_CONDITION filterConditions[3] = {0}; //The FWPM_FILTER_CONDITION0 structure expresses a filter condition that must be true for the action to be taken.
   UINT conditionIndex;

   filter.layerKey = *layerKey;
   filter.displayData.name = (wchar_t*)filterName;
   filter.displayData.description = (wchar_t*)filterDesc;

   filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // El tipo de calllout, en este cvaso indica que se modifica el trafico
   filter.action.calloutKey = *calloutKey;
   filter.filterCondition = filterConditions;
   filter.subLayerKey = TL_INSPECT_SUBLAYER;
   filter.weight.type = FWP_EMPTY; // auto-weight.
   filter.rawContext = context;

   conditionIndex = 0;

   if (remoteAddr != NULL)
   {
		 filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;   //La IP
		 filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL; //QUE COINCIDA

	     if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||     // SI ES UNA IPv4
	         IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
	         IsEqualGUID(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4) ||
	         IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4))
	     {
	     		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32; //CARGA LA IP 32b
	     		filterConditions[conditionIndex].conditionValue.uint32 = *(UINT32*)remoteAddr;
	     }
         else
	     {
	        filterConditions[conditionIndex].conditionValue.type = FWP_BYTE_ARRAY16_TYPE; //SI ES 64 BITS carga la IP 6
	        filterConditions[conditionIndex].conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)remoteAddr;
	     }

		 conditionIndex++;
   }

   //filter.numFilterConditions = conditionIndex;//especifica la cantidad de condiciones
   filter.numFilterConditions = 0;//especifica la cantidad de condiciones

   status = FwpmFilterAdd(gEngineHandle, &filter, NULL, NULL); //agrega el filtro

   return status;
}

NTSTATUS TLInspectRegisterALEClassifyCallouts( _In_ const GUID* layerKey, _In_ const GUID* calloutKey, _Inout_ void* deviceObject, _Out_ UINT32* calloutId)
/* ++

   This function registers callouts and filters at the following layers 
   to intercept inbound or outbound connect attempts.
   
      FWPM_LAYER_ALE_AUTH_CONNECT_V4
      FWPM_LAYER_ALE_AUTH_CONNECT_V6
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

	  O sea, intentos de iniciar una coneccion a nivel de aplicacion
-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPS_CALLOUT sCallout = {0}; //This structure defines the data that is required for a callout driver to register a callout with the filter engine.
   FWPM_CALLOUT mCallout = {0};//This  structure stores the state associated with a callout.

   FWPM_DISPLAY_DATA displayData = {0};

   BOOLEAN calloutRegistered = FALSE;

   sCallout.calloutKey = *calloutKey;

   if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||  IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6))
   {
      sCallout.classifyFn = TLInspectALEConnectClassify;//The filter engine calls a callout driver's classifyFn function whenever there is data to be processed by the callout driver
      sCallout.notifyFn = TLInspectALEConnectNotify;
   }
   else
   {
      sCallout.classifyFn = TLInspectALERecvAcceptClassify;
      sCallout.notifyFn = TLInspectALERecvAcceptNotify;
   }

   status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);//registramos el callout
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   calloutRegistered = TRUE;

   displayData.name = L"Transport Inspect ALE Classify Callout";
   displayData.description = L"Intercepts inbound or outbound connect attempts";

   mCallout.calloutKey = *calloutKey;
   mCallout.displayData = displayData;
   mCallout.applicableLayer = *layerKey;

   status = FwpmCalloutAdd( gEngineHandle, &mCallout, NULL, NULL);

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLInspectAddFilter(
							   L"Transport Inspect ALE Classify",
							   L"Intercepts inbound or outbound connect attempts",
							   (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) || IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)) ? configInspectRemoteAddrV4 : configInspectRemoteAddrV6,
							   0,
							   layerKey,
							   calloutKey
							  );
   //Agregamos el filtro
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

Exit:

   if (!NT_SUCCESS(status))
   {
      if (calloutRegistered)
      {
         FwpsCalloutUnregisterById(*calloutId);
         *calloutId = 0;
      }
   }

   return status;
}

NTSTATUS TLInspectRegisterTransportCallouts( _In_ const GUID* layerKey, _In_ const GUID* calloutKey, _Inout_ void* deviceObject, _Out_ UINT32* calloutId)
/* ++

   This function registers callouts and filters that intercept transport 
   traffic at the following layers --

      FWPM_LAYER_OUTBOUND_TRANSPORT_V4
      FWPM_LAYER_OUTBOUND_TRANSPORT_V6
      FWPM_LAYER_INBOUND_TRANSPORT_V4
      FWPM_LAYER_INBOUND_TRANSPORT_V6
	  O sea, intercepta trafico TCP
-- */
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPS_CALLOUT sCallout = {0};
   FWPM_CALLOUT mCallout = {0};

   FWPM_DISPLAY_DATA displayData = {0};

   BOOLEAN calloutRegistered = FALSE;

   sCallout.calloutKey = *calloutKey;
   sCallout.classifyFn = TLInspectTransportClassify;
   sCallout.notifyFn = TLInspectTransportNotify;

   status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   calloutRegistered = TRUE;

   displayData.name = L"Transport Inspect Callout";
   displayData.description = L"Inspect inbound/outbound transport traffic";

   mCallout.calloutKey = *calloutKey;
   mCallout.displayData = displayData;
   mCallout.applicableLayer = *layerKey;

   status = FwpmCalloutAdd(gEngineHandle, &mCallout, NULL, NULL);

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = TLInspectAddFilter(
							   L"Transport Inspect Filter (Outbound)",
							   L"Inspect inbound/outbound transport traffic",
							   (IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4) ||  IsEqualGUID(layerKey, &FWPM_LAYER_INBOUND_TRANSPORT_V4))? configInspectRemoteAddrV4 : configInspectRemoteAddrV6,
							   0,
							   layerKey,
							   calloutKey
							  );

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

Exit:

   if (!NT_SUCCESS(status))
   {
      if (calloutRegistered)
      {
         FwpsCalloutUnregisterById(*calloutId);
         *calloutId = 0;
      }
   }

   return status;
}

NTSTATUS TLInspectRegisterCallouts( _Inout_ void* deviceObject)
/* ++

   This function registers dynamic callouts and filters that intercept 
   transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and 
   INBOUND/OUTBOUND transport layers.

   Callouts and filters will be removed during DriverUnload.

-- */
{
   NTSTATUS status = STATUS_SUCCESS;
   FWPM_SUBLAYER TLInspectSubLayer;

   BOOLEAN engineOpened = FALSE;
   BOOLEAN inTransaction = FALSE;

   FWPM_SESSION session = {0};

   session.flags = FWPM_SESSION_FLAG_DYNAMIC;	//Abrimos una "sesion". The WFP API is session-oriented, and most function calls are made within the context of a session

   status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngineHandle);

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   engineOpened = TRUE;

   status = FwpmTransactionBegin(gEngineHandle, 0); //Arrancamos una transaccion

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }
   inTransaction = TRUE;

   RtlZeroMemory(&TLInspectSubLayer, sizeof(FWPM_SUBLAYER));  //pongo en cero el descriptor del sublayer

   TLInspectSubLayer.subLayerKey = TL_INSPECT_SUBLAYER;   //una GUID
   TLInspectSubLayer.displayData.name = L"Transport Inspect Sub-Layer"; //descripcion para seres humanos
   TLInspectSubLayer.displayData.description = L"Sub-Layer for use by Transport Inspect callouts";
   TLInspectSubLayer.flags = 0;
   TLInspectSubLayer.weight = 0; // must be less than the weight of 
                                 // FWPM_SUBLAYER_UNIVERSAL to be
                                 // compatible with Vista's IpSec
                                 // implementation.

   status = FwpmSubLayerAdd(gEngineHandle, &TLInspectSubLayer, NULL);

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   if (configInspectRemoteAddrV4 != NULL)// Si se leyo una ip buena del registro
   {
      status = TLInspectRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &TL_INSPECT_ALE_CONNECT_CALLOUT_V4, deviceObject, &gAleConnectCalloutIdV4);
      if (!NT_SUCCESS(status))//FWPM_LAYER_ALE_AUTH_CONNECT_V4: This filtering layer allows for authorizing connect requests for outgoing TCP connections
      {						  
         goto Exit;
      }

      status = TLInspectRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V4,  deviceObject, &gAleRecvAcceptCalloutIdV4);

      if (!NT_SUCCESS(status))//This filtering layer allows for authorizing accept requests for incoming TCP connections
      {
         goto Exit;
      }
	  
      status = TLInspectRegisterTransportCallouts(&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,  &TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4, deviceObject, &gOutboundTlCalloutIdV4);
									
      if (!NT_SUCCESS(status))//This filtering layer is located in the send path just after a sent packet has been passed to the network layer for processing but before any network layer processing takes place
      {
         goto Exit;
      }

      status = TLInspectRegisterTransportCallouts(&FWPM_LAYER_INBOUND_TRANSPORT_V4, &TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V4, deviceObject, &gInboundTlCalloutIdV4);
	  //This filtering layer is located in the receive path just after a received packet's transport header has been parsed by the network stack
												//at the transport layer, but before any transport layer processing takes place.
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }
   }
   //Despues hace todo lo mismo, pero en el caso de IPv6
   if (configInspectRemoteAddrV6 != NULL)
   {
      status = TLInspectRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_CONNECT_V6, &TL_INSPECT_ALE_CONNECT_CALLOUT_V6, deviceObject, &gAleConnectCalloutIdV6);
      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLInspectRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V6, deviceObject, &gAleRecvAcceptCalloutIdV6);

      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLInspectRegisterTransportCallouts(&FWPM_LAYER_OUTBOUND_TRANSPORT_V6, &TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V6, deviceObject, &gOutboundTlCalloutIdV6);

      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

      status = TLInspectRegisterTransportCallouts(&FWPM_LAYER_INBOUND_TRANSPORT_V6, &TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V6, deviceObject, &gInboundTlCalloutIdV6);

      if (!NT_SUCCESS(status))
      {
         goto Exit;
      }

   }

   status = FwpmTransactionCommit(gEngineHandle);
   //Termino la transaccion
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   inTransaction = FALSE;

Exit:

   if (!NT_SUCCESS(status))
   {
      if (inTransaction)
      {
         FwpmTransactionAbort(gEngineHandle);
         _Analysis_assume_lock_not_held_(gEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
      }
      if (engineOpened)
      {
         FwpmEngineClose(gEngineHandle);
         gEngineHandle = NULL;
      }
   }

   return status;
}

void
TLInspectUnregisterCallouts(void)
{
   FwpmEngineClose(gEngineHandle);
   gEngineHandle = NULL;

   FwpsCalloutUnregisterById(gOutboundTlCalloutIdV6);
   FwpsCalloutUnregisterById(gOutboundTlCalloutIdV4);
   FwpsCalloutUnregisterById(gInboundTlCalloutIdV6);
   FwpsCalloutUnregisterById(gInboundTlCalloutIdV4);

   FwpsCalloutUnregisterById(gAleConnectCalloutIdV6);
   FwpsCalloutUnregisterById(gAleConnectCalloutIdV4);
   FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV6);
   FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV4);
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)

void TLInspectEvtDriverUnload(_In_ WDFDRIVER driverObject)
{

   KLOCK_QUEUE_HANDLE connListLockHandle;
   KLOCK_QUEUE_HANDLE packetQueueLockHandle;

   UNREFERENCED_PARAMETER(driverObject);

   KeAcquireInStackQueuedSpinLock(&gConnListLock, &connListLockHandle);
   KeAcquireInStackQueuedSpinLock(&gPacketQueueLock, &packetQueueLockHandle);

   gDriverUnloading = TRUE;

   KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
   KeReleaseInStackQueuedSpinLock(&connListLockHandle);

   if (IsListEmpty(&gConnList) && IsListEmpty(&gPacketQueue))
   {
      KeSetEvent(&gWorkerEvent, IO_NO_INCREMENT, FALSE);
   }

   NT_ASSERT(gThreadObj != NULL);

   KeWaitForSingleObject(gThreadObj, Executive, KernelMode, FALSE, NULL);

   ObDereferenceObject(gThreadObj);

   TLInspectUnregisterCallouts();

   FwpsInjectionHandleDestroy(gInjectionHandle);
}

NTSTATUS TLInspectInitDriverObjects(_Inout_ DRIVER_OBJECT* driverObject, _In_ const UNICODE_STRING* registryPath, _Out_ WDFDRIVER* pDriver, _Out_ WDFDEVICE* pDevice)
{
   NTSTATUS status;
   WDF_DRIVER_CONFIG config;
   PWDFDEVICE_INIT pInit = NULL;
   WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

   config.DriverInitFlags |= WdfDriverInitNonPnpDriver;												//Agrega la flag de que es no-PnP
   config.EvtDriverUnload = TLInspectEvtDriverUnload;

   status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, pDriver);//The WdfDriverCreate method creates a framework driver object for the calling driver.
																									//pDriver= A pointer to a location that receives a handle to the new framework driver object.
   if (!NT_SUCCESS(status))																			//This parameter is optional and can be WDF_NO_HANDLE
   {
      goto Exit;
   }

   pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_KERNEL_ONLY);						//The WdfControlDeviceInitAllocate method allocates a WDFDEVICE_INIT structure 
																									//that a driver uses when creating a new control device object.
   if (!pInit)
   {
      status = STATUS_INSUFFICIENT_RESOURCES;
      goto Exit;
   }

   WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
   WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
   WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

   status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);								//The WdfDeviceCreate method creates a framework device object.

   if (!NT_SUCCESS(status))
   {
      WdfDeviceInitFree(pInit);
      goto Exit;
   }

   WdfControlFinishInitializing(*pDevice);															//WdfControlFinishInitializing method informs the framework that a driver has 
																									//finished initializing a specified control device object.
Exit:
   return status;
}

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
NTSTATUS DriverEntry( _In_ DRIVER_OBJECT* driverObject, _In_ UNICODE_STRING* registryPath)
{
   NTSTATUS status;
   WDFDRIVER driver;
   WDFDEVICE device;
   HANDLE threadHandle;
   packetCount = 0;
   // Request NX Non-Paged Pool when available
   ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
   //DbgPrint("Breakpoint de entrada");
   //DbgBreakPoint();

   status = TLInspectInitDriverObjects(driverObject, registryPath, &driver, &device); //FUNCION QUE CREA EL DRIVER OBJECT Y EL DEVICE OBJECT

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = WdfDriverOpenParametersRegistryKey(driver, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &gParametersKey);  // WdfDriverOpenParametersRegistryKey method opens the driver's Parameters 
																											  // registry key and retrieves a handle to a framework registry-key object that represents the key
   if (!NT_SUCCESS(status))																					  // gParametersKey = A pointer to a location that receives a handle to a framework registry-key object
   {
      goto Exit;
   }

   status = TLInspectLoadConfig(gParametersKey);		//Carga la variable configInspectRemoteAddrV4/V6 con la IP que se agrego en el registro

   if (!NT_SUCCESS(status))
   {
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
      goto Exit;
   }

   if ((configInspectRemoteAddrV4 == NULL) && (configInspectRemoteAddrV6 == NULL))
   {
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
      goto Exit;
   }

   status = FwpsInjectionHandleCreate(AF_UNSPEC, FWPS_INJECTION_TYPE_TRANSPORT, &gInjectionHandle);  //The FwpsInjectionHandleCreate0 function creates a handle that can be used
																									 // by packet injection functions to inject packet or stream data into the TCP/IP network stack
   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   InitializeListHead(&gConnList);													//inicializo listas enlazadas 
   KeInitializeSpinLock(&gConnListLock);											//inicializo los spinlocks

   InitializeListHead(&gPacketQueue);
   KeInitializeSpinLock(&gPacketQueueLock);  


   KeInitializeEvent(&gWorkerEvent, NotificationEvent, FALSE);                      //The KeInitializeEvent routine initializes an event object as a synchronization (single waiter)
																					//or notification type event and sets it to a signaled or not-signaled state.

   gWdmDevice = WdfDeviceWdmGetDeviceObject(device);								//WdfDeviceWdmGetDeviceObject method returns the Windows Driver Model(WDM) 
																					//device object that is associated with a specified framework device object.

   status = TLInspectRegisterCallouts(gWdmDevice);									//registra los callouts

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

  // DbgPrint("por crear el system worker thread");
   //DbgBreakPoint();


   status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, TLInspectWorker, NULL); //PsCreateSystemThread routine creates a system thread 
																											 //that executes in kernel mode and returns a handle for the thread.
																										     //leer en inspect.c que hace TLInspectWorker

   if (!NT_SUCCESS(status))
   {
      goto Exit;
   }

   status = ObReferenceObjectByHandle(threadHandle, 0, NULL, KernelMode, &gThreadObj, NULL);

   NT_ASSERT(NT_SUCCESS(status));

   ZwClose(threadHandle);

Exit:
   
   if (!NT_SUCCESS(status))
   {
      if (gEngineHandle != NULL)
      {
         TLInspectUnregisterCallouts();
      }
      if (gInjectionHandle != NULL)
      {
         FwpsInjectionHandleDestroy(gInjectionHandle);
      }
   }

   return status;
};

