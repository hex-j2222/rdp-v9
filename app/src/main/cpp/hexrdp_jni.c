/*
 * hexrdp_jni.c — JNI bridge between Kotlin (com.gotohex.rdp.rdp.native.AFreeRdpBridge)
 * and the FreeRDP client library (libfreerdp / libfreerdp-client).
 *
 * Compatible: FreeRDP 3.x (tested 3.24.x)
 *
 * Changes vs original:
 *  - Added (void) casts for freerdp_settings_set_* [[nodiscard]] return values (FreeRDP 3.23+)
 *  - Added freerdp_context_new() return value check
 *  - Added PIXEL_FORMAT_BGRA32 pixel-format guard (FreeRDP 3.x uses pixel_format.h)
 *  - Proper NULL check before update callback assignment
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#include <freerdp/freerdp.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/channels/channels.h>
#include <freerdp/codec/color.h>
#include <winpr/synch.h>

#ifndef PIXEL_FORMAT_BGRA32
#define PIXEL_FORMAT_BGRA32 PIXEL_FORMAT_BGRA32_VER
#endif

#define TAG "hexrdp_jni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

typedef struct
{
    rdpContext context;
    JavaVM* jvm;
    jobject bridgeObjGlobalRef;
    jmethodID onFrameMethod;
    jmethodID onStateMethod;
    jmethodID onErrorMethod;
} hexrdpContext;

#define HEXRDP_CTX(inst) ((hexrdpContext*)(inst)->context)

/* ── Callbacks invoked by FreeRDP's core on graphics updates ──────────── */

static BOOL hexrdp_on_frame(rdpContext* context, const RECTANGLE_16* rect)
{
    hexrdpContext* hctx = (hexrdpContext*)context;
    rdpGdi* gdi = context->gdi;
    if (!gdi || !gdi->primary_buffer)
        return TRUE;

    /* BUG-5 FIX: attach thread if FreeRDP called this callback from a thread
     * that was not registered with the JVM (common on ARMv7 / older FreeRDP).
     * Without AttachCurrentThread, GetEnv returns JNI_EDETACHED and every
     * frame is silently dropped → black screen with no visible error. */
    JNIEnv* env;
    bool didAttach = false;
    int getEnvResult = (*hctx->jvm)->GetEnv(hctx->jvm, (void**)&env, JNI_VERSION_1_6);
    if (getEnvResult == JNI_EDETACHED) {
        if ((*hctx->jvm)->AttachCurrentThread(hctx->jvm, &env, NULL) != JNI_OK)
            return TRUE;
        didAttach = true;
    } else if (getEnvResult != JNI_OK) {
        return TRUE;
    }

    int x = rect ? rect->left : 0;
    int y = rect ? rect->top : 0;
    int w = rect ? (rect->right - rect->left) : (int)gdi->width;
    int h = rect ? (rect->bottom - rect->top) : (int)gdi->height;
    if (w <= 0 || h <= 0)
        return TRUE;

    jintArray pixels = (*env)->NewIntArray(env, w * h);
    if (!pixels)
        return TRUE;

    jint* buf = (*env)->GetIntArrayElements(env, pixels, NULL);
    const UINT32 stride = gdi->stride;
    const BYTE* src = gdi->primary_buffer;
    for (int row = 0; row < h; row++)
    {
        const UINT32* srcRow = (const UINT32*)(src + (size_t)(y + row) * stride) + x;
        memcpy(buf + (size_t)row * w, srcRow, (size_t)w * sizeof(jint));
    }
    (*env)->ReleaseIntArrayElements(env, pixels, buf, 0);

    (*env)->CallVoidMethod(env, hctx->bridgeObjGlobalRef, hctx->onFrameMethod,
                            x, y, w, h, pixels,
                            (jboolean)(rect == NULL));
    (*env)->DeleteLocalRef(env, pixels);
    if (didAttach)
        (*hctx->jvm)->DetachCurrentThread(hctx->jvm);
    return TRUE;
}

/* ── FreeRDP lifecycle callbacks ────────────────────────────────────────── */

static BOOL hexrdp_pre_connect(freerdp* instance)
{
    rdpSettings* settings = instance->context->settings;
    (void)freerdp_settings_set_bool(settings, FreeRDP_SoftwareGdi, TRUE);
    return TRUE;
}

static BOOL hexrdp_post_connect(freerdp* instance)
{
    if (!gdi_init(instance, PIXEL_FORMAT_BGRA32))
        return FALSE;

    rdpUpdate* update = instance->context->update;
    if (update)
        update->EndPaint = hexrdp_on_frame;  // BUG-1 FIX: was NULL → black screen on all RDP sessions

    /* BUG-STATE FIX: onNativeState was stored in nativeInit but never called,
     * so bridge.stateChanges never emitted any value from native, leaving
     * RdpRemoteAdapter._sessionState stuck at CONNECTING forever and the UI
     * showing a loading screen even when the connection succeeded.
     * Notify Kotlin that we are now CONNECTED (state = 2). */
    hexrdpContext* hctx = (hexrdpContext*)instance->context;
    JNIEnv* env;
    bool didAttach = false;
    int getEnvResult = (*hctx->jvm)->GetEnv(hctx->jvm, (void**)&env, JNI_VERSION_1_6);
    if (getEnvResult == JNI_EDETACHED) {
        if ((*hctx->jvm)->AttachCurrentThread(hctx->jvm, &env, NULL) != JNI_OK)
            return TRUE;   /* connection is alive; state notification failure is non-fatal */
        didAttach = true;
    } else if (getEnvResult != JNI_OK) {
        return TRUE;
    }
    (*env)->CallVoidMethod(env, hctx->bridgeObjGlobalRef, hctx->onStateMethod, 2 /* CONNECTED */);
    if (didAttach)
        (*hctx->jvm)->DetachCurrentThread(hctx->jvm);

    return TRUE;
}

static void hexrdp_post_disconnect(freerdp* instance)
{
    gdi_free(instance);

    /* BUG-STATE FIX: mirror of the post_connect fix — notify Kotlin that the
     * session is now DISCONNECTED (state = 0) so the UI can react correctly. */
    hexrdpContext* hctx = (hexrdpContext*)instance->context;
    JNIEnv* env;
    bool didAttach = false;
    int getEnvResult = (*hctx->jvm)->GetEnv(hctx->jvm, (void**)&env, JNI_VERSION_1_6);
    if (getEnvResult == JNI_EDETACHED) {
        if ((*hctx->jvm)->AttachCurrentThread(hctx->jvm, &env, NULL) != JNI_OK)
            return;
        didAttach = true;
    } else if (getEnvResult != JNI_OK) {
        return;
    }
    (*env)->CallVoidMethod(env, hctx->bridgeObjGlobalRef, hctx->onStateMethod, 0 /* DISCONNECTED */);
    if (didAttach)
        (*hctx->jvm)->DetachCurrentThread(hctx->jvm);
}

/* ── JNI exported functions ─────────────────────────────────────────────── */

JNIEXPORT jlong JNICALL
Java_com_gotohex_rdp_rdp_native_AFreeRdpBridge_nativeInit(JNIEnv* env, jobject thiz)
{
    freerdp* instance = freerdp_new();
    if (!instance)
        return 0;

    instance->ContextSize = sizeof(hexrdpContext);
    instance->ContextNew  = NULL;
    instance->ContextFree = NULL;

    /* freerdp_context_new returns BOOL in FreeRDP 3.x */
    if (!freerdp_context_new(instance))
    {
        freerdp_free(instance);
        return 0;
    }

    hexrdpContext* hctx = HEXRDP_CTX(instance);
    (*env)->GetJavaVM(env, &hctx->jvm);
    hctx->bridgeObjGlobalRef = (*env)->NewGlobalRef(env, thiz);

    jclass cls = (*env)->GetObjectClass(env, thiz);
    hctx->onFrameMethod = (*env)->GetMethodID(env, cls, "onNativeFrame", "(IIII[IZ)V");
    hctx->onStateMethod = (*env)->GetMethodID(env, cls, "onNativeState", "(I)V");
    hctx->onErrorMethod = (*env)->GetMethodID(env, cls, "onNativeError", "(Ljava/lang/String;)V");

    instance->PreConnect    = hexrdp_pre_connect;
    instance->PostConnect   = hexrdp_post_connect;
    instance->PostDisconnect = hexrdp_post_disconnect;

    return (jlong)(intptr_t)instance;
}

JNIEXPORT jboolean JNICALL
Java_com_gotohex_rdp_rdp_native_AFreeRdpBridge_nativeConnect(
    JNIEnv* env, jobject thiz, jlong handle,
    jstring jHost, jint jPort, jstring jUsername, jstring jPassword, jstring jDomain,
    jint jWidth, jint jHeight, jboolean jUseNla,
    jboolean jGatewayEnabled, jstring jGwHost, jint jGwPort, jstring jGwUser, jstring jGwPass, jstring jGwDomain,
    jint jColorDepth, jint jCompressionQuality, jint jPerformanceMode, jboolean jIgnoreCert)
/* BUG-1 FIX: added jColorDepth, jCompressionQuality, jPerformanceMode (were declared in
 * Kotlin external fun but missing here → UnsatisfiedLinkError / stack corruption on connect).
 * BUG-4 FIX: added jIgnoreCert so TLS cert validation is not permanently disabled. */
{
    freerdp* instance = (freerdp*)(intptr_t)handle;
    if (!instance) return JNI_FALSE;
    rdpSettings* settings = instance->context->settings;

    const char* host   = (*env)->GetStringUTFChars(env, jHost,     NULL);
    const char* user   = (*env)->GetStringUTFChars(env, jUsername, NULL);
    const char* pass   = (*env)->GetStringUTFChars(env, jPassword, NULL);
    const char* domain = (*env)->GetStringUTFChars(env, jDomain,   NULL);
    /* BUG-6 FIX: GetStringUTFChars returns NULL on OOM (low-RAM devices with ~512MB).
     * Passing NULL to freerdp_settings_set_string causes a native crash. */
    if (!host || !user || !pass || !domain) {
        if (host)   (*env)->ReleaseStringUTFChars(env, jHost,     host);
        if (user)   (*env)->ReleaseStringUTFChars(env, jUsername, user);
        if (pass)   (*env)->ReleaseStringUTFChars(env, jPassword, pass);
        if (domain) (*env)->ReleaseStringUTFChars(env, jDomain,   domain);
        return JNI_FALSE;
    }

    /* (void) casts suppress [[nodiscard]] warnings in FreeRDP 3.23+ */
    (void)freerdp_settings_set_string(settings, FreeRDP_ServerHostname, host);
    (void)freerdp_settings_set_uint32(settings, FreeRDP_ServerPort,     (UINT32)jPort);
    (void)freerdp_settings_set_string(settings, FreeRDP_Username,       user);
    (void)freerdp_settings_set_string(settings, FreeRDP_Password,       pass);
    (void)freerdp_settings_set_string(settings, FreeRDP_Domain,         domain);
    (void)freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth,   (UINT32)jWidth);
    (void)freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight,  (UINT32)jHeight);
    (void)freerdp_settings_set_bool  (settings, FreeRDP_NlaSecurity,    jUseNla ? TRUE : FALSE);
    (void)freerdp_settings_set_bool  (settings, FreeRDP_TlsSecurity,    TRUE);
    (void)freerdp_settings_set_bool  (settings, FreeRDP_RdpSecurity,    TRUE);
    /* BUG-4 FIX: was always TRUE → every session vulnerable to MITM.
     * Now uses caller-supplied jIgnoreCert (default false from Kotlin). */
    (void)freerdp_settings_set_bool  (settings, FreeRDP_IgnoreCertificate, jIgnoreCert ? TRUE : FALSE);
    /* BUG-1 FIX: apply the three parameters that were declared in Kotlin but ignored in C. */
    (void)freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth,        (UINT32)jColorDepth);
    (void)freerdp_settings_set_uint32(settings, FreeRDP_PerformanceFlags,  (UINT32)jPerformanceMode);
    /* BUG-QUALITY FIX: jCompressionQuality is an app-level value in the range 0–100
     * (higher = better quality). FreeRDP_RemoteFxCodecMode expects a 0–2 enum:
     *   0 = VIDEO (high-motion, lower quality)
     *   1 = IMAGE (low-motion, higher quality)
     * Map the 0-100 range: ≥50 → IMAGE (1, higher quality), <50 → VIDEO (0, lower quality).
     * Previously passing a raw value like 75 was way outside the valid enum range and
     * caused undefined behaviour in the FreeRDP codec. */
    {
        UINT32 rfxMode = (jCompressionQuality >= 50) ? 1 /* IMAGE */ : 0 /* VIDEO */;
        (void)freerdp_settings_set_uint32(settings, FreeRDP_RemoteFxCodecMode, rfxMode);
    }

    if (jGatewayEnabled)
    {
        const char* gwHost   = (*env)->GetStringUTFChars(env, jGwHost,   NULL);
        const char* gwUser   = (*env)->GetStringUTFChars(env, jGwUser,   NULL);
        const char* gwPass   = (*env)->GetStringUTFChars(env, jGwPass,   NULL);
        const char* gwDomain = (*env)->GetStringUTFChars(env, jGwDomain, NULL);

        /* BUG-OOM FIX: GetStringUTFChars returns NULL on OOM (low-RAM devices).
         * Passing NULL to freerdp_settings_set_string causes a native crash.
         * Release whatever was allocated and bail out cleanly. */
        if (!gwHost || !gwUser || !gwPass || !gwDomain)
        {
            if (gwHost)   (*env)->ReleaseStringUTFChars(env, jGwHost,   gwHost);
            if (gwUser)   (*env)->ReleaseStringUTFChars(env, jGwUser,   gwUser);
            if (gwPass)   (*env)->ReleaseStringUTFChars(env, jGwPass,   gwPass);
            if (gwDomain) (*env)->ReleaseStringUTFChars(env, jGwDomain, gwDomain);
            (*env)->ReleaseStringUTFChars(env, jHost,     host);
            (*env)->ReleaseStringUTFChars(env, jUsername, user);
            (*env)->ReleaseStringUTFChars(env, jPassword, pass);
            (*env)->ReleaseStringUTFChars(env, jDomain,   domain);
            return JNI_FALSE;
        }

        (void)freerdp_settings_set_bool  (settings, FreeRDP_GatewayEnabled,      TRUE);
        (void)freerdp_settings_set_string(settings, FreeRDP_GatewayHostname,     gwHost);
        (void)freerdp_settings_set_uint32(settings, FreeRDP_GatewayPort,         (UINT32)jGwPort);
        (void)freerdp_settings_set_string(settings, FreeRDP_GatewayUsername,     gwUser);
        (void)freerdp_settings_set_string(settings, FreeRDP_GatewayPassword,     gwPass);
        (void)freerdp_settings_set_string(settings, FreeRDP_GatewayDomain,       gwDomain);
        (void)freerdp_settings_set_uint32(settings, FreeRDP_GatewayUsageMethod,  1 /* TSC_PROXY_MODE_DIRECT */);

        (*env)->ReleaseStringUTFChars(env, jGwHost,   gwHost);
        (*env)->ReleaseStringUTFChars(env, jGwUser,   gwUser);
        (*env)->ReleaseStringUTFChars(env, jGwPass,   gwPass);
        (*env)->ReleaseStringUTFChars(env, jGwDomain, gwDomain);
    }

    (*env)->ReleaseStringUTFChars(env, jHost,     host);
    (*env)->ReleaseStringUTFChars(env, jUsername, user);
    (*env)->ReleaseStringUTFChars(env, jPassword, pass);
    (*env)->ReleaseStringUTFChars(env, jDomain,   domain);

    BOOL ok = freerdp_connect(instance);
    if (!ok)
    {
        hexrdpContext* hctx = HEXRDP_CTX(instance);
        UINT32 code = freerdp_get_last_error(instance->context);
        const char* name = freerdp_get_last_error_name(code);
        (*env)->CallVoidMethod(env, hctx->bridgeObjGlobalRef, hctx->onErrorMethod,
                                (*env)->NewStringUTF(env, name ? name : "Unknown FreeRDP error"));
    }
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_gotohex_rdp_rdp_native_AFreeRdpBridge_nativeSendMouse(
    JNIEnv* env, jobject thiz, jlong handle, jint x, jint y, jint flags)
{
    (void)env; (void)thiz;
    freerdp* instance = (freerdp*)(intptr_t)handle;
    if (!instance || !instance->context->input) return;
    (void)freerdp_input_send_mouse_event(instance->context->input,
                                          (UINT16)flags, (UINT16)x, (UINT16)y);
}

JNIEXPORT void JNICALL
Java_com_gotohex_rdp_rdp_native_AFreeRdpBridge_nativeSendKey(
    JNIEnv* env, jobject thiz, jlong handle, jint scanCode, jboolean down, jboolean extended)
{
    (void)env; (void)thiz;
    freerdp* instance = (freerdp*)(intptr_t)handle;
    if (!instance || !instance->context->input) return;
    UINT16 kflags = (UINT16)((down ? 0 : KBD_FLAGS_RELEASE) | (extended ? KBD_FLAGS_EXTENDED : 0));
    (void)freerdp_input_send_keyboard_event(instance->context->input, kflags, (UINT16)scanCode);
}

JNIEXPORT void JNICALL
Java_com_gotohex_rdp_rdp_native_AFreeRdpBridge_nativeDisconnect(JNIEnv* env, jobject thiz, jlong handle)
{
    (void)env; (void)thiz;
    freerdp* instance = (freerdp*)(intptr_t)handle;
    if (!instance) return;
    freerdp_disconnect(instance);
}

JNIEXPORT void JNICALL
Java_com_gotohex_rdp_rdp_native_AFreeRdpBridge_nativeFree(JNIEnv* env, jobject thiz, jlong handle)
{
    (void)thiz;
    freerdp* instance = (freerdp*)(intptr_t)handle;
    if (!instance) return;
    hexrdpContext* hctx = HEXRDP_CTX(instance);
    if (hctx && hctx->bridgeObjGlobalRef)
        (*env)->DeleteGlobalRef(env, hctx->bridgeObjGlobalRef);
    freerdp_context_free(instance);
    freerdp_free(instance);
}
