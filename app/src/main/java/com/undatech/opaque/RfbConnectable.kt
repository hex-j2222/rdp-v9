package com.undatech.opaque

import android.content.Context
import android.graphics.Bitmap

/**
 * STUB — يحاكي com.undatech.opaque.RfbConnectable من مكتبة bVNC/remoteClientLib.
 *
 * الـ API المُحاكاة مستخرجة من VncClient.kt:
 *   - connect()              → يُنشئ اتصال RFB
 *   - framebuffer            → آخر Bitmap تم استقباله من الخادم
 *   - sendPointerEvent()     → يُرسل حركة/نقر الفأرة
 *   - sendKeyEvent()         → يُرسل حدث لوحة مفاتيح (X11 keysym)
 *   - close()                → يُغلق الاتصال
 *
 * هذا الـ stub يرمي [UnsupportedOperationException] عند الاستخدام الفعلي —
 * هدفه فقط جعل الكود يُترجَم ويمر lint.
 */
class RfbConnectable(
    private val connection: Connection,
    @Suppress("UNUSED_PARAMETER") private val context: Context,
) {

    /** آخر Bitmap مُستقبَل من خادم VNC. null حتى الاتصال الأول. */
    var framebuffer: Bitmap? = null
        private set

    /**
     * يفتح اتصال RFB بالخادم المُحدَّد في [connection].
     * @throws AuthenticationException إذا رفض الخادم كلمة المرور.
     * @throws java.io.IOException عند فشل الاتصال.
     */
    fun connect() {
        throw UnsupportedOperationException(
            "VNC stub: يجب دمج iiordanov/remote-desktop-clients كـ submodule " +
            "أو تضمين AARs المُجمَّعة مسبقاً لتشغيل VNC."
        )
    }

    /** يُرسل حدث مؤشر (حركة / نقر / تمرير). mask: بتّات أزرار الفأرة (1=يسار، 2=وسط، 4=يمين). */
    fun sendPointerEvent(x: Int, y: Int, mask: Int) { /* stub */ }

    /** يُرسل حدث لوحة مفاتيح. keysym: رقم X11 keysym. down: true=ضغط، false=رفع. */
    fun sendKeyEvent(keysym: Int, down: Boolean) { /* stub */ }

    /** يُغلق الاتصال ويُحرِّر الموارد. */
    fun close() { /* stub */ }
}

