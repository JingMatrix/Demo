package org.matrix.demo;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

/**
 * Declared with {@code android:nativeService="true"}. On Android 17 the framework
 * routes this to zygote_next: it loads {@code libmain.so} from the APK and calls
 * {@code ANativeService_onCreate} (see cpp/probe.cpp), which registers its own
 * binder — the JNI Service methods below are then NOT used for the native path.
 *
 * <p>This Java class remains as the declared component and as a graceful fallback:
 * on a platform that instantiates it as an ordinary isolated service, it still runs
 * a scan (tagged native-fallback) so the app degrades instead of failing to bind.
 */
public class NativeProbeService extends Service {

    private final IDemoProbeService.Stub binder = new IDemoProbeService.Stub() {
        @Override
        public String getResult() {
            Log.i(ProcScanner.TAG, "NativeProbeService(JAVA fallback).getResult() pid="
                    + Process.myPid() + " isolated=" + Process.isIsolated());
            return ProcScanner.scan("native-fallback").toString();
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return Process.isIsolated() ? binder : null;
    }
}
