package org.matrix.demo;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

/**
 * Sepolicy probe service. Declared in AndroidManifest.xml with both
 * {@code isolatedProcess="true"} and {@code useAppZygote="true"}, so it is forked from the
 * app zygote whose {@link SepolicyZygote#doPreload} already computed the result while
 * transitioning into this process's restricted context (see SepolicyZygote for why that
 * transition requires SELinux access the app zygote alone can exercise).
 */
public class SepolicyProbeService extends Service {

    private final IDemoProbeService.Stub binder = new IDemoProbeService.Stub() {
        @Override
        public String getResult() {
            Log.i(ProcScanner.TAG, "SepolicyProbeService.getResult() invoked in "
                    + (Process.isIsolated() ? "isolated" : "NON-isolated") + " process pid="
                    + Process.myPid());
            return SepolicyZygote.result;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        Log.i(ProcScanner.TAG, "SepolicyProbeService.onBind() pid=" + Process.myPid()
                + " isolated=" + Process.isIsolated());
        // Only serve when we really are isolated; a non-isolated bind would prove the
        // sandbox never engaged and the whole premise is moot.
        return Process.isIsolated() ? binder : null;
    }
}
