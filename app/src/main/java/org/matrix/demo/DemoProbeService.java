package org.matrix.demo;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

/**
 * Classic isolated service (forked from zygote). Inherits AID_READPROC, so it runs
 * the wide cross-process scan. Returns the JSON document to MainActivity.
 */
public class DemoProbeService extends Service {

    private final IDemoProbeService.Stub binder = new IDemoProbeService.Stub() {
        @Override
        public String getResult() {
            Log.i(ProcScanner.TAG, "DemoProbeService.getResult() invoked in "
                    + (Process.isIsolated() ? "isolated" : "NON-isolated") + " process pid="
                    + Process.myPid());
            return ProcScanner.scan("classic-isolated").toString();
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        // Only serve when we really are isolated; a non-isolated bind would prove the
        // sandbox never engaged and the whole premise is moot.
        return Process.isIsolated() ? binder : null;
    }
}
