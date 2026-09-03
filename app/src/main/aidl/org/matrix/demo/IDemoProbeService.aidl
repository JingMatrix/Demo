package org.matrix.demo;

// Both the classic isolated service and the native (zygote_next) service
// implement this. getResult() returns a JSON document describing everything the
// probe observed, which MainActivity renders into the HTML dashboard.
interface IDemoProbeService {
    String getResult();
}
