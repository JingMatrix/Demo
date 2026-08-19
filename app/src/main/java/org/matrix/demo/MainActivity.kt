package org.matrix.demo

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONArray
import org.json.JSONObject

/**
 * Binds both probe services (classic isolated + native zygote_next), collects their
 * JSON reports, and renders a native Jetpack Compose (Material 3) dashboard.
 * Full detail remains in logcat (adb logcat -s DemoProbe).
 */
class MainActivity : ComponentActivity() {

    private var classicResult by mutableStateOf<JSONObject?>(null)
    private var nativeResult by mutableStateOf<JSONObject?>(null)
    private var classicDone by mutableStateOf(false)
    private var nativeDone by mutableStateOf(false)
    private var integrityResult by mutableStateOf<JSONObject?>(null)

    private val handler = Handler(Looper.getMainLooper())

    // Main-process native integrity checks (injection / mount tamper), libdemo.so.
    private external fun runIntegrityChecks(): String

    private inner class Conn(val tag: String, val isNative: Boolean) : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            try {
                val raw = IDemoProbeService.Stub.asInterface(binder).getResult()
                Log.i(ProcScanner.TAG, "$tag raw report ${raw.length} bytes")
                val o = JSONObject(raw)
                if (isNative) nativeResult = o else classicResult = o
            } catch (e: Exception) {
                Log.e(ProcScanner.TAG, "$tag failed", e)
            } finally {
                mark(isNative)
                runCatching { unbindService(this) }
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {}

        override fun onNullBinding(name: ComponentName) {
            Log.w(ProcScanner.TAG, "$tag null binding (service returned null)")
            mark(isNative)
            runCatching { unbindService(this) }
        }
    }

    private fun mark(isNative: Boolean) {
        if (isNative) nativeDone = true else classicDone = true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        bind(Intent(this, DemoProbeService::class.java), Conn("classic", false))
        bind(Intent(this, NativeProbeService::class.java), Conn("native", true))

        // safety net: mark everything done after 8s even if a bind hung
        handler.postDelayed({
            if (!(classicDone && nativeDone)) {
                Log.w(ProcScanner.TAG, "timeout; rendering partial")
                classicDone = true
                nativeDone = true
            }
        }, 8000)

        // main-process native integrity checks (libdemo.so), off the UI thread
        Thread {
            val r = try {
                JSONObject(runIntegrityChecks())
            } catch (e: Throwable) {
                Log.e(ProcScanner.TAG, "integrity failed", e)
                null
            }
            runOnUiThread { integrityResult = r }
        }.start()

        setContent {
            DemoTheme {
                DemoApp(
                    integrity = integrityResult,
                    classic = classicResult,
                    nativeR = nativeResult,
                    loading = !(classicDone && nativeDone),
                )
            }
        }
    }

    private fun bind(intent: Intent, conn: Conn) {
        try {
            if (!bindService(intent, conn, Context.BIND_AUTO_CREATE)) {
                Log.w(ProcScanner.TAG, "${conn.tag} bindService returned false")
                mark(conn.isNative)
            }
        } catch (e: Exception) {
            Log.e(ProcScanner.TAG, "${conn.tag} bind threw", e)
            mark(conn.isNative)
        }
    }

    private companion object {
        init {
            System.loadLibrary("demo")
        }
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
@Composable
private fun DemoTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

private val Good: Color
    @Composable get() = if (isSystemInDarkTheme()) Color(0xFF3FB950) else Color(0xFF2E7D32)

// ---------------------------------------------------------------------------
// App scaffold
// ---------------------------------------------------------------------------
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DemoApp(integrity: JSONObject?, classic: JSONObject?, nativeR: JSONObject?, loading: Boolean) {
    var tab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Report", "Logs")

    val context = LocalContext.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("JingMatrix/Demo") },
                actions = {
                    IconButton(onClick = { exportCurrent(context, tab, integrity, classic, nativeR) }) {
                        Icon(painterResource(R.drawable.ic_save), contentDescription = "Save")
                    }
                    IconButton(onClick = {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/JingMatrix/Demo")),
                        )
                    }) {
                        Icon(painterResource(R.drawable.ic_github), contentDescription = "GitHub repository")
                    }
                },
            )
        },
    ) { inner ->
        Column(Modifier.padding(inner).fillMaxSize()) {
            TabRow(selectedTabIndex = tab) {
                tabs.forEachIndexed { i, title ->
                    Tab(
                        selected = tab == i,
                        onClick = { tab = i },
                        text = { Text(title) },
                    )
                }
            }
            when (tab) {
                0 -> ReportTab(integrity, classic, nativeR, loading)
                else -> LogsTab(integrity, classic, nativeR)
            }
        }
    }
}

@Composable
private fun ReportTab(integrity: JSONObject?, classic: JSONObject?, nativeR: JSONObject?, loading: Boolean) {
    val expanded = remember { mutableStateMapOf<String, Boolean>() }
    fun exp(k: String) = expanded[k] ?: true
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        integrity?.let { integritySection(it, exp("integrity"), { toggle(expanded, "integrity") }) }
        if (loading) {
            item {
                Row(
                    Modifier.fillMaxWidth().padding(8.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.width(20.dp))
                    Text(
                        "Running probes… (detailed trace in adb logcat -s DemoProbe)",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
        if (classic != null) {
            reportSection(classic, "classic isolated", exp("classic"), { toggle(expanded, "classic") })
        } else if (!loading) {
            item { LabelRow("Classic isolated probe did not report.") }
        }
        if (nativeR != null) {
            reportSection(nativeR, "native zygote_next", exp("native"), { toggle(expanded, "native") })
        }
    }
}

private fun sectionDetected(r: JSONObject) = r.optJSONObject("verdict")?.optBoolean("detected") == true

private fun toggle(map: MutableMap<String, Boolean>, key: String) {
    map[key] = !(map[key] ?: true)
}

private fun LazyListScope.reportSection(r: JSONObject, label: String, expanded: Boolean, onToggle: () -> Unit) {
    item { SectionHeader(label, expanded, onToggle, sectionDetected(r)) }
    if (!expanded) return
    item { VerdictCard(r) }
    environmentCard(r)?.let { block -> item { block() } }
    reconcileCard(r.optJSONObject("reconcile"))?.let { block -> item { block() } }
    markerHitsCard(r.optJSONArray("markerHits"))?.let { block -> item { block() } }
    differentialCard(r.optJSONObject("differential"))?.let { block -> item { block() } }
    fileAccessCard(r)?.let { block -> item { block() } }
    crossFileCard(r.optJSONArray("crossFile"))?.let { block -> item { block() } }
    selfVsInitCard(r.optJSONObject("selfVsInit"))?.let { block -> item { block() } }
    namespaceGroupsCard(r.optJSONObject("namespaceGroups"))?.let { block -> item { block() } }
    processesCards(r.optJSONArray("processes"), this)
    nativeExtrasCards(r, this)
}

// Main-process native integrity detections (injection / mount tamper).
private fun LazyListScope.integritySection(r: JSONObject, expanded: Boolean, onToggle: () -> Unit) {
    item { SectionHeader("main-process integrity", expanded, onToggle, sectionDetected(r)) }
    if (!expanded) return
    item { VerdictCard(r) }
    val checks = r.optJSONArray("checks") ?: return
    // Two distinct families: process-integrity (linker solist / memory) vs mount
    // namespace tampering. Render them as separate groups, injection first.
    integrityGroupCard(checks, "injection", "Injection detections")?.let { block -> item { block() } }
    integrityGroupCard(checks, "mount", "Mount traces")?.let { block -> item { block() } }
    // The detailed reconciliation findings/probes belong to the mount family.
    reconcileCard(r.optJSONObject("reconcile"))?.let { block -> item { block() } }
}

// One card for a single detection family (by the check's "type"). Returns null when
// the report carries no checks of that family.
private fun integrityGroupCard(checks: JSONArray, type: String, title: String): (@Composable () -> Unit)? {
    val group = ArrayList<JSONObject>()
    for (i in 0 until checks.length()) {
        val c = checks.optJSONObject(i) ?: continue
        if (c.optString("type") == type) group.add(c)
    }
    if (group.isEmpty()) return null
    val detected = group.count { it.optBoolean("detected") }
    return {
        StageCard {
            CardTitle("$title  ·  $detected/${group.size} detected")
            for (c in group) {
                val det = c.optBoolean("detected")
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Text(
                        if (det) "●" else "○",
                        color = if (det) MaterialTheme.colorScheme.error else Good,
                        modifier = Modifier.width(20.dp),
                    )
                    Column(Modifier.weight(1f)) {
                        Text(c.optString("name"), fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        Text(
                            c.optString("detail"),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cards per stage. Each builder returns a composable or null when there is
// nothing to render, so empty stages are simply skipped.
// ---------------------------------------------------------------------------
@Composable
private fun VerdictCard(r: JSONObject) {
    val verdict = r.optJSONObject("verdict")
    val detected = verdict != null && verdict.optBoolean("detected")
    val reasons = verdict?.optJSONArray("reasons").toStringList()
    val accent = if (detected) MaterialTheme.colorScheme.error else Good
    val container =
        if (detected) MaterialTheme.colorScheme.errorContainer else Good.copy(alpha = 0.12f)
    val bodyColor =
        if (detected) MaterialTheme.colorScheme.onErrorContainer
        else MaterialTheme.colorScheme.onSurface
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = container),
    ) {
        Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
            Box(Modifier.width(5.dp).fillMaxHeight().background(accent))
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        if (detected) "DETECTED" else "CLEAN",
                        color = accent,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 18.sp,
                    )
                    val count =
                        if (reasons.isNotEmpty()) "  ·  ${reasons.size} reason(s)"
                        else if (detected) "" else "  ·  no anomalies"
                    if (count.isNotEmpty()) {
                        Text(
                            count,
                            color = bodyColor,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                reasons.forEach { BulletRow(it, bodyColor) }
            }
        }
    }
}

private fun environmentCard(r: JSONObject): (@Composable () -> Unit)? {
    val self = r.optJSONObject("self") ?: return null
    val items = ArrayList<Pair<String, String>>()
    fun add(label: String, key: String) {
        if (self.has(key)) items.add(label to self.optString(key))
    }
    add("pid", "pid")
    add("uid", "uid")
    add("isolated", "isolated")
    if (self.has("hasReadproc")) items.add("readproc(3009)" to self.optString("hasReadproc"))
    add("mnt ns", "nsMnt")
    if (self.has("proc1Readable")) items.add("/proc/1 read" to self.optString("proc1Readable"))
    add("root prop", "selfPropagation")
    if (r.has("visiblePids")) items.add("visible pids" to r.optString("visiblePids"))
    if (r.has("readableMountinfoPids")) {
        items.add("readable mnt pids" to r.optString("readableMountinfoPids"))
    }
    // surface any additional self.* fields (e.g. native schema variants) so nothing is dropped
    val covered = setOf(
        "pid", "uid", "isolated", "hasReadproc", "nsMnt", "proc1Readable", "selfPropagation",
    )
    val keys = self.keys()
    while (keys.hasNext()) {
        val k = keys.next()
        if (k !in covered) items.add(k to self.optString(k))
    }
    return {
        StageCard {
            CardTitle("Environment")
            KvGrid(items)
        }
    }
}

private fun markerHitsCard(hits: JSONArray?): (@Composable () -> Unit)? {
    if (hits == null || hits.length() == 0) return null
    // Native marker hits use a different schema {labels, high, line}; branch on it.
    val first = hits.optJSONObject(0)
    val native = first != null && (first.has("labels") || first.has("line"))
    val header: List<String>
    val rows = ArrayList<List<String>>(hits.length())
    if (native) {
        header = listOf("high", "labels", "line")
        for (i in 0 until hits.length()) {
            val h = hits.optJSONObject(i) ?: continue
            rows.add(
                listOf(
                    h.optInt("high").toString(),
                    h.optString("labels"),
                    h.optString("line"),
                ),
            )
        }
    } else {
        // conf moved to the front so the verdict-relevant column is always on-screen; the
        // kernel-truncated comm is pushed last since it is the widest, least-diagnostic column.
        header = listOf("pid", "conf", "label", "file", "field", "comm")
        for (i in 0 until hits.length()) {
            val h = hits.optJSONObject(i) ?: continue
            rows.add(
                listOf(
                    h.optString("pid"),
                    h.optInt("confidence").toString(),
                    h.optString("label"),
                    h.optString("file"),
                    h.optString("field"),
                    h.optString("comm"),
                ),
            )
        }
    }
    return {
        StageCard {
            CardTitle("Marker hits (${rows.size})")
            MonoBlock(monoTable(header, rows))
        }
    }
}

// Mount reconciliation: kernel stat ground truth vs mountinfo. The one mount check
// that survives kernel-side mountinfo filtering (KSU mount_hide et al.).
private fun reconcileCard(recon: JSONObject?): (@Composable () -> Unit)? {
    if (recon == null) return null
    val hidden = recon.optInt("hidden")
    val structural = recon.optInt("structural")
    val findings = recon.optJSONArray("findings")
    return {
        StageCard {
            CardTitle("Mount reconciliation — hidden=$hidden structural=$structural")
            if (findings == null || findings.length() == 0) {
                Text(
                    "mountinfo matches kernel stat ground truth (no hidden mounts)",
                    color = Good,
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                val rows = ArrayList<List<String>>(findings.length())
                for (i in 0 until findings.length()) {
                    val f = findings.optJSONObject(i) ?: continue
                    rows.add(
                        listOf(
                            f.optString("severity"),
                            f.optString("path"),
                            f.optString("detail"),
                        ),
                    )
                }
                MonoBlock(monoTable(listOf("sev", "path", "detail"), rows))
            }
            val probes = recon.optJSONArray("probes")
            if (probes != null && probes.length() > 0) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "probe outcomes (single-file bind targets)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val prows = ArrayList<List<String>>(probes.length())
                for (i in 0 until probes.length()) {
                    val p = probes.optJSONObject(i) ?: continue
                    prows.add(
                        listOf(
                            p.optString("path"),
                            if (p.optBoolean("exists")) "y" else "n",
                            if (p.optBoolean("mountRoot")) "y" else "n",
                            p.optString("fs"),
                            if (p.optBoolean("inMountinfo")) "y" else "n",
                        ),
                    )
                }
                MonoBlock(monoTable(listOf("path", "exist", "mnt", "fs", "in-mi"), prows))
            }
        }
    }
}

private fun differentialCard(diff: JSONObject?): (@Composable () -> Unit)? {
    if (diff == null) return null
    val files = listOf("mountinfo", "mounts", "mountstats")
    if (files.none { diff.optJSONObject(it) != null }) return null
    return {
        StageCard {
            CardTitle("Differential (distinct views vs propagation classes)")
            Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                Cell("file", 0.34f, header = true)
                Cell("views", 0.18f, header = true)
                Cell("classes", 0.24f, header = true)
                Cell("result", 0.24f, header = true)
            }
            for (f in files) {
                val d = diff.optJSONObject(f) ?: continue
                val mismatch = d.optBoolean("mismatch")
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Cell(f, 0.34f)
                    Cell(d.optInt("distinctViews").toString(), 0.18f)
                    Cell(d.optInt("propagationClasses").toString(), 0.24f)
                    Cell(
                        if (mismatch) "MISMATCH" else "ok",
                        0.24f,
                        color = if (mismatch) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            for (f in files) {
                val d = diff.optJSONObject(f) ?: continue
                val groups = d.optJSONArray("groups")
                val a = d.optJSONArray("diffOnlyInGroupA").toStringList()
                val b = d.optJSONArray("diffOnlyInGroupB").toStringList()
                val hasGroups = groups != null && groups.length() > 0
                if (!hasGroups && a.isEmpty() && b.isEmpty()) continue
                SubLabel("$f — class membership & differing lines:")
                val lines = ArrayList<String>()
                if (hasGroups) {
                    for (i in 0 until groups!!.length()) {
                        val g = groups.optJSONObject(i) ?: continue
                        val pids = g.optJSONArray("samplePids").toStringList().joinToString(", ")
                        lines.add(
                            "class ${i + 1}: ${g.optInt("pidCount")} pids [$pids] " +
                                "(${g.optInt("lineCount")} lines)",
                        )
                    }
                }
                a.forEach { lines.add("only in group A: $it") }
                b.forEach { lines.add("only in group B: $it") }
                MonoBlock(lines)
            }
        }
    }
}

// Fixed schema order for the file-access matrix rows (mirrors ProcScanner's
// SENSITIVE_FILES + SENSITIVE_LINKS + SENSITIVE_DIRS), so rows never appear in JSON hash order.
private val FILE_ACCESS_ROWS = listOf(
    "cmdline", "comm", "stat", "status", "statm", "cgroup", "wchan", "sched", "limits",
    "personality", "io", "syscall", "maps", "smaps", "smaps_rollup", "pagemap", "auxv",
    "environ", "mem", "mountinfo", "mounts", "mountstats", "attr/current",
    "ns/mnt", "ns/pid", "ns/net", "ns/user", "root", "cwd", "exe",
    "fd", "fdinfo",
)

private fun fileAccessCard(r: JSONObject): (@Composable () -> Unit)? {
    val fa = r.optJSONObject("fileAccess") ?: return null
    val keys = ArrayList<String>()
    val it = fa.keys()
    while (it.hasNext()) keys.add(it.next())
    if (keys.isEmpty()) return null

    val selfPid = r.optJSONObject("self")?.optString("pid").orEmpty()
    // order columns self -> peers (ascending) -> init(1), then any leftover
    val ordered = ArrayList<String>()
    if (selfPid.isNotEmpty() && keys.contains(selfPid)) ordered.add(selfPid)
    keys.filter { it != selfPid && it != "1" }
        .sortedBy { it.toIntOrNull() ?: Int.MAX_VALUE }
        .forEach { ordered.add(it) }
    if (keys.contains("1")) ordered.add("1")
    keys.filter { it !in ordered }.forEach { ordered.add(it) }

    fun role(pid: String) = when (pid) {
        selfPid -> "self"
        "1" -> "init"
        else -> "peer"
    }

    // union all inner keys, but render in fixed schema order first, then any extras
    val extraRows = ArrayList<String>()
    for (pid in ordered) {
        val obj = fa.optJSONObject(pid) ?: continue
        val ik = obj.keys()
        while (ik.hasNext()) {
            val k = ik.next()
            if (k !in FILE_ACCESS_ROWS && k !in extraRows) extraRows.add(k)
        }
    }
    val rowKeys = FILE_ACCESS_ROWS + extraRows

    return {
        StageCard {
            CardTitle("File access — /proc/<pid> readability (${ordered.size} targets)")
            SubLabel("✓ = readable / resolved link · otherwise the errno; columns self / peer / init")
            val scroll = rememberScrollState()
            Box(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
                    .background(
                        MaterialTheme.colorScheme.surfaceContainerHighest,
                        RoundedCornerShape(6.dp),
                    )
                    .horizontalScroll(scroll)
                    .padding(horizontal = 10.dp, vertical = 8.dp),
            ) {
                Column {
                    // header row
                    Row {
                        MatrixLabel("proc file", header = true)
                        for (pid in ordered) MatrixHead(role(pid), pid)
                    }
                    for (key in rowKeys) {
                        Row(Modifier.padding(top = 2.dp)) {
                            MatrixLabel(key)
                            for (pid in ordered) {
                                val v = fa.optJSONObject(pid)?.optString(key).orEmpty()
                                MatrixCell(v)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MatrixLabel(text: String, header: Boolean = false) {
    Text(
        text,
        modifier = Modifier.width(126.dp).padding(end = 6.dp),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        fontWeight = if (header) FontWeight.SemiBold else FontWeight.Normal,
        maxLines = 1,
    )
}

@Composable
private fun MatrixHead(role: String, pid: String) {
    Column(Modifier.width(78.dp).padding(end = 4.dp)) {
        Text(
            role,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 10.sp,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            pid,
            color = MaterialTheme.colorScheme.onSurface,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            maxLines = 1,
        )
    }
}

@Composable
private fun MatrixCell(value: String) {
    val ok = value.startsWith("ok") || value.startsWith("->")
    Text(
        shortErrno(value),
        modifier = Modifier.width(78.dp).padding(end = 4.dp),
        color = if (ok) Good else MaterialTheme.colorScheme.error,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        fontWeight = if (ok) FontWeight.Bold else FontWeight.Normal,
        maxLines = 1,
    )
}

private fun shortErrno(v: String): String = when {
    v.isEmpty() -> "·"
    v.startsWith("ok") || v.startsWith("->") -> "✓"
    v == "AccessDeniedException" -> "EACCES"
    v == "NoSuchFileException" -> "ENOENT"
    v == "NotDirectoryException" -> "ENOTDIR"
    v == "FileSystemException" -> "EIO"
    v == "IOException" -> "EIO"
    v.endsWith("Exception") -> v.removeSuffix("Exception")
    else -> v
}

private fun crossFileCard(cross: JSONArray?): (@Composable () -> Unit)? {
    if (cross == null || cross.length() == 0) return null
    return {
        StageCard {
            CardTitle("Cross-file asymmetry (mountinfo vs mounts)")
            val lines = ArrayList<String>()
            for (i in 0 until cross.length()) {
                val o = cross.optJSONObject(i) ?: continue
                lines.add("pid ${o.optString("pid")} ${o.optString("comm")}")
                o.optJSONArray("onlyInMountinfo").toStringList()
                    .forEach { lines.add("  only in mountinfo: $it") }
                o.optJSONArray("onlyInMounts").toStringList()
                    .forEach { lines.add("  only in mounts:    $it") }
            }
            MonoBlock(lines)
        }
    }
}

private fun selfVsInitCard(svi: JSONObject?): (@Composable () -> Unit)? {
    if (svi == null || !svi.optBoolean("initReadable")) return null
    return {
        StageCard {
            CardTitle("Self vs init (global view)")
            KvGrid(
                listOf(
                    "self mounts" to svi.optString("selfMounts"),
                    "init mounts" to svi.optString("initMounts"),
                ),
            )
            val onlyInit = svi.optJSONArray("onlyInInit").toStringList()
            val onlySelf = svi.optJSONArray("onlySelf").toStringList()
            if (onlyInit.isNotEmpty() || onlySelf.isNotEmpty()) {
                val lines = onlyInit.map { "in init, not in self: $it" } +
                    onlySelf.map { "in self, not in init: $it" }
                MonoBlock(lines)
            }
        }
    }
}

private fun namespaceGroupsCard(ns: JSONObject?): (@Composable () -> Unit)? {
    if (ns == null) return null
    val groups = ns.optJSONArray("groups")
    if (groups == null || groups.length() == 0) return null
    return {
        StageCard {
            CardTitle("Namespace groups (${ns.optInt("distinctNamespaces")} distinct)")
            Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                Cell("mnt ns", 0.7f, header = true, mono = true)
                Cell("pids", 0.3f, header = true)
            }
            for (i in 0 until groups.length()) {
                val g = groups.optJSONObject(i) ?: continue
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Cell("${g.opt("nsMnt")}", 0.7f, mono = true)
                    Cell(g.optInt("pidCount").toString(), 0.3f)
                }
            }
        }
    }
}

private fun processesCards(procs: JSONArray?, scope: LazyListScope) {
    if (procs == null || procs.length() == 0) return
    scope.item { CardTitle("Mount records (${procs.length()} processes)", topPad = true) }
    for (i in 0 until procs.length()) {
        val p = procs.optJSONObject(i) ?: continue
        scope.item { ProcessCard(p) }
    }
}

@Composable
private fun ProcessCard(p: JSONObject) {
    val header = "pid ${p.optString("pid")} ${p.optString("comm")}  " +
        "uid=${p.optString("uid")} ns=${p.optString("nsMnt")} prop=${p.optString("propagation")}"
    ExpandableCard(header) {
        val files = p.optJSONObject("files")
        if (files == null) {
            LabelRow("(no readable mount files)")
            return@ExpandableCard
        }
        var any = false
        for (f in listOf("mountinfo", "mounts", "mountstats")) {
            val fo = files.optJSONObject(f) ?: continue
            if (!fo.optBoolean("readable")) continue
            val lines = fo.optJSONArray("lines").toStringList()
            if (lines.isEmpty()) continue
            any = true
            SubLabel(
                "$f (${fo.optInt("lineCount")} lines" +
                    (if (fo.optBoolean("truncated")) ", truncated" else "") + ")",
            )
            MonoBlock(lines)
        }
        if (!any) LabelRow("(no readable mount files)")
    }
}

private fun nativeExtrasCards(r: JSONObject, scope: LazyListScope) {
    val stats = r.optJSONObject("stats")
    val verdict = r.optJSONObject("verdict")
    val hasNativeVerdict = verdict != null && verdict.has("globalViewSignature")
    if (stats != null || hasNativeVerdict) {
        scope.item {
            StageCard {
                CardTitle("Native stats")
                val items = ArrayList<Pair<String, String>>()
                if (stats != null) {
                    if (stats.has("mountinfoLines")) {
                        items.add("mountinfo lines" to stats.optString("mountinfoLines"))
                    }
                    if (stats.has("markerLines")) {
                        items.add("marker lines" to stats.optString("markerLines"))
                    }
                    if (stats.has("highHits")) items.add("high hits" to stats.optString("highHits"))
                }
                if (hasNativeVerdict) {
                    if (verdict!!.has("highHits")) {
                        items.add("verdict high" to verdict.optString("highHits"))
                    }
                    if (verdict.has("propagation")) {
                        items.add("propagation" to verdict.optString("propagation"))
                    }
                    items.add("global view sig" to verdict.optString("globalViewSignature"))
                }
                KvGrid(items)
            }
        }
    }
    val mi = r.optJSONArray("mountinfo").toStringList()
    if (mi.isNotEmpty()) {
        scope.item {
            ExpandableCard("Native /proc/self/mountinfo (${mi.size} lines)") {
                MonoBlock(mi)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Logs tab
// ---------------------------------------------------------------------------
@Composable
private fun LogsTab(integrity: JSONObject?, classic: JSONObject?, nativeR: JSONObject?) {
    val expanded = remember { mutableStateMapOf<String, Boolean>() }
    fun exp(k: String) = expanded[k] ?: true
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        logSection(integrity, "main-process integrity", exp("li"), { toggle(expanded, "li") })
        logSection(classic, "classic isolated", exp("lc"), { toggle(expanded, "lc") })
        logSection(nativeR, "native zygote_next", exp("ln"), { toggle(expanded, "ln") })
    }
}

// Export the currently-shown panel: Report -> combined JSON; Logs -> combined log text.
private fun exportCurrent(
    context: android.content.Context,
    tab: Int,
    integrity: JSONObject?,
    classic: JSONObject?,
    nativeR: JSONObject?,
) {
    val report = tab == 0
    val name = if (report) "demo-report.json" else "demo-logs.txt"
    val content = if (report) {
        JSONObject().apply {
            integrity?.let { put("integrity", it) }
            classic?.let { put("classic", it) }
            nativeR?.let { put("native", it) }
        }.toString(2)
    } else {
        buildString {
            fun sec(label: String, r: JSONObject?) {
                val log = r?.optJSONArray("log") ?: return
                append("===== ").append(label).append(" =====\n")
                for (i in 0 until log.length()) append(log.optString(i)).append('\n')
                append('\n')
            }
            sec("main-process integrity", integrity)
            sec("classic isolated", classic)
            sec("native zygote_next", nativeR)
        }
    }
    try {
        val file = java.io.File(context.cacheDir, name).apply { writeText(content) }
        val uri = androidx.core.content.FileProvider.getUriForFile(
            context, "${context.packageName}.fileprovider", file,
        )
        val send = Intent(Intent.ACTION_SEND).apply {
            type = if (report) "application/json" else "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(send, if (report) "Export report" else "Export logs"))
    } catch (e: Exception) {
        android.widget.Toast.makeText(context, "Export failed: ${e.message}", android.widget.Toast.LENGTH_LONG).show()
    }
}

private fun LazyListScope.logSection(r: JSONObject?, label: String, expanded: Boolean, onToggle: () -> Unit) {
    if (r == null) return
    item { SectionHeader(label, expanded, onToggle, null) }
    if (!expanded) return
    val log = r.optJSONArray("log").toStringList()
    item {
        StageCard {
            if (log.isEmpty()) {
                LabelRow("No progress log (see adb logcat -s DemoProbe).")
            } else {
                MonoBlock(log)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------
@Composable
private fun StageCard(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            content()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ExpandableCard(
    title: String,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth().animateContentSize(),
        onClick = { expanded = !expanded },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f),
                    maxLines = if (expanded) Int.MAX_VALUE else 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    if (expanded) "▾" else "▸",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (expanded) content()
        }
    }
}

@Composable
private fun SectionHeader(label: String, expanded: Boolean, onToggle: () -> Unit, detected: Boolean?) {
    Row(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable { onToggle() }
            .padding(vertical = 10.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            if (expanded) "▾" else "▸",
            fontSize = 15.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(24.dp),
        )
        Text(
            label.uppercase(),
            fontWeight = FontWeight.Bold,
            fontSize = 15.sp,
            color = MaterialTheme.colorScheme.onSurface,
        )
        if (detected != null) {
            Spacer(Modifier.weight(1f))
            Box(
                Modifier.width(10.dp).height(10.dp).clip(RoundedCornerShape(5.dp))
                    .background(if (detected) MaterialTheme.colorScheme.error else Good),
            )
        }
    }
}

@Composable
private fun CardTitle(text: String, topPad: Boolean = false) {
    Text(
        text.uppercase(),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        fontWeight = FontWeight.Bold,
        fontSize = 12.sp,
        letterSpacing = 0.6.sp,
        modifier = Modifier.padding(top = if (topPad) 6.dp else 0.dp, bottom = 2.dp),
    )
}

@Composable
private fun SubLabel(text: String) {
    Text(
        text,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        fontSize = 12.sp,
        modifier = Modifier.padding(top = 4.dp, bottom = 0.dp),
    )
}

@Composable
private fun LabelRow(text: String) {
    Text(
        text,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun BulletRow(text: String, color: Color = MaterialTheme.colorScheme.onSurface) {
    Row(Modifier.fillMaxWidth().padding(start = 2.dp, top = 2.dp)) {
        Text("•  ", color = color.copy(alpha = 0.7f))
        Text(text, color = color, style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * Dense scalar key/value grid: two pairs per row on the available width, the label
 * content-sized (wrapping only past a cap, never truncating) so the value sits right
 * after it instead of across a fixed dead gap.
 */
@Composable
private fun KvGrid(items: List<Pair<String, String>>) {
    if (items.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        items.chunked(2).forEach { pair ->
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                pair.forEach { (k, v) -> KvInline(k, v, Modifier.weight(1f)) }
                if (pair.size == 1) Spacer(Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun KvInline(key: String, value: String, modifier: Modifier) {
    Row(modifier, verticalAlignment = Alignment.Top) {
        Text(
            key,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 12.sp,
            modifier = Modifier.widthIn(max = 150.dp).padding(end = 8.dp),
        )
        Text(
            value,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium,
            fontSize = 12.sp,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.Cell(
    text: String,
    weight: Float,
    header: Boolean = false,
    mono: Boolean = false,
    color: Color = if (header) MaterialTheme.colorScheme.onSurfaceVariant
    else MaterialTheme.colorScheme.onSurface,
) {
    Text(
        text,
        modifier = Modifier.weight(weight).padding(end = 6.dp),
        color = color,
        fontSize = if (mono) 11.sp else 12.sp,
        fontWeight = if (header) FontWeight.SemiBold else FontWeight.Normal,
        fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

/**
 * Renders a header + rows into fixed-width monospace lines with a separator
 * rule, so columns align exactly and nothing truncates. Each column is padded
 * to the widest cell in it; the caller wraps the result in [MonoBlock] so the
 * whole table scrolls horizontally as one unit.
 */
private fun monoTable(header: List<String>, rows: List<List<String>>): List<String> {
    val cols = header.size
    val widths = IntArray(cols) { header[it].length }
    for (row in rows) {
        for (c in 0 until cols) {
            val v = row.getOrNull(c).orEmpty()
            if (v.length > widths[c]) widths[c] = v.length
        }
    }
    fun fmt(cells: List<String>): String {
        val sb = StringBuilder()
        for (c in 0 until cols) {
            if (c > 0) sb.append("  ")
            sb.append(cells.getOrNull(c).orEmpty().padEnd(widths[c]))
        }
        return sb.toString().trimEnd()
    }
    val out = ArrayList<String>(rows.size + 2)
    out.add(fmt(header))
    out.add(widths.joinToString("  ") { "-".repeat(it) })
    for (row in rows) out.add(fmt(row))
    return out
}

/**
 * Monospace raw lines inside a horizontally-scrollable surface. Tap toggles soft
 * wrap so a long mount/diff line can be read without pushing every other line's
 * left edge off-screen. The block always fills width and scrolls inside its own
 * card, so the page body never scrolls horizontally.
 */
@Composable
private fun MonoBlock(lines: List<String>) {
    if (lines.isEmpty()) return
    var wrap by remember { mutableStateOf(false) }
    val scroll = rememberScrollState()
    var box = Modifier
        .fillMaxWidth()
        .padding(vertical = 4.dp)
        .background(
            MaterialTheme.colorScheme.surfaceContainerHighest,
            RoundedCornerShape(6.dp),
        )
        .clickable { wrap = !wrap }
    box = if (wrap) box else box.horizontalScroll(scroll)
    Box(box.padding(horizontal = 10.dp, vertical = 6.dp)) {
        Text(
            lines.joinToString("\n"),
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            lineHeight = 15.sp,
            color = MaterialTheme.colorScheme.onSurface,
            softWrap = wrap,
        )
    }
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------
private fun JSONArray?.toStringList(): List<String> {
    if (this == null) return emptyList()
    val out = ArrayList<String>(length())
    for (i in 0 until length()) out.add(optString(i))
    return out
}
