"use strict";
/**
 * DexShell v29.0 — Confirmed Minimal Bypass
 * All method names verified via discovery run (frida_v29_discovery_run1.txt, 2026-06-03)
 *
 * Usage:
 *   frida -H 127.0.0.1:14725 -f com.x.dexprotectx -l bypass_v29_minimal.js
 *
 * What this bypasses:
 *   K.ᛴᲆᛶ ()Z                          → return true  (security check, was K.s in v26)
 *   K.ᛴᲆᛷ (String)Z                    → return true  (security check, was K.b in v26)
 *   InstrumentationHijacker.ᛱ᛽᛽ᲅ ()V → no-op    (install method, called from Application.onCreate)
 *   InstrumentationHijacker boolean checks             → return false (ᛱᛱᛱ, ᛱᛱᛲ, ᛱᛱᛳ, ᛱᛱᛶ)
 *   InstrumentationHijacker.isInstalled()             → return false
 *   InstrumentationHijacker.ᛱ᛼᲋ᲊ (Object,Instrumentation)V → no-op (Instrumentation injector)
 *   UpdateActivity launch                             → blocked
 *   dexshell_hook Intent extra                        → forced false
 *   /proc/self/maps Frida filter                      → active
 *   GOT crash trap exception handler                  → active
 *   dl_iterate_phdr Frida ELF filter                 → active
 */

// ── 1. /proc hide ────────────────────────────────────────────────────────────
(function() {
    var libc = Process.getModuleByName("libc.so");
    var fds  = {};
    Interceptor.attach(libc.getExportByName("open"), {
        onEnter: function(a) { this.path = a[0].readUtf8String(); },
        onLeave: function(r) {
            if (this.path === "/proc/self/maps" || this.path === "/proc/self/status")
                fds[r.toInt32()] = this.path;
        }
    });
    Interceptor.attach(libc.getExportByName("read"), {
        onEnter: function(a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
        onLeave: function(r) {
            var n = r.toInt32(); if (n <= 0) return;
            var p = fds[this.fd]; if (!p) return;
            var c = this.buf.readUtf8String(n);
            if (p === "/proc/self/maps") {
                var f = c.split("\n").filter(function(l){ return l.toLowerCase().indexOf("frida") === -1; }).join("\n");
                this.buf.writeUtf8String(f); r.replace(ptr(f.length));
            } else {
                this.buf.writeUtf8String(c.replace(/TracerPid:\s*\d+/, "TracerPid:\t0"));
            }
        }
    });
    Interceptor.attach(libc.getExportByName("close"), { onEnter: function(a){ delete fds[a[0].toInt32()]; }});
    console.log("[+] /proc hide active");
})();

// ── 2. GOT crash trap exception handler ──────────────────────────────────────
Process.setExceptionHandler(function(d) {
    if (d.type === "access-violation" || d.type === "illegal-instruction") return true;
    return false;
});
console.log("[+] Exception handler active");

// ── 3. dl_iterate_phdr — hide Frida ELFs from ByteHook ───────────────────────
(function() {
    var libc = Process.getModuleByName("libc.so");
    var fn   = libc.findExportByName("dl_iterate_phdr");
    if (!fn) return;
    var HIDE = ["frida", "gadget", "agent"];
    Interceptor.attach(fn, {
        onEnter: function(args) {
            var orig = args[0];
            if (orig.isNull()) return;
            args[0] = new NativeCallback(function(info, size, data) {
                var namePtr = info.readPointer();
                if (!namePtr.isNull()) {
                    try {
                        var name = namePtr.readUtf8String().toLowerCase();
                        for (var i = 0; i < HIDE.length; i++)
                            if (name.indexOf(HIDE[i]) !== -1) return 0;
                    } catch(e) {}
                }
                return orig(info, size, data);
            }, "int", ["pointer", "size_t", "pointer"]);
        }
    });
    console.log("[+] dl_iterate_phdr filter active");
})();

// ── 4. Java-layer hooks ───────────────────────────────────────────────────────
Java.perform(function() {

    // ── K class security checks (confirmed via discovery run) ──
    var kTimer = setInterval(function() {
        try {
            var K = Java.use("com.dexshell.x.shell.K");

            // ᛴᲆᛶ ()boolean  — security check (was K.s in v26)
            K["ᛴᲆᛶ"].implementation = function() {
                return true;
            };

            // ᛴᲆᛷ (String)boolean — security check (was K.b in v26)
            K["ᛴᲆᛷ"].overload("java.lang.String")
                .implementation = function(_s) { return true; };

            console.log("[+] K security checks bypassed (ᛴᲆᛶ, ᛴᲆᛷ)");
            clearInterval(kTimer);
        } catch(e) {}
    }, 100);

    // ── InstrumentationHijacker bypass ──
    var ihTimer = setInterval(function() {
        try {
            var IH = Java.use("com.dexshell.x.InstrumentationHijacker");

            // Install method called from Application.onCreate — no-op it
            // ᛱ᛽᛽ᲅ ()V
            IH["ᛱ᛽᛽ᲅ"].implementation = function() {};

            // Instrumentation injector — no-op so ProxyInstrumentation is never swapped in
            // ᛱ᛼᲋ᲊ (Object, android.app.Instrumentation)V
            IH["ᛱ᛼᲋ᲊ"].overload("java.lang.Object","android.app.Instrumentation")
                .implementation = function(_a, _b) {};

            // isInstalled() — return false so install path is skipped
            IH["isInstalled"].implementation = function() { return false; };

            // Boolean detection methods — return false
            ["ᛱᛱᛱ", "ᛱᛱᛲ", "ᛱᛱᛳ"].forEach(function(m) {
                try { IH[m].implementation = function() { return false; }; } catch(e) {}
            });

            // ᛱᛱᛶ (String)boolean
            try {
                IH["ᛱᛱᛶ"].overload("java.lang.String")
                    .implementation = function(_s) { return false; };
            } catch(e) {}

            // ᛱᛱᛸ (Context, String, String)boolean
            try {
                IH["ᛱᛱᛸ"]
                    .overload("android.content.Context","java.lang.String","java.lang.String")
                    .implementation = function(_c,_a,_b) { return false; };
            } catch(e) {}

            console.log("[+] InstrumentationHijacker bypassed");
            clearInterval(ihTimer);
        } catch(e) {}
    }, 100);

    // ── UpdateActivity block (v29 class name confirmed from AndroidManifest) ──
    try {
        var Instr = Java.use("android.app.Instrumentation");
        Instr.execStartActivity.overload(
            "android.content.Context","android.os.IBinder","android.os.IBinder",
            "android.app.Activity","android.content.Intent","int","android.os.Bundle"
        ).implementation = function(ctx,b1,b2,act,intent,i,bundle) {
            var comp = intent.getComponent();
            if (comp !== null) {
                var cls = comp.getClassName();
                if (cls === "com.x.dexprotectx.dex_baAEHvRjJcRMuRYW9H8") {
                    console.log("[BLOCKED] UpdateActivity: " + cls);
                    return null;
                }
            }
            return this.execStartActivity(ctx,b1,b2,act,intent,i,bundle);
        };
        console.log("[+] UpdateActivity block active");
    } catch(e) { console.log("[!] execStartActivity hook: " + e); }

    // ── dexshell_hook Intent extra — force false ──
    try {
        var Intent = Java.use("android.content.Intent");
        Intent.getBooleanExtra.implementation = function(name, def) {
            if (name === "dexshell_hook") return false;
            return this.getBooleanExtra(name, def);
        };
        console.log("[+] dexshell_hook extra forced false");
    } catch(e) {}
});

console.log("[*] DexShell v29.0 minimal bypass loaded");
