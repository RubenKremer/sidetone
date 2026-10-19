// Builds the reference C codecs bundled in native/: Speex (Xiph, BSD) and
// iLBC (WebRTC, BSD). Both are plain C; the file lists come from their
// upstream build files.

use std::path::Path;

fn sources(dir: &str) -> Vec<String> {
    std::fs::read_to_string(Path::new(dir).join("sources.txt"))
        .expect("sources.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

fn main() {
    println!("cargo:rerun-if-changed=native");
    let target = std::env::var("TARGET").unwrap_or_default();

    let mut speex = cc::Build::new();
    speex
        .include("native/speex/include")
        .define("FLOATING_POINT", None)
        .define("EXPORT", Some(""))
        .define("USE_SMALLFT", None)
        .warnings(false);
    // Scratch memory on the C stack (VLAs, or alloca on MSVC) instead of the
    // fixed manual stack inside each state, which can overflow.
    if target.contains("msvc") {
        speex.define("USE_ALLOCA", None);
    } else {
        speex.define("VAR_ARRAYS", None);
    }
    for f in sources("native/speex") {
        speex.file(format!("native/speex/libspeex/{f}"));
    }
    speex.compile("sidetone_speex");

    let mut ilbc = cc::Build::new();
    ilbc.include("native/ilbc").warnings(false);
    if target.contains("windows") {
        ilbc.define("WEBRTC_WIN", None)
            .define("_CRT_SECURE_NO_WARNINGS", None);
    } else {
        ilbc.define("WEBRTC_POSIX", None);
        if target.contains("apple") {
            ilbc.define("WEBRTC_MAC", None);
        } else {
            ilbc.define("WEBRTC_LINUX", None);
        }
    }
    if target.contains("aarch64") {
        ilbc.define("WEBRTC_ARCH_ARM64", None);
    }
    for f in sources("native/ilbc") {
        ilbc.file(format!("native/ilbc/{f}"));
    }
    ilbc.file("native/ilbc/shim.c");
    ilbc.compile("sidetone_ilbc");
}
