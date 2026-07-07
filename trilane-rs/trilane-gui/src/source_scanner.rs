use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceScanFact {
    pub lane: &'static str,
    pub category: &'static str,
    pub target: String,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub next: &'static str,
}

pub fn scanner_packet(objective: &str, lane: Option<&str>, max_items: usize) -> String {
    let Some(root) = source_root_from_objective(objective) else {
        return "SCANNER_PACKET% status=disabled reason=no-source-root".to_string();
    };
    let facts = scan_root(&root, lane, max_items);
    let mut lines = vec![format!(
        "SCANNER_PACKET% status=ok root={} facts={} mode=deterministic",
        marker_value(&root.to_string_lossy()),
        facts.len()
    )];
    for (idx, fact) in facts.iter().enumerate() {
        lines.push(format!(
            "SCANNER_FACT% id=SF-{idx:03} lane={} category={} target={} confidence={} title={} reason={} next=poc:{}",
            fact.lane,
            fact.category,
            marker_value(&fact.target),
            fact.confidence,
            fact.title,
            fact.reason,
            fact.next,
            idx = idx + 1,
        ));
    }
    lines.join("\n")
}

pub fn source_root_from_objective(objective: &str) -> Option<PathBuf> {
    objective
        .split_whitespace()
        .map(|token| {
            token.trim_matches(|ch: char| {
                matches!(
                    ch,
                    ',' | ';' | '.' | ':' | '"' | '\'' | '`' | '(' | ')' | '[' | ']'
                )
            })
        })
        .filter(|token| token.starts_with("~/") || token.starts_with('/'))
        .filter_map(expand_path)
        .find(|path| path.is_dir())
}

fn expand_path(token: &str) -> Option<PathBuf> {
    if let Some(rest) = token.strip_prefix("~/") {
        return std::env::var_os("HOME").map(|home| PathBuf::from(home).join(rest));
    }
    Some(PathBuf::from(token))
}

fn scan_root(root: &Path, lane: Option<&str>, max_items: usize) -> Vec<SourceScanFact> {
    let mut facts = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut files_seen = 0usize;
    while let Some(path) = stack.pop() {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    stack.push(entry.path());
                }
            }
            continue;
        }
        if !is_scannable_file(&path) || meta.len() > 1_500_000 {
            continue;
        }
        files_seen += 1;
        if files_seen > 2_500 || facts.len() >= max_items {
            break;
        }
        scan_file(root, &path, lane, max_items, &mut seen, &mut facts);
    }
    facts.truncate(max_items);
    facts
}

fn scan_file(
    root: &Path,
    path: &Path,
    lane: Option<&str>,
    max_items: usize,
    seen: &mut HashSet<String>,
    facts: &mut Vec<SourceScanFact>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    for (idx, line) in content.lines().enumerate() {
        if facts.len() >= max_items {
            return;
        }
        let line_no = idx + 1;
        let lower = line.to_ascii_lowercase();
        add_matches(&rel, line_no, &lower, lane, seen, facts);
    }
}

fn add_matches(
    rel: &str,
    line_no: usize,
    lower: &str,
    lane: Option<&str>,
    seen: &mut HashSet<String>,
    facts: &mut Vec<SourceScanFact>,
) {
    let target = format!("{rel}:{line_no}");
    let mut push = |fact: SourceScanFact| {
        if lane.is_some_and(|lane| lane != fact.lane && lane != "quick_hits_engine") {
            return;
        }
        let key = format!("{}:{}:{}", fact.lane, fact.title, fact.target);
        if seen.insert(key) {
            facts.push(fact);
        }
    };

    if contains_any(lower, &["sequelize.query", "select "])
        && contains_any(lower, &["req.", "${", "+", "where"])
    {
        push(fact(
            "injection_engine",
            "injection",
            target.clone(),
            "sql-injection-source-sink",
            "source->sink: request input near raw SQL",
            "login-or-search-sqli",
        ));
    }
    if contains_any(
        lower,
        &["$where", "nosql", "mongodb", "where: req", "body.where"],
    ) {
        push(fact(
            "injection_engine",
            "injection",
            target.clone(),
            "nosql-injection-source-sink",
            "source->sink: request-shaped NoSQL predicate",
            "nosql-injection",
        ));
    }
    if contains_any(
        lower,
        &["eval(", "safeeval", "notevil", "vm.run", "function("],
    ) {
        push(fact(
            "injection_engine",
            "injection",
            target.clone(),
            "unsafe-eval-sink",
            "source->sink: dynamic code execution sink",
            "unsafe-eval",
        ));
    }
    if contains_any(
        lower,
        &[
            "dangerouslysetinnerhtml",
            "innerhtml",
            "ng-bind-html",
            "v-html",
            "bypasssecuritytrusthtml",
            "jsonp",
            "res.render",
            "sanitizehtml",
        ],
    ) {
        push(fact(
            "injection_engine",
            "xss",
            target.clone(),
            "browser-render-sink",
            "source->sink: browser render/header sink",
            "xss-sink",
        ));
    }
    if contains_any(
        lower,
        &[
            "jwt",
            "expressjwt",
            "jsonwebtoken",
            "privatekey",
            "publickey",
            "begin rsa private key",
            "createhmac",
        ],
    ) {
        push(fact(
            "identity_engine",
            "session",
            target.clone(),
            "jwt-key-algorithm-surface",
            "source->sink: JWT/key/HMAC handling",
            "jwt-variant",
        ));
        push(fact(
            "config_engine",
            "crypto",
            target.clone(),
            "jwt-secret-material",
            "source->sink: key material or algorithm config",
            "jwt-key-or-algorithm",
        ));
    }
    if contains_any(lower, &["md5", "createhash('md5", "createhash(\"md5"]) {
        push(fact(
            "config_engine",
            "crypto",
            target.clone(),
            "weak-md5-hash",
            "source->sink: MD5 hash use",
            "password-md5-hash",
        ));
    }
    if contains_any(
        lower,
        &[
            "cookieparser",
            "cookie-parser",
            "express-session",
            "sessionsecret",
        ],
    ) {
        push(fact(
            "config_engine",
            "secrets_config",
            target.clone(),
            "cookie-session-secret",
            "source->sink: cookie/session secret config",
            "cookie-or-session-secret",
        ));
    }
    if contains_any(
        lower,
        &["basketid", "appenduserid", "isauthorized", "role", "admin"],
    ) {
        push(fact(
            "identity_engine",
            "authz",
            target.clone(),
            "object-or-role-boundary",
            "source->sink: object id or role boundary",
            "object-ownership-or-role",
        ));
    }
    if contains_any(
        lower,
        &[
            "captcha",
            "securityquestion",
            "security question",
            "whoami",
            "totp",
            "2fa",
        ],
    ) {
        push(fact(
            "logic_engine",
            "anti_automation_bypass",
            target.clone(),
            "recovery-or-captcha-leak",
            "source->sink: recovery/anti-automation data flow",
            "captcha-security-question-or-2fa",
        ));
    }
    if contains_any(
        lower,
        &[
            "coupon",
            "deluxe",
            "wallet",
            "order",
            "payment",
            "review",
            "feedback",
            "dataexport",
        ],
    ) {
        push(fact(
            "logic_engine",
            "state_invariant_abuse",
            target.clone(),
            "business-invariant-surface",
            "source->sink: business state transition",
            "business-invariant",
        ));
    }
    if contains_any(
        lower,
        &[
            "sendfile",
            "serveindex",
            "static(",
            "logfile",
            "ftp",
            "backup",
        ],
    ) {
        push(fact(
            "ingress_engine",
            "traversal_lfi",
            target.clone(),
            "file-or-directory-exposure",
            "source->sink: file/static exposure",
            "file-or-directory-exposure",
        ));
        push(fact(
            "config_engine",
            "observability_leak",
            target.clone(),
            "public-file-log-docs",
            "source->sink: public observability/config surface",
            "public-config-docs-logs",
        ));
    }
    if contains_any(
        lower,
        &[
            "errorhandler(",
            "err.stack",
            "/metrics",
            "swagger-ui",
            "openapi",
        ],
    ) {
        push(fact(
            "config_engine",
            "observability_leak",
            target.clone(),
            "debug-docs-metrics-surface",
            "source->sink: debug/docs/metrics exposure",
            "debug-docs-or-metrics",
        ));
    }
    if contains_any(
        lower,
        &[
            "../",
            "null byte",
            "poison",
            "path.resolve",
            "path.join",
            "unzip",
            "zip",
        ],
    ) {
        push(fact(
            "ingress_engine",
            "traversal_lfi",
            target.clone(),
            "path-traversal-or-archive",
            "source->sink: path/archive parser boundary",
            "path-traversal-or-zip",
        ));
    }
    if contains_any(
        lower,
        &["xml2js", "xmldom", "yaml.load", "js-yaml", "deserialize"],
    ) {
        push(fact(
            "ingress_engine",
            "file_upload_xxe",
            target.clone(),
            "parser-abuse-surface",
            "source->sink: XML/YAML/deserialization parser",
            "parser-abuse",
        ));
    }
    if contains_any(
        lower,
        &[
            "redirect",
            "isredirectallowed",
            "request(",
            "axios.",
            "fetch(",
        ],
    ) && lower.contains("req.")
    {
        push(fact(
            "ingress_engine",
            "ssrf_redirect",
            target,
            "ssrf-or-redirect-surface",
            "source->sink: request-controlled egress/redirect",
            "ssrf-or-redirect",
        ));
    }
}

fn fact(
    lane: &'static str,
    category: &'static str,
    target: String,
    title: &'static str,
    reason: &'static str,
    next: &'static str,
) -> SourceScanFact {
    SourceScanFact {
        lane,
        category,
        target,
        confidence: "medium",
        title,
        reason,
        next,
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            matches!(
                name,
                ".git" | "node_modules" | "target" | "dist" | "build" | ".next" | "coverage"
            )
        })
        .unwrap_or(false)
}

fn is_scannable_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    matches!(
        ext,
        "ts" | "tsx"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "json"
            | "yml"
            | "yaml"
            | "html"
            | "pug"
            | "hbs"
            | "rs"
            | "go"
            | "py"
            | "rb"
            | "php"
            | "java"
            | "env"
            | "md"
    )
}

fn marker_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join("_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_high_value_juice_shop_snippets() {
        let root =
            std::env::temp_dir().join(format!("trilane-scanner-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("routes")).unwrap();
        fs::write(
            root.join("routes/login.ts"),
            "sequelize.query(`SELECT * FROM Users WHERE email='${req.body.email}'`)\nconst privateKey = 'BEGIN RSA PRIVATE KEY'\n",
        )
        .unwrap();
        fs::write(
            root.join("routes/misc.ts"),
            "serveIndex('ftp')\ncreateHash('md5').update(password)\nres.redirect(req.query.to)\n",
        )
        .unwrap();
        fs::write(
            root.join("routes/app.ts"),
            "app.use(errorhandler())\napp.use('/api-docs', swaggerUi.serve)\ncookieParser('kekse')\n",
        )
        .unwrap();
        fs::write(
            root.join("routes/view.tsx"),
            "return <div dangerouslySetInnerHTML={{ __html: req.query.html }} />\n",
        )
        .unwrap();

        let facts = scan_root(&root, None, 30);
        let titles = facts.iter().map(|fact| fact.title).collect::<Vec<_>>();
        assert!(titles.contains(&"sql-injection-source-sink"));
        assert!(titles.contains(&"jwt-secret-material"));
        assert!(titles.contains(&"weak-md5-hash"));
        assert!(titles.contains(&"file-or-directory-exposure"));
        assert!(titles.contains(&"browser-render-sink"));
        assert!(titles.contains(&"cookie-session-secret"));
        assert!(titles.contains(&"debug-docs-metrics-surface"));

        let _ = fs::remove_dir_all(root);
    }
}
