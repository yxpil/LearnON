//! TLS 端点装配：多证书 SNI 解析 + ALPN + 协议版本控制。
//!
//! 一个监听端口上可以挂多张证书（来自多个 server 块），握手时按 ClientHello 的
//! server_name 选择：精确名 > `*.example.com` 通配 > 默认证书（第一个）。
//! 对应 nginx 的 `listen 443 ssl` + 多 server 块 + SNI 语义。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SupportedProtocolVersion};

/// 一对证书（服务于某个 server_name 集合）
#[derive(Debug, Clone)]
pub struct CertSpec {
    pub names: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub specs: Vec<CertSpec>,
    /// ALPN 是否协商 h2
    pub http2: bool,
    pub min_version: TlsVersion,
}

#[derive(Debug)]
pub struct SniResolver {
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// `*.example.com` 存成后缀 `.example.com`
    wildcard: Vec<(String, Arc<CertifiedKey>)>,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.choose(client_hello.server_name())
    }
}

impl SniResolver {
    /// SNI -> 证书。没有 SNI（HTTPS 直连 IP、或 TLS1.3 的 ECH/无扩展客户端）时，
    /// 和 nginx 一样退回 default server 的证书，而不是掐断握手：
    /// 证书选择失败只会让客户端看到一个没有状态码的握手错误，比 404 难查得多。
    pub fn choose(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = server_name else {
            return Some(Arc::clone(&self.default));
        };
        let sni = name.to_ascii_lowercase();
        if let Some(k) = self.exact.get(&sni) {
            return Some(Arc::clone(k));
        }
        // 通配只匹配子域：`*.example.com` 命中 api.example.com，不命中 example.com
        for (suffix, key) in &self.wildcard {
            if sni.ends_with(suffix.as_str()) && sni.len() > suffix.len() {
                return Some(Arc::clone(key));
            }
        }
        Some(Arc::clone(&self.default))
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("打开证书 {} 失败: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(f);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("解析证书 {} 失败: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} 里没有 PEM 证书", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("打开私钥 {} 失败: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("解析私钥 {} 失败: {e}", path.display()))?
        .ok_or_else(|| format!("{} 中未找到私钥", path.display()))
}

pub fn build_resolver(specs: &[CertSpec]) -> Result<SniResolver, String> {
    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcard: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for spec in specs {
        let certs = load_certs(&spec.cert)?;
        let key_der = load_key(&spec.key)?;
        let key = any_supported_type(&key_der)
            .map_err(|e| format!("私钥 {} 不被支持的签名算法: {e}", spec.key.display()))?;
        // 校验私钥与证书公钥匹配（rustls 在 CertifiedKey 使用时才报，这里提前失败）
        let ck = Arc::new(CertifiedKey::new(certs, key));
        if default.is_none() {
            default = Some(Arc::clone(&ck));
        }
        for name in &spec.names {
            let n = name.trim().to_ascii_lowercase();
            if n.is_empty() {
                continue;
            }
            match n.strip_prefix('*') {
                Some(suffix) => wildcard.push((suffix.to_string(), Arc::clone(&ck))),
                None => {
                    exact.insert(n, Arc::clone(&ck));
                }
            }
        }
    }
    let default = default.ok_or("TLS 监听端口没有配置任何证书")?;
    Ok(SniResolver {
        exact,
        wildcard,
        default,
    })
}

pub fn build_server_config(opts: &TlsOptions) -> Result<ServerConfig, String> {
    let resolver = Arc::new(build_resolver(&opts.specs)?);
    let versions: Vec<&'static SupportedProtocolVersion> = match opts.min_version {
        TlsVersion::Tls13 => vec![&rustls::version::TLS13],
        TlsVersion::Tls12 => vec![&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let mut config = ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = if opts.http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(config)
}

/// 供 `-t` 配置校验使用：只解析证书与私钥，不装 acceptor
pub fn validate(specs: &[CertSpec]) -> Result<Vec<String>, String> {
    let r = build_resolver(specs)?;
    let mut out: Vec<String> = r.exact.keys().cloned().collect();
    out.extend(r.wildcard.iter().map(|(s, _)| format!("*{s}")));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(dir: &Path, names: &[&str]) -> (PathBuf, PathBuf) {
        let cert =
            rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("rcgen 生成证书");
        let cp = dir.join(format!("{}-cert.pem", names[0].replace('*', "wild")));
        let kp = dir.join(format!("{}-key.pem", names[0].replace('*', "wild")));
        std::fs::write(&cp, cert.cert.pem()).unwrap();
        std::fs::write(&kp, cert.key_pair.serialize_pem()).unwrap();
        (cp, kp)
    }

    #[test]
    fn builds_config_from_two_certs_and_prefers_exact_then_wildcard() {
        let dir = std::env::temp_dir().join(format!("learnon-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c1, k1) = write_pair(&dir, &["*.example.com", "example.com"]);
        let (c2, k2) = write_pair(&dir, &["api.other.com"]);

        let resolver = build_resolver(&[
            CertSpec {
                names: vec!["*.example.com".into(), "example.com".into()],
                cert: c1,
                key: k1,
            },
            CertSpec {
                names: vec!["api.other.com".into()],
                cert: c2,
                key: k2,
            },
        ])
        .unwrap();

        assert!(resolver.exact.contains_key("example.com"));
        assert!(resolver.exact.contains_key("api.other.com"));
        assert_eq!(resolver.wildcard.len(), 1);
        assert_eq!(resolver.wildcard[0].0, ".example.com");
        // 默认证书 = 第一个 spec
        assert!(Arc::ptr_eq(
            &resolver.choose(None).unwrap(),
            &resolver.choose(Some("example.com")).unwrap()
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chooses_cert_by_sni_with_default_fallback() {
        let dir = std::env::temp_dir().join(format!("learnon-certs-sni-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c1, k1) = write_pair(&dir, &["example.com"]);
        let (c2, k2) = write_pair(&dir, &["*.spec.io"]);
        let resolver = build_resolver(&[
            CertSpec {
                names: vec!["example.com".into()],
                cert: c1,
                key: k1,
            },
            CertSpec {
                names: vec!["*.spec.io".into()],
                cert: c2,
                key: k2,
            },
        ])
        .unwrap();
        let default = resolver.choose(Some("example.com")).unwrap();
        let wildcard_cert = resolver.choose(Some("a.spec.io")).unwrap();
        // 通配命中子域，且不是默认证书
        assert!(!Arc::ptr_eq(&default, &wildcard_cert));
        assert!(Arc::ptr_eq(
            &wildcard_cert,
            &resolver.choose(Some("API.SPEC.IO")).unwrap()
        ));
        // 通配不覆盖主域本身：spec.io 回落默认
        assert!(Arc::ptr_eq(&default, &resolver.choose(Some("spec.io")).unwrap()));
        // 无 SNI / 未知 SNI 都用默认证书，而不是让握手失败
        assert!(Arc::ptr_eq(&default, &resolver.choose(None).unwrap()));
        assert!(Arc::ptr_eq(&default, &resolver.choose(Some("nope.net")).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_missing_cert_file() {
        let err = build_resolver(&[CertSpec {
            names: vec!["x.com".into()],
            cert: PathBuf::from("/nope/not-here.pem"),
            key: PathBuf::from("/nope/not-here-key.pem"),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn server_config_sets_alpn_by_http2_flag() {
        let dir = std::env::temp_dir().join(format!("learnon-certs-alpn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = write_pair(&dir, &["localhost"]);
        let spec = CertSpec {
            names: vec!["localhost".into()],
            cert: c,
            key: k,
        };
        let h2 = build_server_config(&TlsOptions {
            specs: vec![spec.clone()],
            http2: true,
            min_version: TlsVersion::Tls12,
        })
        .unwrap();
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        let h1 = build_server_config(&TlsOptions {
            specs: vec![spec],
            http2: false,
            min_version: TlsVersion::Tls13,
        })
        .unwrap();
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
