use askama::Template;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexPage;

#[derive(Template)]
#[template(path = "frontends.html")]
pub struct FrontendsPage;

#[derive(Template)]
#[template(path = "frontends-edit.html")]
pub struct FrontendsEditPage;

#[derive(Template)]
#[template(path = "backends.html")]
pub struct BackendsPage;

#[derive(Template)]
#[template(path = "backends-edit.html")]
pub struct BackendsEditPage;

#[derive(Template)]
#[template(path = "certificates.html")]
pub struct CertificatesPage;

#[derive(Template)]
#[template(path = "certificates-view.html")]
pub struct CertificatesViewPage;

#[derive(Template)]
#[template(path = "certificates-import.html")]
pub struct CertificatesImportPage;

#[derive(Template)]
#[template(path = "certificates-generate.html")]
pub struct CertificatesGeneratePage;

#[derive(Template)]
#[template(path = "certificates-acme.html")]
pub struct CertificatesAcmePage;

#[derive(Template)]
#[template(path = "waf.html")]
pub struct WafPage;

#[derive(Template)]
#[template(path = "security.html")]
pub struct SecurityPage;

#[derive(Template)]
#[template(path = "security-profiles.html")]
pub struct SecurityProfilesPage;

#[derive(Template)]
#[template(path = "acl.html")]
pub struct AclPage;

#[derive(Template)]
#[template(path = "tls-profiles.html")]
pub struct TlsProfilesPage;

#[derive(Template)]
#[template(path = "log-profiles.html")]
pub struct LogProfilesPage;

#[derive(Template)]
#[template(path = "relay.html")]
pub struct RelayPage;

#[derive(Template)]
#[template(path = "dkim.html")]
pub struct DkimPage;

#[derive(Template)]
#[template(path = "dmarc.html")]
pub struct DmarcPage;

#[derive(Template)]
#[template(path = "spf.html")]
pub struct SpfPage;

#[derive(Template)]
#[template(path = "global-settings.html")]
pub struct GlobalSettingsPage;

#[derive(Template)]
#[template(path = "acme-settings.html")]
pub struct AcmeSettingsPage;

#[derive(Template)]
#[template(path = "logs.html")]
pub struct LogsPage;

#[derive(Template)]
#[template(path = "queue.html")]
pub struct QueuePage;

#[derive(Template)]
#[template(path = "antispam.html")]
pub struct AntispamPage;

/// Render a named HTML page by filename. Returns `None` for unknown paths.
pub fn render_page(path: &str) -> Option<String> {
    match path {
        "login.html"                 => LoginPage.render().ok(),
        "index.html"                 => IndexPage.render().ok(),
        "frontends.html"             => FrontendsPage.render().ok(),
        "frontends-edit.html"        => FrontendsEditPage.render().ok(),
        "backends.html"              => BackendsPage.render().ok(),
        "backends-edit.html"         => BackendsEditPage.render().ok(),
        "certificates.html"          => CertificatesPage.render().ok(),
        "certificates-view.html"     => CertificatesViewPage.render().ok(),
        "certificates-import.html"   => CertificatesImportPage.render().ok(),
        "certificates-generate.html" => CertificatesGeneratePage.render().ok(),
        "certificates-acme.html"     => CertificatesAcmePage.render().ok(),
        "waf.html"                   => WafPage.render().ok(),
        "security.html"              => SecurityPage.render().ok(),
        "security-profiles.html"     => SecurityProfilesPage.render().ok(),
        "acl.html"                   => AclPage.render().ok(),
        "tls-profiles.html"          => TlsProfilesPage.render().ok(),
        "log-profiles.html"          => LogProfilesPage.render().ok(),
        "relay.html"                 => RelayPage.render().ok(),
        "dkim.html"                  => DkimPage.render().ok(),
        "dmarc.html"                 => DmarcPage.render().ok(),
        "spf.html"                   => SpfPage.render().ok(),
        "global-settings.html"       => GlobalSettingsPage.render().ok(),
        "acme-settings.html"         => AcmeSettingsPage.render().ok(),
        "logs.html"                  => LogsPage.render().ok(),
        "queue.html"                 => QueuePage.render().ok(),
        "antispam.html"              => AntispamPage.render().ok(),
        _                            => None,
    }
}
