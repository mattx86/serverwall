use axum::{extract::{Path, State}, Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// GET /api/certs - list loaded certificates
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.load();
    let mut certs = Vec::new();

    for frontend in &config.frontend {
        if let Some(ref cert_path) = frontend.tls_cert {
            certs.push(json!({
                "frontend": frontend.name,
                "cert_path": cert_path.display().to_string(),
                "key_path": frontend.tls_key.as_ref().map(|p| p.display().to_string()),
                "tls_min_version": frontend.tls_min_version,
            }));
        } else if let Some(ref pfx_path) = frontend.tls_pfx {
            certs.push(json!({
                "frontend": frontend.name,
                "pfx_path": pfx_path.display().to_string(),
                "tls_min_version": frontend.tls_min_version,
            }));
        }
    }

    Json(json!({"certificates": certs}))
}

/// GET /api/certs/:id
pub async fn get(Path(_id): Path<String>) -> Json<Value> {
    Json(json!({"error": "use GET /api/certs to list all certificates"}))
}

/// POST /api/certs/import - upload PEM/PFX certificate
pub async fn create() -> Json<Value> {
    // Certificate import would require multipart upload handling.
    // For now, certificates are managed via the filesystem.
    Json(json!({"error": "certificate import via API is not yet implemented; place files in cert_dir and reload"}))
}

/// DELETE /api/certs/:id
pub async fn delete(Path(_id): Path<String>) -> Json<Value> {
    Json(json!({"error": "certificate deletion via API is not supported; manage files directly"}))
}
