use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct LogQuery {
    frontend: Option<String>,
    source: Option<String>,   // "daemon" | "webui"
}

/// GET /api/logs?frontend=NAME  or  ?source=daemon|webui
/// Stream log lines via Server-Sent Events.
pub async fn stream(
    State(state): State<AppState>,
    Query(params): Query<LogQuery>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let config = state.config.load();

    let log_path: Option<String> = if let Some(ref src) = params.source {
        let log_dir = config.global.log_dir.to_string_lossy().into_owned();
        match src.as_str() {
            "daemon" => Some(format!("{}/serverwall.log", log_dir)),
            "webui"  => Some(format!("{}/serverwall-webui.log", log_dir)),
            _ => None,
        }
    } else {
        params
            .frontend
            .as_deref()
            .and_then(|name| config.frontend.iter().find(|f| f.name == name))
            .and_then(|f| f.log_file.clone())
            .or_else(|| config.frontend.iter().find_map(|f| f.log_file.clone()))
    };

    drop(config);

    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Event, Infallible>>();

    tokio::spawn(async move {
        match log_path {
            Some(path) => tail_file(std::path::PathBuf::from(path), tx).await,
            None => {
                let ev = Event::default()
                    .data("{\"error\":\"no log file configured for this source\"}");
                let _ = tx.unbounded_send(Ok(ev));
            }
        }
    });

    Sse::new(rx).keep_alive(KeepAlive::default())
}

async fn tail_file(
    path: PathBuf,
    tx: futures::channel::mpsc::UnboundedSender<Result<Event, Infallible>>,
) {
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("{{\"error\":\"cannot open log file: {}\"}}", e);
            let _ = tx.unbounded_send(Ok(Event::default().data(msg)));
            return;
        }
    };

    // Seek to end so we only tail new lines.
    let _ = file.seek(std::io::SeekFrom::End(0)).await;

    let mut buf = Vec::new();

    loop {
        if tx.is_closed() {
            return;
        }

        let mut chunk = [0u8; 4096];
        match file.read(&mut chunk).await {
            Ok(0) => {
                // EOF — wait for more data to be written.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // Emit one event per complete line.
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line = String::from_utf8_lossy(&buf[..pos]).trim().to_string();
                    buf.drain(..=pos);
                    if !line.is_empty() {
                        if tx.unbounded_send(Ok(Event::default().data(line))).is_err() {
                            return; // client disconnected
                        }
                    }
                }
            }
            Err(e) => {
                let msg = format!("{{\"error\":\"log read error: {}\"}}", e);
                let _ = tx.unbounded_send(Ok(Event::default().data(msg)));
                return;
            }
        }
    }
}
