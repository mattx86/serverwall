use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use lol_html::{ElementContentHandlers, HtmlRewriter, Settings};

use crate::pipeline::{MessageContext, PostDataCheck};
use crate::result::CheckOutcome;
use crate::score::{CheckCategory, ScoreContribution};

/// Analyzes HTML content for obfuscation, hidden text, and spam patterns.
pub struct HtmlAnalysisCheck {
    pub weight: f64,
}

impl HtmlAnalysisCheck {
    pub fn new(weight: f64) -> Self {
        Self { weight }
    }
}

#[async_trait]
impl PostDataCheck for HtmlAnalysisCheck {
    fn name(&self) -> &str {
        "html"
    }

    async fn check(&self, ctx: &MessageContext) -> (CheckOutcome, Vec<ScoreContribution>) {
        let body_text = String::from_utf8_lossy(&ctx.raw_message);

        // Only analyse if there is HTML content.
        if !body_text.contains("<html") && !body_text.contains("<HTML") && !body_text.contains("text/html") {
            return (
                CheckOutcome::Skip {
                    reason: "No HTML content".to_string(),
                },
                Vec::new(),
            );
        }

        let html_part = extract_html_part(&body_text);
        if html_part.is_empty() {
            return (CheckOutcome::Pass, Vec::new());
        }

        let hidden_text_count = Arc::new(AtomicUsize::new(0));
        let img_count = Arc::new(AtomicUsize::new(0));
        let form_count = Arc::new(AtomicUsize::new(0));

        let hidden_clone = hidden_text_count.clone();
        let img_clone = img_count.clone();
        let form_clone = form_count.clone();

        let mut output = Vec::new();
        {
            let mut rewriter = HtmlRewriter::new(
                Settings {
                    element_content_handlers: vec![
                        (
                            Cow::Owned("*[style]".parse().unwrap()),
                            ElementContentHandlers::default().element(move |el| {
                                if let Some(style) = el.get_attribute("style") {
                                    let style_lower = style.to_lowercase();
                                    if style_lower.contains("display:none")
                                        || style_lower.contains("display: none")
                                        || style_lower.contains("visibility:hidden")
                                        || style_lower.contains("visibility: hidden")
                                        || style_lower.contains("font-size:0")
                                        || style_lower.contains("font-size: 0")
                                    {
                                        hidden_clone.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Ok(())
                            }),
                        ),
                        (
                            Cow::Owned("img".parse().unwrap()),
                            ElementContentHandlers::default().element(move |_el| {
                                img_clone.fetch_add(1, Ordering::Relaxed);
                                Ok(())
                            }),
                        ),
                        (
                            Cow::Owned("form".parse().unwrap()),
                            ElementContentHandlers::default().element(move |_el| {
                                form_clone.fetch_add(1, Ordering::Relaxed);
                                Ok(())
                            }),
                        ),
                    ],
                    ..Settings::default()
                },
                |c: &[u8]| output.extend_from_slice(c),
            );

            let _ = rewriter.write(html_part.as_bytes());
            let _ = rewriter.end();
        }

        let hidden = hidden_text_count.load(Ordering::Relaxed);
        let imgs = img_count.load(Ordering::Relaxed);
        let forms = form_count.load(Ordering::Relaxed);

        let mut contributions = Vec::new();
        let mut total_severity: f64 = 0.0;

        if hidden > 0 {
            let score = self.weight * 0.6;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "html/hidden_text".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("{} hidden elements", hidden),
            });
        }

        if imgs > 3 {
            let score = self.weight * 0.5;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "html/image_heavy".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("{} images in HTML email", imgs),
            });
        }

        if forms > 0 {
            let score = self.weight * 0.8;
            total_severity += score;
            contributions.push(ScoreContribution {
                check_name: "html/form".to_string(),
                category: CheckCategory::Content,
                score,
                description: format!("{} form element(s) in email", forms),
            });
        }

        if contributions.is_empty() {
            (CheckOutcome::Pass, contributions)
        } else {
            (
                CheckOutcome::Hit {
                    severity: total_severity,
                    detail: format!("{} HTML issues", contributions.len()),
                },
                contributions,
            )
        }
    }
}

/// Crude extraction of HTML content from a MIME message.
fn extract_html_part(raw: &str) -> String {
    if let Some(idx) = raw.to_lowercase().find("content-type: text/html") {
        let rest = &raw[idx..];
        if let Some(body_start) = rest.find("\r\n\r\n") {
            let body = &rest[body_start + 4..];
            if let Some(end) = body.find("\r\n--") {
                return body[..end].to_string();
            }
            return body.to_string();
        }
    }
    if raw.contains("<html") || raw.contains("<HTML") {
        return raw.to_string();
    }
    String::new()
}
