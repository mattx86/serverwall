use axum::{extract::State, http::StatusCode, Json};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::middleware::Claims;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub captcha_token: String,
    pub captcha_answer: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

/// Claims embedded in the CAPTCHA token (separate from auth JWT claims).
#[derive(Debug, Serialize, Deserialize)]
struct CaptchaClaims {
    /// Lowercase hex SHA-256 of the correct answer string.
    answer_hash: String,
    exp: usize,
}

/// GET /api/auth/captcha — generate a math CAPTCHA and return a signed token
/// plus a PNG image of the expression (never the expression text itself).
pub async fn captcha(State(state): State<AppState>) -> Json<Value> {
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    let b1 = u1.as_bytes();
    let b2 = u2.as_bytes();
    let a = (b1[0] % 15) + 1; // 1..=15
    let b = (b2[0] % 15) + 1; // 1..=15

    // Randomly choose + or −; for subtraction ensure non-negative result
    let subtract = b1[1] % 2 == 0;
    let (op1, op2, op_sym, answer): (u8, u8, char, u32) = if subtract {
        let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
        (hi, lo, '-', (hi - lo) as u32)
    } else {
        (a, b, '+', a as u32 + b as u32)
    };

    let answer_hash = sha256_hex(&answer.to_string());

    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(5))
        .unwrap()
        .timestamp() as usize;

    let claims = CaptchaClaims { answer_hash, exp };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .unwrap_or_default();

    // Seed image PRNG from UUID bytes; expression text is never sent to client.
    let seed = u64::from_le_bytes(b1[0..8].try_into().unwrap_or_default());
    let image = render_captcha_image(&format!("{} {} {}", op1, op_sym, op2), seed);

    Json(json!({ "token": token, "image": image }))
}

/// POST /api/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> (StatusCode, Json<Value>) {
    if !verify_captcha(&req.captcha_token, &req.captcha_answer, &state.jwt_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid captcha"})),
        );
    }

    match verify_web_user(&req.username, &req.password, &state) {
        Ok(true) => {
            let exp = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .unwrap()
                .timestamp() as usize;

            let claims = Claims { sub: req.username.clone(), exp };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
            )
            .unwrap_or_default();

            (StatusCode::OK, Json(json!({ "token": token, "username": req.username })))
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid username or password"})),
        ),
    }
}

/// POST /api/auth/logout
pub async fn logout() -> Json<Value> {
    Json(json!({"status": "logged_out"}))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn verify_captcha(token: &str, answer: &str, secret: &str) -> bool {
    if token.is_empty() || answer.is_empty() {
        return false;
    }
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let data = decode::<CaptchaClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    );
    match data {
        Ok(td) => sha256_hex(answer.trim()) == td.claims.answer_hash,
        Err(_) => false,
    }
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

fn verify_web_user(username: &str, password: &str, state: &AppState) -> anyhow::Result<bool> {
    let config = state.config.load();
    let content = std::fs::read_to_string(&config.webui.web_users_file)?;

    #[derive(serde::Deserialize)]
    struct UsersFile {
        #[serde(default)]
        user: Vec<UserEntry>,
    }
    #[derive(serde::Deserialize)]
    struct UserEntry {
        username: String,
        password_hash: String,
    }

    let users: UsersFile = toml::from_str(&content)?;
    use argon2::Argon2;
    use argon2::PasswordVerifier;
    use argon2::password_hash::PasswordHash;

    for user in &users.user {
        if user.username == username {
            if let Ok(ph) = PasswordHash::new(&user.password_hash) {
                if Argon2::default().verify_password(password.as_bytes(), &ph).is_ok() {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
    }
    Ok(false)
}

// ─── Anti-OCR CAPTCHA image rendering ────────────────────────────────────────

/// Minimal multiplicative LCG — seeded from UUID bytes, no extra crate.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Lcg(seed | 1) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    /// Random value in 0..n.
    fn rn(&mut self, n: u64) -> u64 { self.next() % n }
    /// Random value in -half..=half.
    fn rc(&mut self, half: i32) -> i32 {
        (self.next() % (2 * half as u64 + 1)) as i32 - half
    }
}

/// 5×7 pixel bitmaps for '0'–'9', '+', '-', ' '.
/// Each row is 5 bits, bit-4 = leftmost pixel.
const FONT: [[u8; 7]; 13] = [
    [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110], // 0
    [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110], // 1
    [0b01110, 0b10001, 0b00001, 0b00110, 0b01000, 0b10000, 0b11111], // 2
    [0b01110, 0b10001, 0b00001, 0b00110, 0b00001, 0b10001, 0b01110], // 3
    [0b10001, 0b10001, 0b11111, 0b00001, 0b00001, 0b00001, 0b00001], // 4
    [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110], // 5
    [0b01110, 0b10000, 0b11110, 0b10001, 0b10001, 0b10001, 0b01110], // 6
    [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000], // 7
    [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110], // 8
    [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110], // 9
    [0b00000, 0b00100, 0b00100, 0b11111, 0b00100, 0b00100, 0b00000], // +
    [0b00000, 0b00000, 0b00000, 0b11111, 0b00000, 0b00000, 0b00000], // -
    [0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000], // (space)
];

fn font_index(c: char) -> Option<usize> {
    match c {
        '0'..='9' => Some(c as usize - '0' as usize),
        '+' => Some(10),
        '-' => Some(11),
        ' ' => Some(12),
        _ => None,
    }
}

/// Render `expr` (e.g. "7 + 8") as an anti-OCR SVG data URL.
/// Anti-OCR measures: background noise rects, per-char Y-jitter, ink colour
/// variation, random extra ink dots, two crossing lines drawn over the text.
fn render_captcha_image(expr: &str, seed: u64) -> String {
    const W: i32 = 160;
    const H: i32 = 50;
    const SCALE: i32 = 3; // each logical pixel → 3×3 SVG rect
    const BG: i32 = 20;   // dark background (matches login-box theme)
    const FG: (i32, i32, i32) = (200, 220, 255); // near-white ink

    let mut rng = Lcg::new(seed);
    let mut svg = String::with_capacity(8192);

    svg.push_str(&format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}">"#));

    // Background
    svg.push_str(&format!(r#"<rect width="{W}" height="{H}" fill="rgb({BG},{BG},{BG})"/>"#));

    // 350 noise rects (1–4 px, gray ±25, slight colour tint)
    for _ in 0..350 {
        let nx = rng.rn(W as u64) as i32;
        let ny = rng.rn(H as u64) as i32;
        let sz = (rng.rn(4) + 1) as i32;
        let nv = (BG + rng.rc(25)).clamp(0, 255);
        let tr = (nv + rng.rc(12)).clamp(0, 255);
        let tg = (nv + rng.rc(12)).clamp(0, 255);
        let tb = (nv + rng.rc(18)).clamp(0, 255);
        svg.push_str(&format!(
            r#"<rect x="{nx}" y="{ny}" width="{sz}" height="{sz}" fill="rgb({tr},{tg},{tb})"/>"#
        ));
    }

    // 18 dim circles scattered across the image
    for _ in 0..18 {
        let cx = rng.rn(W as u64) as i32;
        let cy = rng.rn(H as u64) as i32;
        let cr = (rng.rn(5) + 2) as i32;
        let cv = (BG + rng.rc(35)).clamp(0, 255);
        let ca = (BG + rng.rc(35)).clamp(0, 255) + 20;
        svg.push_str(&format!(
            r#"<circle cx="{cx}" cy="{cy}" r="{cr}" fill="none" stroke="rgb({cv},{cv},{ca})" stroke-width="1"/>"#
        ));
    }

    // 5 random filled blobs (small rects 5–14 px, muted tones)
    for _ in 0..5 {
        let bx = rng.rn(W as u64) as i32;
        let by = rng.rn(H as u64) as i32;
        let bw = (rng.rn(10) + 5) as i32;
        let bh = (rng.rn(6) + 3) as i32;
        let bv = (BG + rng.rc(30)).clamp(0, 255);
        svg.push_str(&format!(
            r#"<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" fill="rgb({bv},{bv},{bv})" opacity="0.45"/>"#
        ));
    }

    // Layout: centre expression horizontally and vertically
    let chars: Vec<char> = expr.chars().collect();
    let n = chars.len() as i32;
    let cw = 5 * SCALE;
    let gap = 2 * SCALE;
    let total_w = n * cw + (n - 1).max(0) * gap;
    let x0 = (W - total_w) / 2;
    let y0 = (H - 7 * SCALE) / 2;

    // Render characters in two passes so overlays always appear on top of all glyphs.
    // Pass 1: character bitmaps only. Overlays are buffered in `overlays`.
    let mut overlays = String::with_capacity(2048);

    for (ci, &ch) in chars.iter().enumerate() {
        let fi = match font_index(ch) { Some(i) => i, None => continue };
        let bitmap = &FONT[fi];
        let cx = x0 + ci as i32 * (cw + gap);
        let cy = y0 + rng.rc(3);

        for row in 0..7i32 {
            for col in 0..5i32 {
                if (bitmap[row as usize] >> (4 - col)) & 1 == 0 { continue; }
                let px = cx + col * SCALE;
                let py = cy + row * SCALE;
                if px < 0 || py < 0 || px + SCALE > W || py + SCALE > H { continue; }
                let v = rng.rc(10);
                let r = (FG.0 + v).clamp(0, 255);
                let g = (FG.1 + v).clamp(0, 255);
                let b = (FG.2 + v).clamp(0, 255);
                svg.push_str(&format!(
                    r#"<rect x="{px}" y="{py}" width="{SCALE}" height="{SCALE}" fill="rgb({r},{g},{b})"/>"#
                ));
                // ~4% chance: extra 1×1 dot nearby
                if rng.rn(100) < 4 {
                    let ex = (px + rng.rc(3)).clamp(0, W - 1);
                    let ey = (py + rng.rc(3)).clamp(0, H - 1);
                    svg.push_str(&format!(
                        r#"<rect x="{ex}" y="{ey}" width="1" height="1" fill="rgb({},{},{})"/>"#,
                        FG.0, FG.1, FG.2
                    ));
                }
            }
        }

        // Buffer per-character overlays (scatter pixels + short strokes) for pass 2.
        let bh_u = (7 * SCALE) as u64;
        let bw_u = cw as u64;

        // 5–9 scatter pixels: mix of fg-tinted (fake ink) and bg-tinted (partial erasure)
        for _ in 0..(rng.rn(5) + 5) {
            let sx = (cx + rng.rn(bw_u) as i32).clamp(0, W - 1);
            let sy = (cy + rng.rn(bh_u) as i32).clamp(0, H - 1);
            let sz = (rng.rn(2) + 1) as i32;
            let (sr, sg, sb) = if rng.rn(2) == 0 {
                let v = rng.rc(25);
                ((FG.0 + v).clamp(0, 255), (FG.1 + v).clamp(0, 255), (FG.2 + v).clamp(0, 255))
            } else {
                let v = (BG + rng.rc(30)).clamp(0, 100);
                (v, v, v)
            };
            overlays.push_str(&format!(
                r#"<rect x="{sx}" y="{sy}" width="{sz}" height="{sz}" fill="rgb({sr},{sg},{sb})"/>"#
            ));
        }

        // 1–2 short strokes passing through the character
        for _ in 0..(rng.rn(2) + 1) {
            let lx0 = (cx - 4 + rng.rn(bw_u + 8) as i32).clamp(0, W - 1);
            let ly0 = (cy  + rng.rn(bh_u) as i32).clamp(0, H - 1);
            let lx1 = (lx0 + rng.rc(14)).clamp(0, W - 1);
            let ly1 = (ly0 + rng.rc(9)).clamp(0, H - 1);
            let lr = (70  + rng.rc(60)).clamp(0, 255);
            let lg = (90  + rng.rc(60)).clamp(0, 255);
            let lb = (150 + rng.rc(80)).clamp(0, 255);
            overlays.push_str(&format!(
                r#"<line x1="{lx0}" y1="{ly0}" x2="{lx1}" y2="{ly1}" stroke="rgb({lr},{lg},{lb})" stroke-width="2" opacity="0.75"/>"#
            ));
        }
    }

    // Pass 2: flush all per-character overlays on top of every glyph.
    svg.push_str(&overlays);

    // 6 crossing lines with varying width and colour
    for i in 0..6u64 {
        let lx0 = rng.rn(W as u64) as i32;
        let ly0 = rng.rn(H as u64) as i32;
        let lx1 = rng.rn(W as u64) as i32;
        let ly1 = rng.rn(H as u64) as i32;
        let sw = if i % 3 == 0 { "3" } else { "2" };
        let lr = (80  + rng.rc(40)).clamp(0, 255);
        let lg = (100 + rng.rc(40)).clamp(0, 255);
        let lb = (160 + rng.rc(50)).clamp(0, 255);
        svg.push_str(&format!(
            r#"<line x1="{lx0}" y1="{ly0}" x2="{lx1}" y2="{ly1}" stroke="rgb({lr},{lg},{lb})" stroke-width="{sw}"/>"#
        ));
    }

    svg.push_str("</svg>");
    format!("data:image/svg+xml;base64,{}", b64(svg.as_bytes()))
}

/// Standard Base64 encoder — no external crate.
fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((data.len() + 2) / 3 * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[((n >> 18) & 63) as usize] as char);
        s.push(T[((n >> 12) & 63) as usize] as char);
        s.push(if c.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        s.push(if c.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    s
}
