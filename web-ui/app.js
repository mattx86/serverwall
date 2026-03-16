/* ServerWall shared helpers */

// ── Auth ──────────────────────────────────────────────────────────────────────
function getCookie(n){var m=document.cookie.match(new RegExp('(^| )'+n+'=([^;]+)'));return m?m[2]:null}
function authHeaders(){var t=getCookie('lg_session');var h={'Content-Type':'application/json'};if(t)h['Authorization']='Bearer '+t;return h}

// ── Formatters ────────────────────────────────────────────────────────────────
function fmtUptime(s){if(!s&&s!==0)return'--';var d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return(d?d+'d ':'')+(h?h+'h ':'')+(m+'m')}
function fmtDate(d){if(!d)return'--';return new Date(d).toLocaleString()}
function fmtSize(b){if(!b)return'0B';if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB'}

// ── Navigation ────────────────────────────────────────────────────────────────
var NAV_ITEMS = [
  {id:'dashboard', label:'Dashboard', href:'/ui/index.html'},
  {id:'frontends', label:'Frontends',  href:'/ui/frontends.html'},
  {id:'backends',  label:'Backends',   href:'/ui/backends.html'},
  {id:'queue',     label:'Mail Queue', href:'/ui/queue.html', navId:'nav-queue'},
];

function buildNav(activePage) {
  var sb = document.getElementById('sidebar');
  if (!sb) return;
  var html = '<div class="nav-section">Navigation</div>';
  NAV_ITEMS.forEach(function(item) {
    var cls = item.id === activePage ? ' class="active"' : '';
    var id  = item.navId ? ' id="'+item.navId+'"' : '';
    html += '<a href="'+item.href+'"'+cls+id+'>'+item.label+'</a>';
  });
  sb.innerHTML = html;
}

function wireLogout() {
  var btn = document.getElementById('logoutBtn');
  if (btn) {
    btn.addEventListener('click', function() {
      document.cookie = 'lg_session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      window.location.href = '/ui/login.html';
    });
  }
}

async function checkSmtpFrontends() {
  try {
    var r = await fetch('/api/frontends', {headers: authHeaders()});
    if (!r.ok) return;
    var d = await r.json();
    var hasSmtp = (d.frontends || []).some(function(f) {
      return f.protocol === 'smtps' || f.protocol === 'smtpstarttls';
    });
    if (hasSmtp) {
      var el = document.getElementById('nav-queue');
      if (el) el.style.display = '';
      var card = document.getElementById('cardQueue');
      if (card) card.style.display = '';
    }
  } catch(e) { /* degrade gracefully */ }
}

function initPage(activePage) {
  buildNav(activePage);
  wireLogout();
  checkSmtpFrontends();
}
