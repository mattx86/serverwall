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
  {id:'dashboard',  label:'Dashboard',    href:'/ui/index.html'},
  {id:'frontends',  label:'Frontends',    href:'/ui/frontends.html'},
  {id:'backends',   label:'Backends',     href:'/ui/backends.html'},
  {id:'certs',      label:'Certificates', href:'/ui/certificates.html', children:[
    {id:'certs-import',   label:'Import',        href:'/ui/certificates-import.html'},
    {id:'certs-generate', label:'Generate',      href:'/ui/certificates-generate.html'},
    {id:'certs-acme',     label:"Let's Encrypt", href:'/ui/certificates-acme.html'},
  ]},
  {id:'acl',          label:'IP ACL',          href:'/ui/acl.html'},
  {id:'log-profiles', label:'Logging Profiles',href:'/ui/log-profiles.html'},
  {id:'http', label:'HTTP', href:'/ui/waf.html', children:[
    {id:'waf',      label:'WAF Rulesets',      href:'/ui/waf.html'},
    {id:'security', label:'Security',           href:'/ui/security.html'},
    {id:'profiles', label:'Frontend Profiles',  href:'/ui/security-profiles.html'},
  ]},
  {id:'email', label:'Email', href:'/ui/antispam.html', children:[
    {id:'antispam', label:'Antispam',   href:'/ui/antispam.html'},
    {id:'relay',    label:'Relay',      href:'/ui/relay.html'},
    {id:'queue',    label:'Mail Queue', href:'/ui/queue.html'},
    {id:'dkim',     label:'DKIM',       href:'/ui/dkim.html'},
    {id:'dmarc',    label:'DMARC',      href:'/ui/dmarc.html'},
    {id:'spf',      label:'SPF',        href:'/ui/spf.html'},
  ]},
  {id:'logs',      label:'Logs',         href:'/ui/logs.html'},
  {id:'settings', label:'Settings', href:'/ui/global-settings.html', children:[
    {id:'global-settings',  label:'Global',               href:'/ui/global-settings.html'},
    {id:'acme-settings',    label:"ACME / Let's Encrypt", href:'/ui/acme-settings.html'},
    {id:'webui-settings',   label:'WebUI Access',         href:'/ui/webui-settings.html'},
  ]},
];

function buildNav(activePage) {
  var sb = document.getElementById('sidebar');
  if (!sb) return;
  var html = '<div class="nav-section">Navigation</div>';
  NAV_ITEMS.forEach(function(item) {
    var id    = item.navId ? ' id="'+item.navId+'"' : '';
    var style = item.navId ? ' style="display:none"' : '';
    if (item.children) {
      var groupActive = activePage === item.id
          || activePage.indexOf(item.id + '-') === 0
          || item.children.some(function(c) { return c.id === activePage; });
      var cls = groupActive ? ' class="active"' : '';
      html += '<a href="'+item.href+'"'+cls+id+style+'>'+item.label+'</a>';
      if (groupActive) {
        item.children.forEach(function(child) {
          var childCls = activePage === child.id ? ' class="nav-child active"' : ' class="nav-child"';
          html += '<a href="'+child.href+'"'+childCls+'>'+child.label+'</a>';
        });
      }
    } else {
      var cls = item.id === activePage ? ' class="active"' : '';
      html += '<a href="'+item.href+'"'+cls+id+style+'>'+item.label+'</a>';
    }
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
