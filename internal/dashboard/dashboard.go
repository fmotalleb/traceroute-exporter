package dashboard

// DashboardHTML contains the embedded dashboard HTML/JS
const DashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Traceroute dashboard</title>
<style>
:root { color-scheme: light dark; --bg: #0f172a; --panel: #111827; --text: #e5e7eb; --muted: #94a3b8; --line: #64748b; --ok: #22c55e; --warn: #f59e0b; --bad: #ef4444; --blue: #38bdf8; }
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
header { padding: 18px 22px; border-bottom: 1px solid rgba(148,163,184,.25); background: rgba(15,23,42,.92); position: sticky; top: 0; z-index: 2; }
h1 { margin: 0 0 10px; font-size: 22px; }
form { display: grid; grid-template-columns: minmax(220px, 1fr) 110px 90px 80px 70px 120px auto; gap: 10px; align-items: end; }
label { display: grid; gap: 4px; color: var(--muted); font-size: 12px; }
input, select, button { border: 1px solid rgba(148,163,184,.35); border-radius: 10px; background: #020617; color: var(--text); padding: 9px 10px; font: inherit; }
button { cursor: pointer; background: #2563eb; border-color: #2563eb; color: white; font-weight: 700; }
button:disabled { opacity: .6; cursor: wait; }
main { padding: 18px 22px 26px; }
.panel { background: rgba(17,24,39,.92); border: 1px solid rgba(148,163,184,.22); border-radius: 16px; padding: 16px; margin-bottom: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.2); }
.status { color: var(--muted); min-height: 22px; }
.summary { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
.pill { border: 1px solid rgba(148,163,184,.25); border-radius: 999px; padding: 6px 10px; color: var(--muted); background: rgba(2,6,23,.7); }
.pill strong { color: var(--text); }
.graph-wrap { overflow: auto; min-height: 320px; }
svg { width: 100%; min-width: 850px; height: auto; }
.edge { stroke: var(--line); stroke-width: 2; fill: none; marker-end: url(#arrow); opacity: .8; }
.edge.no-reply { stroke-dasharray: 6 6; opacity: .55; }
.node rect { stroke-width: 2; rx: 12; }
.node.source rect { fill: rgba(56,189,248,.18); stroke: var(--blue); }
.node.responded rect { fill: rgba(34,197,94,.15); stroke: var(--ok); }
.node.no-reply rect { fill: rgba(148,163,184,.12); stroke: var(--warn); stroke-dasharray: 5 4; }
.node text { fill: var(--text); font-size: 12px; }
.node .muted { fill: var(--muted); font-size: 11px; }
.hop-label { fill: var(--muted); font-size: 12px; }
pre { white-space: pre-wrap; overflow: auto; max-height: 360px; background: #020617; border: 1px solid rgba(148,163,184,.2); border-radius: 12px; padding: 12px; color: #cbd5e1; }
a { color: #93c5fd; }
@media (max-width: 1050px) { form { grid-template-columns: 1fr 1fr; } button { grid-column: 1 / -1; } }
</style>
</head>
<body>
<header>
<h1>Traceroute single-trace dashboard</h1>
<form id="traceForm">
<label>Target <input id="target" name="target" placeholder="example.com:443" autocomplete="off"></label>
<label>Method <select id="method"><option value="auto">auto</option><option value="tcp">tcp</option><option value="icmp">icmp</option><option value="udp">udp</option></select></label>
<label>Max hops <input id="maxHops" type="number" min="1" max="255" value="30"></label>
<label>Queries <input id="queries" type="number" min="1" max="10" value="1"></label>
<label>IP <select id="ipFamily"><option value="">auto</option><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
<label>Loop repeats <input id="loopRepeats" type="number" min="0" max="100" value="{{DEFAULT_LOOP_REPEATS}}"></label>
<button id="run" type="submit">Run trace</button>
</form>
</header>
<main>
<section class="panel">
<div id="status" class="status">Ready.</div>
<div id="summary" class="summary"></div>
</section>
<section class="panel graph-wrap" id="graph"><p class="status">Run a trace to render the tree.</p></section>
<section class="panel">
<details>
<summary>Raw Prometheus exposition</summary>
<pre id="raw"></pre>
</details>
</section>
</main>
<script>
'use strict';
var initialTarget = {{TARGET_JSON}};
var form = document.getElementById('traceForm');
var targetInput = document.getElementById('target');
var methodInput = document.getElementById('method');
var maxHopsInput = document.getElementById('maxHops');
var queriesInput = document.getElementById('queries');
var ipFamilyInput = document.getElementById('ipFamily');
var loopRepeatsInput = document.getElementById('loopRepeats');
var runButton = document.getElementById('run');
var statusEl = document.getElementById('status');
var summaryEl = document.getElementById('summary');
var graphEl = document.getElementById('graph');
var rawEl = document.getElementById('raw');

targetInput.value = initialTarget || 'example.com:443';

form.addEventListener('submit', function (event) {
  event.preventDefault();
  runTrace();
});

if (targetInput.value) {
  runTrace();
}

function setStatus(message, isError) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? 'var(--bad)' : 'var(--muted)';
}

async function runTrace() {
  var target = targetInput.value.trim();
  if (!target) {
    setStatus('Target is required.', true);
    return;
  }
  runButton.disabled = true;
  summaryEl.innerHTML = '';
  graphEl.innerHTML = '<p class="status">Running traceroute...</p>';
  rawEl.textContent = '';
  setStatus('Running trace for ' + target + ' ...', false);
  var params = new URLSearchParams();
  params.set('target', target);
  params.set('debug', '1');
  params.set('method', methodInput.value);
  params.set('max_hops', maxHopsInput.value || '30');
  params.set('queries', queriesInput.value || '1');
  params.set('loop_max_repeats', loopRepeatsInput.value || '0');
  if (ipFamilyInput.value) {
    params.set('ip_family', ipFamilyInput.value);
  }
  try {
    var started = Date.now();
    var response = await fetch('/trace?' + params.toString(), { credentials: 'same-origin', cache: 'no-store' });
    var text = await response.text();
    rawEl.textContent = text;
    var data = parsePrometheus(text);
    renderSummary(data, response.status, Date.now() - started);
    renderGraph(data);
    setStatus(data.loopGiveup === 1 ? 'Trace stopped after repeated routing loop.' : 'Trace complete.', !response.ok || data.probeSuccess === 0 || data.loopGiveup === 1);
  } catch (err) {
    setStatus('Trace failed: ' + err.message, true);
    graphEl.innerHTML = '<p class="status">' + esc(err.message) + '</p>';
  } finally {
    runButton.disabled = false;
  }
}

function parsePrometheus(text) {
  var data = { nodes: new Map(), edges: [], probeSuccess: null, parseSuccess: null, hops: null, duration: null, errors: [], targetInfo: null, loopDetected: 0, loopGiveup: 0, loopInfo: null };
  var lines = text.split(/\n/);
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line || line[0] === '#') continue;
    var sample = parseSample(line);
    if (!sample) continue;
    if (sample.name === 'traceroute_node_info') {
      var node = Object.assign({}, sample.labels);
      node.hop = parseInt(node.hop || '0', 10);
      node.responded = node.responded !== 'false';
      data.nodes.set(node.node, node);
    } else if (sample.name === 'traceroute_tree_edge_info') {
      data.edges.push(Object.assign({}, sample.labels));
    } else if (sample.name === 'traceroute_probe_success') {
      data.probeSuccess = sample.value;
    } else if (sample.name === 'traceroute_output_parse_success') {
      data.parseSuccess = sample.value;
    } else if (sample.name === 'traceroute_hops') {
      data.hops = sample.value;
    } else if (sample.name === 'traceroute_probe_duration_seconds') {
      data.duration = sample.value;
    } else if (sample.name === 'traceroute_loop_detected') {
      data.loopDetected = sample.value;
    } else if (sample.name === 'traceroute_loop_giveup') {
      data.loopGiveup = sample.value;
    } else if (sample.name === 'traceroute_loop_info') {
      data.loopInfo = sample.labels;
    } else if (sample.name === 'traceroute_probe_error_info' && sample.value === 1) {
      data.errors.push(sample.labels.reason || 'unknown');
    } else if (sample.name === 'traceroute_target_info') {
      data.targetInfo = sample.labels;
    }
  }
  data.edges.forEach(function (edge) {
    if (!data.nodes.has(edge.parent)) {
      data.nodes.set(edge.parent, { node: edge.parent, hostname: edge.parent_hostname || edge.parent, address: edge.parent_address || '', hop: parseInt(edge.parent_hop || '0', 10), responded: true, role: 'hop' });
    }
    if (!data.nodes.has(edge.node)) {
      data.nodes.set(edge.node, { node: edge.node, hostname: edge.node_hostname || edge.node, address: edge.node_address || '', hop: parseInt(edge.node_hop || '0', 10), responded: edge.node_responded !== 'false', role: 'hop' });
    }
  });
  return data;
}

function parseSample(line) {
  var match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([-+0-9.eE]+)$/);
  if (!match) return null;
  return { name: match[1], labels: parseLabels(match[2] || ''), value: Number(match[3]) };
}

function parseLabels(input) {
  var labels = {};
  var i = 0;
  while (i < input.length) {
    while (input[i] === ',' || input[i] === ' ') i++;
    var keyStart = i;
    while (i < input.length && input[i] !== '=') i++;
    var key = input.slice(keyStart, i);
    i++;
    if (input[i] !== '"') break;
    i++;
    var value = '';
    while (i < input.length) {
      var ch = input[i++];
      if (ch === '"') break;
      if (ch === '\\' && i < input.length) {
        var next = input[i++];
        if (next === 'n') value += '\n';
        else value += next;
      } else {
        value += ch;
      }
    }
    labels[key] = value;
    while (input[i] === ',' || input[i] === ' ') i++;
  }
  return labels;
}

function renderSummary(data, httpStatus, elapsedMs) {
  var reached = data.probeSuccess === 1 ? 'yes' : 'no';
  var parsed = data.parseSuccess === 1 ? 'yes' : 'no';
  var loop = data.loopDetected === 1 ? 'yes' : 'no';
  var giveup = data.loopGiveup === 1 ? 'yes' : 'no';
  var destination = data.targetInfo ? ((data.targetInfo.hostname || '') + ' ' + (data.targetInfo.address || '')).trim() : targetInput.value.trim();
  var html = '';
  html += pill('HTTP', String(httpStatus));
  html += pill('Reached', reached);
  html += pill('Parsed', parsed);
  html += pill('Loop', loop);
  html += pill('Loop give-up', giveup);
  html += pill('Hops', data.hops == null ? '-' : String(data.hops));
  html += pill('Probe time', data.duration == null ? (elapsedMs / 1000).toFixed(2) + 's' : Number(data.duration).toFixed(2) + 's');
  html += pill('Nodes', String(data.nodes.size));
  html += pill('Destination', destination || '-');
  if (data.loopInfo) html += pill('Loop pattern', (data.loopInfo.pattern || '-') + ' x' + (data.loopInfo.repeats || '?'));
  if (data.errors.length) html += pill('Errors', data.errors.join(', '));
  summaryEl.innerHTML = html;
}

function pill(key, value) {
  return '<span class="pill"><strong>' + esc(key) + ':</strong> ' + esc(value) + '</span>';
}

function renderGraph(data) {
  if (data.nodes.size === 0) {
    graphEl.innerHTML = '<p class="status">No nodes parsed. Open raw exposition for details.</p>';
    return;
  }
  var groups = new Map();
  data.nodes.forEach(function (node) {
    var hop = Number.isFinite(node.hop) ? node.hop : 0;
    if (!groups.has(hop)) groups.set(hop, []);
    groups.get(hop).push(node);
  });
  var hops = Array.from(groups.keys()).sort(function (a, b) { return a - b; });
  hops.forEach(function (hop) {
    groups.get(hop).sort(function (a, b) { return (a.hostname || a.node).localeCompare(b.hostname || b.node); });
  });

  var xStep = 220;
  var yStep = 110;
  var nodeW = 170;
  var nodeH = 62;
  var marginX = 40;
  var marginY = 54;
  var maxPerHop = 1;
  hops.forEach(function (hop) { maxPerHop = Math.max(maxPerHop, groups.get(hop).length); });
  var width = Math.max(900, marginX * 2 + (hops.length - 1) * xStep + nodeW);
  var height = Math.max(320, marginY * 2 + maxPerHop * yStep);
  var pos = new Map();
  hops.forEach(function (hop, hopIndex) {
    var nodes = groups.get(hop);
    var totalHeight = (nodes.length - 1) * yStep;
    var startY = height / 2 - totalHeight / 2;
    nodes.forEach(function (node, idx) {
      pos.set(node.node, { x: marginX + hopIndex * xStep, y: startY + idx * yStep });
    });
  });

  var svg = [];
  svg.push('<svg viewBox="0 0 ' + width + ' ' + height + '" aria-label="Traceroute tree">');
  svg.push('<defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"></path></marker></defs>');
  hops.forEach(function (hop, hopIndex) {
    svg.push('<text class="hop-label" x="' + (marginX + hopIndex * xStep) + '" y="24">hop ' + hop + '</text>');
  });
  data.edges.forEach(function (edge) {
    var a = pos.get(edge.parent);
    var b = pos.get(edge.node);
    if (!a || !b) return;
    var cls = edge.node_responded === 'false' ? 'edge no-reply' : 'edge';
    svg.push('<path class="' + cls + '" d="M ' + (a.x + nodeW) + ' ' + (a.y + nodeH / 2) + ' C ' + (a.x + nodeW + 55) + ' ' + (a.y + nodeH / 2) + ', ' + (b.x - 55) + ' ' + (b.y + nodeH / 2) + ', ' + b.x + ' ' + (b.y + nodeH / 2) + '"></path>');
  });
  data.nodes.forEach(function (node) {
    var p = pos.get(node.node);
    if (!p) return;
    var role = node.role === 'source' ? 'source' : (node.responded ? 'responded' : 'no-reply');
    var title = node.hostname || node.node;
    var sub = node.address && node.address !== title ? node.address : node.node;
    svg.push('<g class="node ' + role + '" transform="translate(' + p.x + ',' + p.y + ')">');
    svg.push('<rect width="' + nodeW + '" height="' + nodeH + '"></rect>');
    svg.push('<text x="12" y="24">' + esc(shorten(title, 24)) + '</text>');
    svg.push('<text class="muted" x="12" y="44">' + esc(shorten(sub, 28)) + '</text>');
    svg.push('<title>' + esc((node.hostname || node.node) + '\naddress: ' + (node.address || '-') + '\nhop: ' + node.hop + '\nresponded: ' + node.responded) + '</title>');
    svg.push('</g>');
  });
  svg.push('</svg>');
  graphEl.innerHTML = svg.join('');
}

function shorten(value, max) {
  value = String(value || '');
  if (value.length <= max) return value;
  return value.slice(0, Math.max(0, max - 1)) + '…';
}

function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch];
  });
}
</script>
</body>
</html>`
