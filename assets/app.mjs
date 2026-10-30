import {TARGETS, ATTEMPTS, ENTRIES, diagnose, checkState, serializeReport, getLaunchCommands, textSummary, entryName, encodeShare, decodeShare, SHARE_PREFIX, entryText, hostText, reasonText} from './diagnostics.mjs?v=5.5.0';

const $ = id => document.getElementById(id);
let lastReport = null;
const rows = new Map();

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function statusCell(tone, text) {
  const label = el('span', 'result-status');
  const dot = el('span', 'dot ' + tone); dot.setAttribute('aria-hidden', 'true');
  label.append(dot, el('span', '', text));
  return label;
}

function createRows() {
  rows.clear();
  $('results').replaceChildren();
  for (const target of TARGETS) {
    const row = el('tr');
    const title = el('td');
    title.append(el('span', 'target-name', target.name), el('span', 'target-host', new URL(target.url).hostname));
    row.append(title);
    for (const value of ['—', '—']) row.append(el('td', '', value));
    row.cells[2].className = 'timing';
    rows.set(target.id, row); $('results').append(row);
  }
}

function renderCheck(check) {
  const row = rows.get(check.id);
  const state = checkState(check);
  row.cells[1].replaceChildren(statusCell(state.tone, state.label));
  row.cells[2].textContent = check.attempts.map(a => a.durationMs + ' мс').join(' / ');
}

function shortNode(node) { return node ? node.split(' · ')[0] : 'узел ?'; }
function nodePlace(node) { return node ? node.split(' · ').slice(1).join(' · ') : '—'; }

function entryTiles(entries, waiting = false) {
  $('entries').replaceChildren();
  for (const entry of entries) {
    const tile = el('div', 'tile');
    const top = el('div', 'tile-top');
    const result = entry.observation;
    const tone = !result ? (waiting ? 'running' : '') : entry.reachable ? 'success' : 'negative';
    top.append(el('span', 'tile-name', entry.name), statusCell(tone, !result ? (waiting ? 'проверяем' : 'не проверяли') : entry.reachable ? 'открыт' : 'закрыт'));
    const ms = el('div', 'tile-ms', result ? (entry.reachable ? String(result.durationMs) : '×') : '—');
    if (result && entry.reachable) ms.append(el('small', '', 'мс'));
    tile.append(top, ms, el('div', 'tile-sub', entry.place + ' · ' + entry.address +
      (result && entry.reachable ? ' → ' + shortNode(entry.node) : '')));
    $('entries').append(tile);
  }
}

const CHIP = {ru: 'вход в России', abroad: 'зарубежный вход', failed: 'вход не открылся', unknown: 'вход не опознан'};
const HEADLINE = {ru: 'Россия', abroad: 'Зарубеж', failed: 'Сбой', unknown: 'Не ясно'};

function renderRoute(report) {
  const {byAddress, byDns} = report.recognition;
  const n = report.network;
  $('hero').className = 'hero ' + byDns.verdict;
  $('verdict').textContent = HEADLINE[byDns.verdict];
  $('verdict-chip').textContent = CHIP[byDns.verdict]; $('verdict-chip').className = 'chip ' + byDns.verdict; $('verdict-chip').hidden = false;
  $('by-address').textContent = '';
  $('by-dns').textContent = byDns.verdict === 'ru' ? 'Россия' : byDns.verdict === 'abroad' ? 'Зарубеж' : byDns.verdict === 'failed' ? 'нет ответа' : 'не ясно';
  $('route-entry').textContent = byDns.reachable ? entryName(byDns.entryAddress) : '×';
  $('route-entry-sub').textContent = byDns.reachable ? (byDns.observation.durationMs + ' мс') : 'не открылся';
  $('route-node').textContent = byDns.reachable ? shortNode(byDns.node) : '×';
  $('route-node-sub').textContent = byDns.reachable ? nodePlace(byDns.node) : '—';
  let mismatch = '';
  const blocked = report.summary?.code === 'entries_blocked';
  if (blocked) {
    $('hero').className = 'hero failed'; $('verdict').textContent = 'Закрыто';
    $('verdict-chip').textContent = 'все входы закрыты'; $('verdict-chip').className = 'chip failed';
    mismatch = report.summary.text;
  } else if (byDns.verdict === 'failed') mismatch = 'Вход по DNS не открылся — сайты .dev у вас могут не работать. Скопируйте сводку в поддержку.';
  else if ((byDns.verdict === 'ru' || byDns.verdict === 'abroad') && byDns.verdict !== byAddress.verdict)
    mismatch = 'DNS и адрес расходятся: так бывает с публичным DNS (1.1.1.1) или VPN.';
  mismatch = (!blocked && resolverMismatch(report)) || mismatch;
  $('mismatch').textContent = mismatch; $('mismatch').hidden = !mismatch;
  $('network-id').textContent = [n.ip || 'IP ?', n.asn ? 'AS' + n.asn : null, n.node ? 'эта страница: ' + entryName(n.entryAddress) + ' → ' + shortNode(n.node) : null].filter(Boolean).join(' · ');
}

function countryName(code) {
  if (!code) return 'страна ?';
  try { return new Intl.DisplayNames(['ru'], {type: 'region'}).of(code); } catch (_) { return code; }
}

// Какой DNS-сервер спросил наше имя и куда его по правилу отправляет GeoDNS.
function renderResolver(report) {
  const r = report.dnsResolver;
  $('resolver-block').hidden = !r;
  if (!r) return;
  $('resolvers').replaceChildren();
  const first = r.seen?.[0];
  $('dns-sub').textContent = first ? (first.resolver?.provider || first.resolver?.ip || 'DNS-сервер') + ' · ' + (first.ecs ? 'подсеть ' + (first.ecs.country || '?') : countryName(first.resolver?.country)) : 'куда ведут сайты';
  if (r.status !== 'found') {
    $('resolver-note').textContent = r.status === 'unreachable' ? 'Не узнали: ни один вход Layero не открылся.' : 'Наш сервер имён запроса не получил — DNS мог ответить из кэша или не дошёл до нас.';
    return;
  }
  for (const s of r.seen) {
    const tile = el('div', 'tile');
    const top = el('div', 'tile-top');
    const tone = s.decision.entry === 'uz' ? 'success' : 'warning';
    top.append(el('span', 'tile-name', s.resolver?.provider || 'DNS-сервер'), statusCell(tone, entryText(s.decision.entry)));
    tile.append(top, el('div', 'tile-ms', countryName(s.ecs ? s.ecs.country : s.resolver?.country)),
      el('div', 'tile-sub', 'сервер ' + hostText(s.resolver) + (s.ecs ? ' · передал вашу подсеть ' + hostText({...s.ecs, ip: null}) : ' · вашу подсеть не передал')),
      el('div', 'tile-sub', (s.ecs ? 'по подсети: ' : 'по DNS-серверу: ') + reasonText(s.decision.reason)));
    $('resolvers').append(tile);
  }
  $('resolver-note').textContent = r.seen.length > 1 ? 'Сервер спрашивал с нескольких адресов — вход может меняться от запроса к запросу.' : '';
}

function resolverMismatch(report) {
  const r = report.dnsResolver; const n = report.network || {};
  const s = r?.status === 'found' ? r.seen[0] : null;
  if (!s) return '';
  const toRu = s.decision.entry === 'ru6';
  if (toRu && report.recognition.byAddress.verdict === 'abroad') {
    return 'Ваш DNS-сервер — ' + (s.resolver?.provider || s.resolver?.ip) + ' (' + countryName(s.ecs ? s.ecs.country : s.resolver?.country) + '). ' +
      'По нему GeoDNS считает вас Россией и ведёт в Москву, а трафик выходит через ' + countryName(n.countryCode) +
      (n.provider ? ' (' + n.provider + ')' : '') + ' — так бывает с VPN, который не заворачивает DNS. ' +
      (report.entries?.find(e => e.id === 'ru6')?.reachable === false ? 'Из вашей сети вход в Москве закрыт — поэтому сервисы не открываются.' : '');
  }
  if (!toRu && report.recognition.byAddress.verdict === 'ru') {
    return 'Ваш DNS-сервер — ' + (s.resolver?.provider || s.resolver?.ip) + ' (' + countryName(s.resolver?.country) + ') не передаёт вашу подсеть, поэтому GeoDNS ведёт вас как иностранца в Ташкент.';
  }
  return '';
}

function renderNetwork(network) {
  let country = network.countryCode || 'Не определена';
  if (network.countryCode) {
    try { country = new Intl.DisplayNames(['ru'], {type: 'region'}).of(network.countryCode); } catch (_) {}
  }
  $('country').textContent = country;
  $('provider').textContent = network.provider || 'Не определён';
}

function resetRoute(text) {
  $('hero').className = 'hero';
  $('verdict').textContent = text; $('verdict-chip').hidden = true; $('mismatch').hidden = true;
  for (const id of ['by-dns', 'route-entry', 'route-node']) $(id).textContent = '…';
  $('route-entry-sub').textContent = '—'; $('route-node-sub').textContent = '—';
  $('by-address').textContent = 'Страна, вход, узел, сервисы.';
  $('resolver-block').hidden = true; $('dns-sub').textContent = 'куда ведут сайты';
}

async function run() {
  if ($('run').disabled) return;
  lastReport = null;
  $('manual-panel').hidden = true;
  leaveShared();
  $('run').disabled = true; $('run').setAttribute('aria-busy', 'true'); $('download').disabled = true; $('copy-summary').disabled = true;
  $('share').disabled = true; $('share-link').hidden = true;
  $('run-label').textContent = 'Проверяем…'; $('state-dot').className = 'dot running';
  resetRoute('Смотрим…'); entryTiles(ENTRIES, true);
  $('progress-track').hidden = false; $('progress-fill').style.width = '0%';
  $('report').hidden = true; $('report').textContent = '';
  $('summary').hidden = true; $('report-id').textContent = ''; $('network-id').textContent = '';
  $('country').textContent = 'Определяем…'; $('provider').textContent = '…';
  $('progress').textContent = 'Проверяем…';
  $('count').textContent = TARGETS.length + ' адресов · по ' + ATTEMPTS + ' запроса';
  createRows();
  for (const row of rows.values()) row.cells[1].textContent = '…';
  let completed = 0;
  try {
    lastReport = await diagnose({onCheck(check) {
      renderCheck(check); completed++;
      if (checkState(check).tone !== 'success') $('manual-panel').hidden = false;
      $('progress').textContent = completed + ' из ' + TARGETS.length;
      $('progress-fill').style.width = Math.round(completed / TARGETS.length * 100) + '%';
    }});
    renderNetwork(lastReport.network);
    renderRoute(lastReport);
    renderResolver(lastReport);
    entryTiles(lastReport.entries);
    if (lastReport.entries.some(e => !e.reachable)) $('manual-panel').hidden = false;
    $('summary').textContent = lastReport.summary.text; $('summary').hidden = false;
    $('report-id').textContent = 'Проверка ' + lastReport.reportId;
    const answered = lastReport.checks.filter(c => checkState(c).answered === ATTEMPTS).length;
    $('count').textContent = answered + ' из ' + TARGETS.length + ' ответили';
    $('state-dot').className = 'dot ' + (lastReport.summary.code === 'no_failure_reproduced' ? 'success' : 'warning');
    $('progress').textContent = 'Готово. Если что-то не так — скопируйте сводку в поддержку.';
    $('report').textContent = serializeReport(lastReport);
    $('download').disabled = false; $('copy-summary').disabled = false; $('share').disabled = false;
  } catch (_) {
    $('state-dot').className = 'dot negative';
    $('country').textContent = 'Не определена'; $('provider').textContent = 'Не определён';
    resetRoute('Сбой'); entryTiles(ENTRIES.map(e => ({...e, observation: null})));
    $('progress').textContent = 'Проверка не завершилась. Запустите ещё раз.';
  } finally {
    $('run').disabled = false; $('run').removeAttribute('aria-busy'); $('run-label').textContent = 'Ещё раз';
  }
}

function download() {
  if (!lastReport || $('download').disabled) return;
  let url;
  try {
    url = URL.createObjectURL(new Blob([serializeReport(lastReport)], {type: 'application/json;charset=utf-8'}));
    const link = document.createElement('a'); link.href = url;
    link.download = 'layero-diagnostics-' + lastReport.reportId + '.json';
    document.body.append(link); link.click(); link.remove();
    $('progress').textContent = 'JSON скачан. Приложите к обращению.';
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (_) {
    if (url) URL.revokeObjectURL(url);
    $('report').hidden = false;
    $('progress').textContent = 'Скачать не вышло. Скопируйте JSON ниже.';
  }
}

async function copySummary() {
  if (!lastReport || $('copy-summary').disabled) return;
  try {
    await navigator.clipboard.writeText(textSummary(lastReport));
    $('progress').textContent = 'Сводка скопирована.';
  } catch (_) {
    $('report').hidden = false;
    $('progress').textContent = 'Скопировать не вышло. Выделите JSON ниже.';
  }
}

async function share() {
  if (!lastReport || $('share').disabled || lastReport.shared) return;
  let url;
  try {
    url = location.origin + location.pathname + SHARE_PREFIX + await encodeShare(lastReport);
  } catch (_) {
    $('progress').textContent = 'Ссылку собрать не вышло. Скопируйте сводку.';
    return;
  }
  $('share-link').textContent = url; $('share-link').hidden = false;
  try {
    await navigator.clipboard.writeText(url);
    $('progress').textContent = 'Ссылка скопирована — отправьте её в поддержку.';
  } catch (_) {
    $('progress').textContent = 'Скопируйте ссылку ниже и отправьте в поддержку.';
  }
}

// Просмотр результата по ссылке: та же страница, но данные из ссылки, а не свои.
function showShared(report) {
  lastReport = report;
  $('shared-banner').hidden = false;
  let when = report.finishedAt;
  try { when = new Date(report.finishedAt).toLocaleString('ru-RU', {dateStyle: 'medium', timeStyle: 'short'}); } catch (_) {}
  const ctx = report.context || {};
  const opened = ctx.openedOn ? (ctx.openedOn.endsWith('github.io') ? 'копия на GitHub' : ctx.openedOn) : null;
  $('shared-meta').textContent = [when, ctx.timezone, ctx.language, opened ? 'открыто: ' + opened : null, 'проверка ' + report.reportId].filter(Boolean).join(' · ');
  renderNetwork(report.network); renderRoute(report); renderResolver(report); entryTiles(report.entries);
  createRows(); for (const check of report.checks) renderCheck(check);
  $('summary').textContent = report.summary.text; $('summary').hidden = false;
  $('report-id').textContent = 'Проверка ' + report.reportId + ' · версия ' + report.toolVersion;
  $('state-dot').className = 'dot ' + (report.summary.code === 'no_failure_reproduced' ? 'success' : 'warning');
  $('progress').textContent = 'Это результат из ссылки. Своё подключение — кнопка «Проверить».';
  $('copy-summary').disabled = false;
}

function leaveShared() {
  if ($('shared-banner').hidden) return;
  $('shared-banner').hidden = true;
  try { history.replaceState(null, '', location.pathname); } catch (_) {}
}

$('run').addEventListener('click', run);
$('share').addEventListener('click', share);
$('download').addEventListener('click', download);
$('copy-summary').addEventListener('click', copySummary);
createRows();
entryTiles(ENTRIES);
let commandOS = /Windows/i.test(navigator.userAgent) ? 'windows' : 'unix';
const launchCommands = getLaunchCommands(globalThis.location?.origin);
function renderCommand() {
  $('manual-command').textContent = launchCommands[commandOS];
  $('command-help').textContent = commandOS === 'windows' ? 'PowerShell → вставить → прислать результат в поддержку.' : 'Терминал → вставить → прислать результат в поддержку.';
  $('os-unix').setAttribute('aria-pressed', String(commandOS === 'unix'));
  $('os-windows').setAttribute('aria-pressed', String(commandOS === 'windows'));
  $('copy-command').setAttribute('data-copied', 'false');
  $('copy-feedback').textContent = '';
}
for (const os of ['unix', 'windows']) $('os-' + os).addEventListener('click', () => { commandOS = os; renderCommand(); });
$('copy-command').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(launchCommands[commandOS]);
    $('copy-command').setAttribute('data-copied', 'true');
    $('copy-feedback').textContent = 'Команда скопирована.';
  } catch (_) { $('copy-feedback').textContent = 'Выделите и скопируйте строку выше.'; }
});
renderCommand();
const fragment = globalThis.location?.hash || '';
if (fragment.startsWith(SHARE_PREFIX)) {
  decodeShare(fragment).then(report => {
    if (report) showShared(report);
    else $('progress').textContent = 'Ссылка с результатом повреждена. Попросите прислать её ещё раз.';
  });
}
