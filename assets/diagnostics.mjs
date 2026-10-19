// Measurement model. No DOM, cookies, account credentials or automatic upload.
import {LAUNCH_COMMANDS} from './launch-commands.mjs?v=5.4.0';
import {RU_ENTRY, ABROAD_ENTRY, RU_ASNS} from './ru-asns.mjs?v=5.4.0';
export {LAUNCH_COMMANDS, RU_ENTRY, ABROAD_ENTRY};
export const VERSION = '5.4.0';
export const ATTEMPTS = 2;
export const TIMEOUT_MS = 12000;
export const NETWORK_PATH = '/__layero/network-info';
export const TARGETS = Object.freeze([
  {id: 'panel', name: 'Панель', url: 'https://app.layero.ru/login'},
  {id: 'api', name: 'API', url: 'https://api.layero.ru/health'},
  {id: 'site', name: 'Сайт на Layero', url: 'https://status.layero.app/'},
  {id: 'docs', name: 'Документация', url: 'https://docs.layero.ru/'},
  {id: 'landing', name: 'Лендинг', url: 'https://layero.ru/'}
].map(Object.freeze));

// Входы платформы. Каждое служебное имя смотрит на свой адрес и отдаёт только
// сведения о подключении; по ним видно, открывается ли вход у посетителя.
export const ENTRIES = Object.freeze([
  {id: 'yc', name: 'Основной вход', place: 'Yandex Cloud', address: '89.169.148.11',
    url: 'https://entry-yc.layero.dev' + NETWORK_PATH},
  {id: 'ru6', name: 'Вход в России', place: 'Selectel, Москва', address: RU_ENTRY,
    url: 'https://entry-ru6.layero.dev' + NETWORK_PATH},
  {id: 'uz', name: 'Зарубежный вход', place: 'Ташкент', address: ABROAD_ENTRY,
    url: 'https://entry-uz.layero.dev' + NETWORK_PATH}
].map(Object.freeze));
// Имя, которое DNS разрешает теми же правилами, что сайты layero.dev, но
// одним адресом: россиянам — вход в России, остальным — зарубежный вход.
export const GEO_PROBE_URL = 'https://geo-probe.layero.dev' + NETWORK_PATH;
// Edge узнаёт вход по адресу назначения из PROXY-заголовка: балансировщик ru-6
// передаёт свой внутренний адрес, точка в Ташкенте — свой. Проверено 19.10.2026.
export const ENTRY_SIGNATURES = Object.freeze({ru: [RU_ENTRY, '10.80.0.87'], abroad: [ABROAD_ENTRY, '10.90.0.10']});
// Короткое имя входа по адресу из PROXY-заголовка; без заголовка — путь через Yandex Cloud.
export function entryName(address) {
  if (ENTRY_SIGNATURES.ru.includes(address)) return 'Москва · ru-6';
  if (ENTRY_SIGNATURES.abroad.includes(address)) return 'Ташкент';
  return address ? 'неизвестный вход ' + address : 'Yandex Cloud';
}

// Тот же поиск, что в правилах DNS: диапазоны по 8 знаков (начало и конец по
// 4 знака в 36-ричной записи), деление пополам.
export function russianAsn(asn) {
  if (!Number.isInteger(asn) || asn <= 0) return false;
  let lo = 0; let hi = RU_ASNS.length / 8 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (asn < parseInt(RU_ASNS.substr(mid * 8, 4), 36)) hi = mid - 1;
    else if (asn > parseInt(RU_ASNS.substr(mid * 8 + 4, 4), 36)) lo = mid + 1;
    else return true;
  }
  return false;
}

// Правило DNS по адресу сети: зарубеж — только если страна известна, не RU и
// сеть не российская. Остальное считается Россией.
export function classifyByAddress(network) {
  if (network?.status !== 'identified' || !network.countryCode) return {verdict: 'ru', reason: 'country_unknown'};
  if (network.countryCode === 'RU') return {verdict: 'ru', reason: 'country_ru'};
  if (russianAsn(network.asn)) return {verdict: 'ru', reason: 'asn_ru'};
  return {verdict: 'abroad', reason: 'country_abroad'};
}

function entryInfo(observation) {
  const data = observation.body;
  delete observation.body;
  const ok = observation.outcome === 'response_received' && observation.httpStatus === 200 && data?.schemaVersion === 1;
  return {reachable: ok, entryAddress: ok && typeof data.entry?.address === 'string' ? data.entry.address : null,
    seenIp: ok && typeof data.ip === 'string' ? data.ip : null,
    seenCountryCode: ok && /^[A-Z]{2}$/.test(data.countryCode) ? data.countryCode : null,
    seenAsn: ok && Number.isInteger(data.asn) ? data.asn : null,
    seenProvider: ok && typeof data.provider === 'string' ? data.provider.slice(0, 200) : null,
    node: ok && typeof data.node === 'string' ? data.node.slice(0, 120) : null, observation};
}

export async function checkEntries(reportId, options = {}) {
  return Promise.all(ENTRIES.map(async entry => ({...entry,
    ...entryInfo(await measure(entry.url, reportId + '.entry-' + entry.id + '.1', {...options, mode: 'cors', readJson: true}))})));
}

export async function dnsDecision(reportId, options = {}) {
  const info = entryInfo(await measure(GEO_PROBE_URL, reportId + '.geo-probe.1', {...options, mode: 'cors', readJson: true}));
  const verdict = !info.reachable ? 'failed' : ENTRY_SIGNATURES.ru.includes(info.entryAddress) ? 'ru' :
    ENTRY_SIGNATURES.abroad.includes(info.entryAddress) ? 'abroad' : 'unknown';
  return {verdict, ...info};
}

export const LIMITATIONS = Object.freeze([
  'Cross-origin opaque responses hide HTTP status, response body and redirect destination; receiving one does not prove application health.',
  'Browser fetch errors do not distinguish DNS, TCP reset, TLS, local filtering or provider blocking.',
  'Browser APIs do not expose resolved destination IPs or intermediate hops. Resource Timing may hide DNS/TCP/TLS durations without Timing-Allow-Origin.',
  'Two samples are not a statistically meaningful uptime or packet-loss measurement.',
  'No authenticated panel flows, page assets, WebSocket or tenant SSR/runtime applications are exercised.',
  'Client and server routes can be asymmetric. MTR from the client does not measure the reverse route.',
  'GeoIP/ASN identify the observed egress network approximately, not necessarily the retail ISP or physical location. VPN/proxy may change it.',
  'Each entry is measured over one browser connection; the balancer spreads connections, not requests, so one run shows one Edge node per entry.',
  'Egress IP is observed at the diagnostic host. Split VPN/proxy routing may use different egress networks for other targets.',
  'No browser-only test can report failures from clients unable to load this diagnostic site.',
  'The DNS verdict reflects the resolver this browser used at the time of the check; another device, VPN state or resolver may get a different entry. Resolver answers are cached for up to 10 seconds.'
]);

export function clientCommands() {
  return TARGETS.map(t => {
    const host = new URL(t.url).hostname;
    return {host, executed: false,
      dns: `nslookup -type=A ${host}; nslookup -type=AAAA ${host}`,
      httpTrace: `curl -v --connect-timeout 10 --max-time 20 --output layero-${t.id}.html ${t.url} 2> layero-${t.id}-https.txt`,
      command: `mtr -4 -T -P 443 -r -w -n -z -c 30 ${host} > layero-${t.id}-mtr.txt`};
  });
}

export function getLaunchCommands() {
  return LAUNCH_COMMANDS;
}

function errorInfo(error, expired) {
  return {name: String(error?.name || 'Error'), message: String(error?.message || error),
    category: expired ? 'timeout' : 'browser_network_unspecified'};
}

// Durations are milliseconds, wall-clock timestamps are UTC; phases are never invented.
function resourceTiming(url, perf) {
  const entry = perf.getEntriesByName?.(url)?.at(-1);
  if (!entry) return {available: false, reason: 'not_available_at_response_headers'};
  const exposed = entry.requestStart > 0;
  return {
    available: true, phasesExposed: exposed,
    durationMs: entry.duration,
    nextHopProtocol: entry.nextHopProtocol || null,
    dnsMs: exposed ? entry.domainLookupEnd - entry.domainLookupStart : null,
    connectMs: exposed ? entry.connectEnd - entry.connectStart : null,
    tlsMs: exposed && entry.secureConnectionStart > 0 ? entry.connectEnd - entry.secureConnectionStart : null,
    requestToFirstByteMs: exposed ? entry.responseStart - entry.requestStart : null,
    reason: exposed ? null : 'cross_origin_timing_not_exposed'
  };
}

export async function measure(url, requestId, options = {}) {
  const {fetchFn = globalThis.fetch, perf = globalThis.performance,
    timeoutMs = TIMEOUT_MS, mode = 'no-cors', readJson = false} = options;
  const requestedUrl = new URL(url);
  requestedUrl.searchParams.set('_layero_diagnostic', requestId);
  const controller = new AbortController();
  const startedAt = new Date().toISOString();
  const start = perf.now();
  let expired = false;
  let response;
  const timer = setTimeout(() => { expired = true; controller.abort(); }, timeoutMs);
  try {
    response = await fetchFn(requestedUrl.href, {
      method: 'GET', mode, credentials: 'omit', cache: 'no-store', redirect: 'follow',
      referrerPolicy: 'no-referrer', signal: controller.signal
    });
    const headersMs = Math.round(perf.now() - start);
    const opaque = response.type === 'opaque' || response.type === 'opaqueredirect';
    const body = readJson && !opaque ? await response.json() : undefined;
    return {requestId, requestedUrl: requestedUrl.href, startedAt, finishedAt: new Date().toISOString(),
      durationMs: Math.round(perf.now() - start), responseHeadersMs: headersMs,
      outcome: 'response_received', httpStatus: opaque ? null : response.status,
      responseType: response.type, statusVisible: !opaque,
      finalUrl: opaque ? null : response.url || null,
      redirected: opaque ? null : response.redirected ?? null,
      timing: resourceTiming(requestedUrl.href, perf), ...(readJson ? {body} : {})};
  } catch (error) {
    return {requestId, requestedUrl: requestedUrl.href, startedAt, finishedAt: new Date().toISOString(),
      durationMs: Math.round(perf.now() - start), outcome: expired ? 'timeout' : response ? 'invalid_response' : 'fetch_failed',
      httpStatus: response && response.type !== 'opaque' ? response.status : null,
      error: {...errorInfo(error, expired), category: expired ? 'timeout' : response ? 'response_body_invalid' : 'browser_network_unspecified'},
      timing: resourceTiming(requestedUrl.href, perf)};
  } finally { clearTimeout(timer); }
}

export async function identifyNetwork(reportId, options = {}) {
  const result = await measure(new URL(NETWORK_PATH, options.origin || globalThis.location.origin).href,
    reportId + '.network.1', {...options, mode: 'same-origin', readJson: true, timeoutMs: 5000});
  const data = result.body;
  const valid = result.outcome === 'response_received' && result.httpStatus === 200 && data?.schemaVersion === 1 &&
    typeof data.ip === 'string' && /^[0-9a-f:.]+$/i.test(data.ip) &&
    data.scope === 'egress_network' && data.source === 'DB-IP Lite';
  delete result.body;
  if (!valid) return {status: 'unknown', observation: result, reason: 'network_identification_unavailable'};
  return {status: 'identified', ip: data.ip, countryCode: /^[A-Z]{2}$/.test(data.countryCode) ? data.countryCode : null,
    asn: Number.isInteger(data.asn) && data.asn > 0 && data.asn <= 4294967295 ? data.asn : null,
    provider: typeof data.provider === 'string' ? data.provider.slice(0, 200) : null,
    scope: data.scope, source: data.source, attributionUrl: 'https://db-ip.com',
    accuracy: 'approximate', observedAt: data.observedAt, edgeRequestId: data.requestId,
    entryAddress: typeof data.entry?.address === 'string' ? data.entry.address : null,
    node: typeof data.node === 'string' ? data.node.slice(0, 120) : null,
    observation: result};
}

export function isLayeroOrigin(origin) {
  try { return /(^|\.)layero\.(app|dev)$/.test(new URL(origin).hostname); } catch (_) { return false; }
}

function networkFromEntries(entries) {
  const e = entries.find(x => x.reachable && x.seenIp && /^[0-9a-f:.]+$/i.test(x.seenIp));
  if (!e) return {status: 'unknown', reason: 'no_entry_reachable'};
  return {status: 'identified', ip: e.seenIp, countryCode: e.seenCountryCode, asn: e.seenAsn, provider: e.seenProvider,
    scope: 'egress_network', source: 'DB-IP Lite', attributionUrl: 'https://db-ip.com', accuracy: 'approximate',
    observedVia: 'entry-' + e.id, entryAddress: null, node: null};
}

export function checkState(check) {
  const count = check.attempts.filter(a => a.outcome === 'response_received').length;
  const unhealthy = check.health?.verified === true && check.health.healthy !== true;
  const visibleError = check.attempts.some(a => a.httpStatus !== null && a.httpStatus >= 400);
  const healthUnknown = check.health && !check.health.verified;
  return {answered: count, tone: unhealthy || visibleError || count === 0 ? 'negative' : count < ATTEMPTS || healthUnknown ? 'warning' : 'success',
    label: unhealthy ? 'API: ошибка ответа' : visibleError ? 'Ответ с HTTP-ошибкой' :
      check.health?.healthy === true ? 'API исправен · HTTP 200' :
      healthUnknown && count === ATTEMPTS ? 'API: статус не прочитан' :
      count === ATTEMPTS ? 'Ответы получены' : count > 0 ? 'Ответ получен один раз' : 'Ответы не получены'};
}

export function summarize(checks, entries = []) {
  // Страница открылась (значит, интернет есть), а ни один вход Layero — нет.
  if (entries.length && entries.every(e => !e.reachable)) return {code: 'entries_blocked',
    text: 'Интернет работает — эта страница открылась. Но все входы Layero закрыты. Нажмите «Поделиться» и запустите команду ниже.'};
  const problems = checks.filter(c => checkState(c).tone !== 'success');
  if (!problems.length) return {code: 'no_failure_reproduced',
    text: 'Всё отвечает. Сбой не повторился.'};
  if (problems.length === checks.length && checks.every(c => checkState(c).answered === 0)) return {code: 'nothing_answered',
    text: 'Не ответил ни один сервис. Проверьте интернет, VPN или прокси.'};
  return {code: 'failures_observed',
    text: 'Часть сервисов не ответила. Скопируйте сводку и отправьте в поддержку.'};
}

export async function diagnose(options = {}) {
  const {client = globalThis.navigator, origin = globalThis.location.origin,
    perf = globalThis.performance, onCheck = () => {}} = options;
  const id = options.reportId || globalThis.crypto.randomUUID();
  const start = perf.now();
  const report = {schemaVersion: 1, tool: 'Layero Diagnostics', toolVersion: VERSION,
    reportId: id, startedAt: new Date().toISOString(), client: {
      userAgent: client.userAgent, onlineHint: client.onLine, language: client.language || null,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, diagnosticOrigin: origin,
      networkHint: client.connection ? {effectiveType: client.connection.effectiveType || null,
        rttMs: client.connection.rtt ?? null, downlinkMbps: client.connection.downlink ?? null,
        saveData: client.connection.saveData ?? null, reliability: 'browser_estimate_not_measurement'} : null
    }, measurements: {attemptsPerTarget: ATTEMPTS, timeoutMs: TIMEOUT_MS,
      transport: 'browser_fetch', credentials: 'omit', reachabilityScope: 'http_response_headers'},
    limitations: [...LIMITATIONS]};
  const dnsPromise = dnsDecision(id, {...options, perf});
  const entriesPromise = checkEntries(id, {...options, perf});
  // Копия страницы вне домена Layero (GitHub Pages) своей ручки не имеет:
  // сведения о сети берутся из ответа первого открывшегося входа.
  const networkPromise = isLayeroOrigin(origin) ? identifyNetwork(id, {...options, origin, perf})
    : entriesPromise.then(networkFromEntries);
  report.checks = await Promise.all(TARGETS.map(async target => {
    const attempts = [];
    const healthPromise = target.id === 'api' ? measure(target.url, id + '.api-health.1',
      {...options, perf, mode: 'cors', readJson: true}) : null;
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      attempts.push(await measure(target.url, id + '.' + target.id + '.' + attempt, {...options, perf}));
    }
    const check = {...target, attempts, resolvedAddresses: null, resolvedAddressesReason: 'not_exposed_by_browser'};
    if (healthPromise) {
      const observation = await healthPromise;
      const verified = Number.isInteger(observation.httpStatus) && observation.httpStatus > 0;
      check.health = {verified, healthy: verified ? observation.httpStatus === 200 &&
        observation.body?.status === 'ok' && observation.body?.service === 'layero-api' : null,
        body: verified ? {status: observation.body?.status ?? null, service: observation.body?.service ?? null} : null,
        observation: {...observation, body: undefined}};
    }
    onCheck(check);
    return check;
  }));
  report.network = await networkPromise;
  report.recognition = {byAddress: classifyByAddress(report.network), byDns: await dnsPromise,
    rule: 'Abroad only when the country is known, not RU and the ASN is not in the RIPE NCC list for Russia; everything else is treated as Russia.'};
  report.entries = await entriesPromise;
  report.summary = summarize(report.checks, report.entries);
  report.finishedAt = new Date().toISOString();
  report.durationMs = Math.round(perf.now() - start);
  report.correlation = {queryParameter: '_layero_diagnostic',
    requestIdFormat: 'reportId.target.attempt', edgeLogFields: ['uri in JSON access logs', 'request line in text access logs'],
    note: 'Correlation with HTTP access logs, not distributed tracing. CDN-cached docs may not reach edge. Absence from logs does not prove provider blocking.'};
  report.routing = {status: 'not_measured_in_browser', forwardHops: null, reverseHops: null,
    clientCommands: clientCommands(), launchCommands: {...getLaunchCommands(origin), executed: false},
    requirements: 'Second-stage commands, not executed by this tool. Requires nslookup, curl and MTR on the affected device (HTTP command shown for macOS/Linux). Run during failure with the same VPN/proxy state. Save resolved destination IPs and timestamps; MTR IPv4 example must be repeated for each affected resolved IP and IPv6 if used. Repeat without VPN separately. TCP MTR does not test TLS SNI/HTTP and may bypass an application proxy.',
    reverseProbeTarget: report.network.ip || null,
    reverseProbeNote: 'Operator probe to diagnostic-host egress IP is separate; split routing, NAT/VPN/firewall may prevent replies and it may not reproduce the actual return path.',
    interpretation: 'Loss on an intermediate hop alone is not evidence of forwarded packet loss; routers may rate-limit probe replies.'};
  return report;
}

export function serializeReport(report) { return JSON.stringify(report, null, 2) + '\n'; }

const VERDICT_TEXT = {ru: 'Россия', abroad: 'не Россия', failed: 'не удалось', unknown: 'не определено'};
const REASON_TEXT = {country_unknown: 'страна не определена — считаем Россией', country_ru: 'страна сети — Россия',
  asn_ru: 'сеть зарегистрирована в России', country_abroad: 'страна сети не Россия, сеть не российская'};
export const verdictText = verdict => VERDICT_TEXT[verdict] || VERDICT_TEXT.unknown;
export const reasonText = reason => REASON_TEXT[reason] || '';

// Короткая сводка простым текстом — вставить в письмо или чат поддержки.
export function textSummary(report) {
  const n = report.network || {};
  const lines = ['Диагностика Layero ' + report.toolVersion, 'Проверка: ' + report.reportId, 'Время (UTC): ' + report.finishedAt,
    'Браузер: ' + [report.client?.timezone || report.context?.timezone, report.client?.language || report.context?.language].filter(Boolean).join(' · ') +
      ' · страница: ' + (hostOf(report.client?.diagnosticOrigin) || report.context?.openedOn || '?'),
    'Сеть: ' + [n.countryCode || 'страна ?', n.asn ? 'AS' + n.asn : 'ASN ?', n.provider || '', n.ip || 'IP ?'].filter(Boolean).join(' · '),
    'По адресу: ' + verdictText(report.recognition.byAddress.verdict) + ' (' + reasonText(report.recognition.byAddress.reason) + ')',
    'По DNS: ' + verdictText(report.recognition.byDns.verdict) + (report.recognition.byDns.reachable ? ' → ' + entryName(report.recognition.byDns.entryAddress) + ' → ' + (report.recognition.byDns.node || 'узел ?') : ''),
    'Эта страница: ' + entryName(n.entryAddress) + ' → ' + (n.node || 'узел ?'),
    'Входы:'];
  for (const e of report.entries) lines.push('  ' + e.name + ' ' + e.address + ': ' +
    (e.reachable ? 'открывается, ' + e.observation.durationMs + ' мс, ' + (e.node || 'узел ?') : 'не открывается (' + e.observation.outcome + ')'));
  lines.push('Сервисы:');
  for (const c of report.checks) lines.push('  ' + c.name + ': ' + checkState(c).label + ', ' + c.attempts.map(a => a.durationMs + ' мс').join(' / '));
  lines.push('Итог: ' + report.summary.text);
  return lines.join('\n') + '\n';
}

// ── Поделиться результатом ───────────────────────────────────────────────
// Короткий снимок проверки сжимается и кладётся в ссылку после «#»: эту часть
// адреса браузер на сервер не отправляет, на стороне Layero ничего не хранится.
// Ссылку открывает поддержка и видит те же маршрут, входы и сервисы. Снимок из
// ссылки — чужие данные: при чтении всё проверяется и обрезается.
export const SHARE_PREFIX = '#r=';
const OUTCOMES = {response_received: 'r', timeout: 't', fetch_failed: 'f', invalid_response: 'i'};
const OUTCOME_BACK = Object.fromEntries(Object.entries(OUTCOMES).map(([k, v]) => [v, k]));

export function shareSnapshot(report) {
  const n = report.network || {};
  const d = report.recognition.byDns;
  return {v: 1, id: report.reportId, at: report.finishedAt, tool: report.toolVersion,
    net: [n.ip || null, n.countryCode || null, n.asn || null, n.provider || null, n.entryAddress || null, n.node || null],
    addr: [report.recognition.byAddress.verdict, report.recognition.byAddress.reason],
    dns: [d.verdict, d.entryAddress, d.node, d.reachable ? d.observation.durationMs : null],
    entries: report.entries.map(e => [e.id, e.reachable ? 1 : 0, e.observation.durationMs, e.node, e.observation.outcome === 'timeout' ? 1 : 0]),
    checks: report.checks.map(c => [c.id, c.attempts.map(a => [OUTCOMES[a.outcome] || 'f', a.durationMs, a.httpStatus ?? null]),
      c.health ? [c.health.verified ? 1 : 0, c.health.healthy === true ? 1 : c.health.healthy === false ? 0 : null] : null]),
    sum: report.summary.code,
    // Часовой пояс и язык подсказывают регион, когда все входы закрыты и IP неизвестен.
    ctx: [report.client?.timezone || null, report.client?.language || null, hostOf(report.client?.diagnosticOrigin)]};
}

function hostOf(origin) { try { return new URL(origin).hostname; } catch (_) { return null; } }

function toBase64Url(bytes) {
  let s = ''; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromBase64Url(text) {
  const s = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(s, c => c.charCodeAt(0));
}
async function pipe(bytes, stream) {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
}

export async function encodeShare(report) {
  const json = new TextEncoder().encode(JSON.stringify(shareSnapshot(report)));
  // «z» — сжато, «j» — как есть (старый браузер без CompressionStream).
  if (typeof CompressionStream === 'function') return 'z' + toBase64Url(await pipe(json, new CompressionStream('deflate-raw')));
  return 'j' + toBase64Url(json);
}

const str = (v, max) => typeof v === 'string' && v.length <= max ? v : null;
const int = (v, max) => Number.isInteger(v) && v >= 0 && v <= max ? v : null;
const oneOf = (v, list) => list.includes(v) ? v : null;

export async function decodeShare(fragment) {
  if (typeof fragment !== 'string' || !fragment.startsWith(SHARE_PREFIX) || fragment.length > 12000) return null;
  try {
    const kind = fragment[SHARE_PREFIX.length]; const body = fromBase64Url(fragment.slice(SHARE_PREFIX.length + 1));
    const bytes = kind === 'z' ? await pipe(body, new DecompressionStream('deflate-raw')) : kind === 'j' ? body : null;
    if (!bytes || bytes.length > 20000) return null;
    const s = JSON.parse(new TextDecoder().decode(bytes));
    if (s?.v !== 1 || !Array.isArray(s.net) || !Array.isArray(s.dns) || !Array.isArray(s.entries) || !Array.isArray(s.checks)) return null;
    const ip = str(s.net[0], 45);
    const network = {status: ip ? 'identified' : 'unknown', ip: ip && /^[0-9a-f:.]+$/i.test(ip) ? ip : null,
      countryCode: /^[A-Z]{2}$/.test(s.net[1]) ? s.net[1] : null, asn: int(s.net[2], 4294967295),
      provider: str(s.net[3], 200), entryAddress: str(s.net[4], 45), node: str(s.net[5], 120)};
    const dnsVerdict = oneOf(s.dns[0], ['ru', 'abroad', 'failed', 'unknown']) || 'unknown';
    const byDns = {verdict: dnsVerdict, reachable: dnsVerdict !== 'failed', entryAddress: str(s.dns[1], 45), node: str(s.dns[2], 120),
      observation: {durationMs: int(s.dns[3], 600000) ?? 0}};
    const byAddress = {verdict: oneOf(s.addr?.[0], ['ru', 'abroad']) || 'ru', reason: oneOf(s.addr?.[1], Object.keys(REASON_TEXT)) || 'country_unknown'};
    const entries = ENTRIES.map(entry => {
      const row = s.entries.find(e => Array.isArray(e) && e[0] === entry.id) || [];
      return {...entry, reachable: row[1] === 1, node: str(row[3], 120),
        observation: {durationMs: int(row[2], 600000) ?? 0, outcome: row[1] === 1 ? 'response_received' : row[4] === 1 ? 'timeout' : 'fetch_failed'}};
    });
    const checks = TARGETS.map(target => {
      const row = s.checks.find(c => Array.isArray(c) && c[0] === target.id) || [target.id, [], null];
      const attempts = (Array.isArray(row[1]) ? row[1] : []).slice(0, ATTEMPTS).map(a => ({
        outcome: OUTCOME_BACK[a?.[0]] || 'fetch_failed', durationMs: int(a?.[1], 600000) ?? 0, httpStatus: int(a?.[2], 999)}));
      const health = Array.isArray(row[2]) ? {verified: row[2][0] === 1, healthy: row[2][1] === 1 ? true : row[2][1] === 0 ? false : null} : undefined;
      return {...target, attempts, ...(health ? {health} : {})};
    });
    const ctx = Array.isArray(s.ctx) ? s.ctx : [];
    const context = {timezone: typeof ctx[0] === 'string' && /^[A-Za-z0-9_+\/-]{1,64}$/.test(ctx[0]) ? ctx[0] : null,
      language: typeof ctx[1] === 'string' && /^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8}){0,3}$/.test(ctx[1]) ? ctx[1] : null,
      openedOn: typeof ctx[2] === 'string' && /^[a-z0-9.-]{1,100}$/.test(ctx[2]) ? ctx[2] : null};
    return {shared: true, reportId: str(s.id, 64) || '?', finishedAt: str(s.at, 40) || '', toolVersion: str(s.tool, 20) || '?',
      network, recognition: {byAddress, byDns}, entries, checks, context, summary: summarize(checks, entries)};
  } catch (_) {
    return null;
  }
}
