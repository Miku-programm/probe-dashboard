package main

import "strings"

// 面板使用的命名查询（要求 v2node probe_events 表为 schema_version 4：旧表按顺序执行 v2node 的 migrations/002_v2.sql、003_v3.sql、004_quic.sql 中尚未执行的部分）。
//
// 占位符：
//   - {T}  表名
//   - {W}  公共时间/节点条件
//   - {F}  连接记录去重子查询：每个 flow_id 只取 revision 最大的一行；v1 旧行（flow_id 为空）各自成行
//   - {NA} “没有关联到 accepted”的条件：auth 不是 accepted 也不是 not_applicable
//     （包括 v2 的 unknown / rejected 和 v1 的 none）。这只表示没观察到认证成功，不等于主动探测。
//   - {TLSOK} 只有完整、无冲突的 ClientHello 的 TLS 字段才参与比较，与 v2node probelog/README「可比较样本的统一门槛」一致：
//     v3 行要求 tls_state = complete（ClientHello 内有重叠冲突的是 conflict）；v2 行另外排除 reasm_flags 含 conflict 的行
//     （v2 没有区分冲突落在哪里，保守排除）；v1 旧行没有 tls_state，按原样保留
//
// 其余 {name:Type} 是 ClickHouse 查询参数，由 HTTP 接口以 param_name 传入。
const flowsLatest = `(SELECT * FROM {T}
  WHERE {W} AND kind IN ('tcp_flow', 'udp_flow')
  ORDER BY revision DESC, emitted_at DESC
  LIMIT 1 BY if(flow_id = '', concat('v1|', toString(ts), '|', src_ip, '|', toString(src_port), '|', dst_ip, '|', toString(dst_port)), flow_id))`

const (
	noAuth = `auth NOT IN ('accepted', 'not_applicable')`
	tlsOK  = `(schema_version < 2 OR (tls_state = 'complete' AND (schema_version >= 3 OR position(reasm_flags, 'conflict') = 0)))`
)

// expandQuery 展开占位符。{F} 内含 {T} 和 {W}，所以先展开
func expandQuery(q, table, where string) string {
	q = strings.ReplaceAll(q, "{F}", flowsLatest)
	q = strings.ReplaceAll(q, "{NA}", noAuth)
	q = strings.ReplaceAll(q, "{TLSOK}", tlsOK)
	q = strings.ReplaceAll(q, "{T}", table)
	return strings.ReplaceAll(q, "{W}", where)
}

var queries = map[string]string{
	"nodes": `SELECT DISTINCT node FROM {T} WHERE ts > now() - INTERVAL 30 DAY ORDER BY node`,

	"overview": `WITH f AS {F}
SELECT
  (SELECT count() FROM {T} WHERE {W}) AS events,
  (SELECT uniqExact(src_ip) FROM {T} WHERE {W} AND src_ip != '') AS sources,
  (SELECT count() FROM {T} WHERE {W} AND kind = 'syn') AS closed_syn,
  (SELECT uniqExact(src_ip) FROM {T} WHERE {W} AND kind = 'syn') AS scanners,
  (SELECT count() FROM f WHERE kind = 'tcp_flow' AND port_state = 'node' AND {NA}) AS unauth_node_flows,
  (SELECT uniqExact(src_ip) FROM f WHERE kind = 'tcp_flow' AND port_state = 'node' AND {NA}) AS unauth_sources,
  (SELECT count() FROM f WHERE kind = 'tcp_flow' AND auth = 'accepted') AS authed_flows,
  (SELECT count() FROM f WHERE kind = 'tcp_flow' AND auth_assoc = 'ambiguous') AS ambiguous_flows,
  (SELECT count() FROM {T} WHERE {W} AND kind = 'xray_access' AND xray_status = 'rejected') AS rejected,
  (SELECT count() FROM {T} WHERE {W} AND kind = 'xray_log' AND positionCaseInsensitive(message, 'reality') > 0) AS reality_logs,
  (SELECT count() FROM {T} WHERE {W} AND kind = 'syn' AND src_geo = 'cn')
    + (SELECT count() FROM f WHERE src_geo = 'cn' AND {NA}) AS cn_unauth,
  (SELECT count() FROM f WHERE kind = 'udp_flow' AND port_state = 'closed') AS udp_closed`,

	"timeline": `SELECT t, sum(scan_syn) AS scan_syn, sum(unauth_node) AS unauth_node, sum(unauth_other) AS unauth_other,
  sum(authed) AS authed, sum(udp) AS udp, sum(rejected) AS rejected, sum(icmp) AS icmp
FROM (
  SELECT toStartOfInterval(ts, toIntervalSecond({bucket:UInt32})) AS t,
    countIf(kind = 'syn') AS scan_syn, toUInt64(0) AS unauth_node, toUInt64(0) AS unauth_other, toUInt64(0) AS authed,
    toUInt64(0) AS udp, countIf(kind = 'xray_access' AND xray_status = 'rejected') AS rejected, countIf(kind = 'icmp') AS icmp
  FROM {T} WHERE {W} AND kind IN ('syn', 'xray_access', 'icmp')
  GROUP BY t
  UNION ALL
  SELECT toStartOfInterval(ts, toIntervalSecond({bucket:UInt32})) AS t,
    toUInt64(0), countIf(kind = 'tcp_flow' AND port_state = 'node' AND {NA}), countIf(kind = 'tcp_flow' AND port_state = 'listen'),
    countIf(kind = 'tcp_flow' AND auth = 'accepted'), countIf(kind = 'udp_flow'), toUInt64(0), toUInt64(0)
  FROM {F}
  GROUP BY t
)
GROUP BY t ORDER BY t`,

	"probes": `SELECT ts, node, flow_id, record_type, src_ip, src_port, src_geo, dst_ip, dst_port, node_type, obs_mode,
  ttl, ip_id, tcp_win, tcp_opts, ts_val, syn_retrans, first_data_ms, first_resp_ms,
  payload_len, payload_truncated, round(entropy, 2) AS entropy, round(printable, 2) AS printable, payload_head,
  prefix_len, prefix_hash, prefix_stop, reasm_flags, tls_state, tls_ver, tls_sni, tls_alpn, ja4, tls_sid_len, resp_records,
  flow_ms, flow_pkts, flow_bytes, flow_end, close_by, handshake, hs_flags, auth, auth_assoc, schema_version
FROM {F}
WHERE kind = 'tcp_flow' AND port_state = 'node' AND {NA} AND position(tcp_flags, 'S') > 0
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	"probe_sources": `SELECT src_ip, any(src_geo) AS geo,
  countIf({NA}) AS unauth, countIf(auth = 'accepted') AS authed, countIf(auth_assoc = 'ambiguous') AS ambiguous,
  uniqExact(dst_port) AS ports, groupUniqArray(4)(node) AS nodes,
  groupUniqArrayIf(4)(tls_sni, tls_sni != '' AND {NA} AND {TLSOK}) AS snis,
  groupUniqArrayIf(6)(payload_len, {NA}) AS lens,
  countIf({NA} AND payload_len = 0) AS no_data,
  min(ts) AS first_seen, max(ts) AS last_seen,
  topK(1)(ttl)[1] AS ttl, topK(1)(tcp_opts)[1] AS opts
FROM {F}
WHERE kind = 'tcp_flow' AND port_state = 'node' AND position(tcp_flags, 'S') > 0
GROUP BY src_ip HAVING unauth > 0
ORDER BY authed = 0 DESC, unauth DESC LIMIT {limit:UInt32}`,

	"scanners": `SELECT src_ip, any(src_geo) AS geo, count() AS syns, uniqExact(dst_port) AS ports,
  min(dst_port) AS min_port, max(dst_port) AS max_port, min(ts) AS first_seen, max(ts) AS last_seen,
  topK(1)(ttl)[1] AS ttl, topK(1)(tcp_win)[1] AS win, topK(1)(tcp_opts)[1] AS opts, groupUniqArray(4)(node) AS nodes
FROM {T} WHERE {W} AND kind = 'syn'
GROUP BY src_ip ORDER BY ports DESC, syns DESC LIMIT {limit:UInt32}`,

	// v3 行用固定策略的重组前缀（prefix_len + prefix_hash，覆盖范围见 prefix_stop），排除内容冲突的流。
	// v2 行的前缀范围取决于 TCP 分段，单独分组、不与 v3 混合；v1 旧行退回首段哈希。短前缀区分度低，看 len 列分层。
	"replays": `SELECT
  multiIf(schema_version >= 3, concat('v3:', toString(prefix_len), ':', prefix_hash),
          schema_version = 2, concat('v2:', toString(prefix_len), ':', prefix_hash),
          concat('v1:', payload_hash)) AS match_key,
  count() AS n, uniqExact(src_ip) AS ips, groupUniqArray(6)(src_ip) AS sample_ips,
  min(ts) AS first_seen, max(ts) AS last_seen, dateDiff('second', min(ts), max(ts)) AS span_s,
  any(if(schema_version >= 2, prefix_len, payload_len)) AS len, any(tls_sni) AS sni, any(dst_port) AS port,
  argMin(src_ip, ts) AS first_src, argMin(auth, ts) AS first_auth, countIf(auth = 'accepted') AS authed,
  groupUniqArray(4)(src_geo) AS geos, groupUniqArray(4)(prefix_stop) AS stops
FROM {F}
WHERE if(schema_version >= 2, prefix_hash != '' AND position(reasm_flags, 'conflict') = 0, payload_hash != '')
GROUP BY match_key HAVING ips > 1
ORDER BY n DESC LIMIT {limit:UInt32}`,

	"fp_probe": `SELECT ttl, tcp_win, tcp_opts, mss, if({TLSOK}, ja4, '') AS ja4, count() AS n, uniqExact(src_ip) AS ips,
  groupUniqArray(5)(src_ip) AS sample_ips, countIf(src_geo = 'cn') AS cn,
  round(avg(payload_len), 1) AS avg_len, round(avgIf(first_data_ms, first_data_ms >= 0), 1) AS avg_first_ms
FROM {F}
WHERE kind = 'tcp_flow' AND port_state = 'node' AND {NA} AND position(tcp_flags, 'S') > 0
GROUP BY ttl, tcp_win, tcp_opts, mss, ja4
ORDER BY ips DESC, n DESC LIMIT {limit:UInt32}`,

	"fp_scan": `SELECT ttl, tcp_win, tcp_opts, mss, ip_df, count() AS n, uniqExact(src_ip) AS ips,
  uniqExact(dst_port) AS ports, groupUniqArray(5)(src_ip) AS sample_ips, countIf(src_geo = 'cn') AS cn
FROM {T} WHERE {W} AND kind = 'syn'
GROUP BY ttl, tcp_win, tcp_opts, mss, ip_df
ORDER BY ips DESC, n DESC LIMIT {limit:UInt32}`,

	"payload_len": `SELECT payload_len, count() AS n, uniqExact(src_ip) AS ips,
  round(avg(entropy), 2) AS entropy, countIf(tls_state = 'complete' AND {TLSOK}) AS tls, countIf(payload_truncated = 1) AS truncated
FROM {F}
WHERE kind = 'tcp_flow' AND port_state = 'node' AND {NA} AND position(tcp_flags, 'S') > 0
GROUP BY payload_len ORDER BY payload_len`,

	"reaction": `SELECT
  multiIf(s < 0, '无用户连接', s < 1, '<1s', s < 10, '1-10s', s < 60, '10-60s', s < 600, '1-10m', s < 3600, '10-60m', s < 86400, '1-24h', '>24h') AS bucket,
  min(s) AS sort_key, count() AS n, uniqExact(src_ip) AS ips
FROM (
  SELECT p.src_ip AS src_ip,
    if(a.ts = toDateTime64(0, 3, 'UTC'), -1, dateDiff('millisecond', a.ts, p.ts) / 1000) AS s
  FROM (
    SELECT ts, node, dst_port, src_ip FROM {F}
    WHERE kind = 'tcp_flow' AND port_state = 'node' AND {NA} AND position(tcp_flags, 'S') > 0
  ) AS p
  ASOF LEFT JOIN (
    SELECT ts, node, dst_port FROM {F} WHERE kind = 'tcp_flow' AND auth = 'accepted'
  ) AS a
  ON p.node = a.node AND p.dst_port = a.dst_port AND p.ts >= a.ts
)
GROUP BY bucket ORDER BY sort_key`,

	"sni": `SELECT tls_sni, countIf(auth = 'accepted') AS authed, countIf({NA}) AS unauth,
  uniqExactIf(src_ip, {NA}) AS unauth_ips, groupUniqArray(3)(ja4) AS ja4s
FROM {F} WHERE kind = 'tcp_flow' AND tls_sni != '' AND {TLSOK}
GROUP BY tls_sni ORDER BY unauth DESC, authed DESC LIMIT {limit:UInt32}`,

	"ports": `SELECT dst_port, proto, any(port_state) AS state, any(node_type) AS node_type,
  sum(syn) AS syn, sum(unauth) AS unauth, sum(authed) AS authed, uniqExactMerge(ips_state) AS ips
FROM (
  SELECT dst_port, proto, port_state, node_type, count() AS syn, toUInt64(0) AS unauth, toUInt64(0) AS authed,
    uniqExactState(src_ip) AS ips_state
  FROM {T} WHERE {W} AND kind = 'syn' GROUP BY dst_port, proto, port_state, node_type
  UNION ALL
  SELECT dst_port, proto, port_state, node_type, toUInt64(0), countIf({NA}), countIf(auth = 'accepted'), uniqExactState(src_ip)
  FROM {F} GROUP BY dst_port, proto, port_state, node_type
)
GROUP BY dst_port, proto ORDER BY syn + unauth DESC LIMIT {limit:UInt32}`,

	"geo": `SELECT geo, sum(syn) AS syn, sum(unauth) AS unauth, sum(authed) AS authed, sum(udp) AS udp, uniqExactMerge(ips_state) AS ips
FROM (
  SELECT if(src_geo = '', '未知', src_geo) AS geo, countIf(kind = 'syn') AS syn, toUInt64(0) AS unauth, toUInt64(0) AS authed,
    toUInt64(0) AS udp, uniqExactState(src_ip) AS ips_state
  FROM {T} WHERE {W} AND src_ip != '' AND kind IN ('syn', 'icmp') GROUP BY geo
  UNION ALL
  SELECT if(src_geo = '', '未知', src_geo), toUInt64(0), countIf(kind = 'tcp_flow' AND {NA}), countIf(kind = 'tcp_flow' AND auth = 'accepted'),
    countIf(kind = 'udp_flow'), uniqExactState(src_ip)
  FROM {F} GROUP BY src_geo
)
GROUP BY geo ORDER BY ips DESC`,

	// QUIC 字段只有 v4 行才有；gfw_inspects 对应论文中 GFW 只检查源端口 > 目的端口的规则
	"udp": `SELECT ts, node, flow_id, src_ip, src_port, src_geo, dst_port, port_state, node_type, ttl,
  payload_len, payload_truncated, round(entropy, 2) AS entropy, payload_head, payload_hash, quic_ver,
  quic_initial, if({TLSOK}, tls_sni, '') AS tls_sni, if({TLSOK}, ja4, '') AS ja4, quic_sni_first, quic_initials,
  src_port > dst_port AS gfw_inspects,
  flow_ms, flow_pkts, flow_bytes, flow_end, auth, auth_assoc
FROM {F} WHERE kind = 'udp_flow' AND auth != 'accepted'
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	"xray": `SELECT ts, node, kind, src_ip, src_port, src_geo, xray_status, xray_email, xray_target, xray_reason, severity, message
FROM {T}
WHERE {W} AND (kind = 'xray_log' OR (kind = 'xray_access' AND xray_status = 'rejected'))
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	// IP 查询保留同一连接的所有记录（snapshot / final / correction），便于看演变
	"ip": `SELECT ts, node, kind, flow_id, record_type, revision, proto, src_port, dst_ip, dst_port, port_state,
  auth, auth_assoc, flow_end, close_by, handshake, hs_flags, flow_ms, flow_pkts,
  payload_len, round(entropy, 2) AS entropy, tls_state, tls_sni, ja4, prefix_len, prefix_stop, reasm_flags, ttl, tcp_win, tcp_opts, ts_val,
  first_data_ms, payload_head, xray_status, xray_email, xray_target, xray_reason, schema_version
FROM {T} WHERE {W} AND src_ip = {ip:String}
ORDER BY ts DESC, revision DESC LIMIT {limit:UInt32}`,

	"stats": `SELECT node, max(ts) AS last_seen, argMax(message, ts) AS stats
FROM {T} WHERE {W} AND kind = 'stats'
GROUP BY node ORDER BY node`,
}
