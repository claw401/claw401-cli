# init: project structure — Sat Mar  7 13:07:28 +03 2026
# feat: add core config — Sat Mar  7 13:07:28 +03 2026
# feat: wallet address validation — Sat Mar  7 13:07:29 +03 2026
# feat: connect clawbyte security endpoint — Sat Mar  7 13:07:29 +03 2026
# feat: risk score parsing — Sat Mar  7 13:07:29 +03 2026
# feat: openclaw agent integration — Sat Mar  7 13:07:29 +03 2026
# feat: error handling and retries — Sat Mar  7 13:07:29 +03 2026
# chore: update dependencies — Sat Mar  7 13:07:29 +03 2026
# docs: add usage examples — Sat Mar  7 13:07:29 +03 2026
# chore: bump version to 0.1.0 — Sat Mar  7 13:07:29 +03 2026
# feat: add openclaw agent handshake protocol — Sun Mar  8 17:22:30 +03 2026
# feat: implement wallet reputation caching — Sun Mar  8 17:22:30 +03 2026
# feat: batch wallet scanning support — Sun Mar  8 17:22:30 +03 2026
# fix: handle rate limit responses gracefully — Sun Mar  8 17:22:30 +03 2026
# feat: add risk level threshold configuration — Sun Mar  8 17:22:30 +03 2026
# feat: streaming scan results via websocket — Sun Mar  8 17:22:30 +03 2026
# chore: add unit tests for core scanner — Sun Mar  8 17:22:30 +03 2026
# feat: api key authentication middleware — Sun Mar  8 17:22:30 +03 2026
# docs: openclaw integration guide — Sun Mar  8 17:22:30 +03 2026
# chore: bump version to 0.2.0 — Sun Mar  8 17:22:30 +03 2026
# feat: multi-wallet scan endpoint — Sun Mar  8 17:33:13 +03 2026
# feat: add solana mainnet/devnet toggle — Sun Mar  8 17:33:14 +03 2026
# fix: edge case on fresh wallet scoring — Sun Mar  8 17:33:14 +03 2026
# feat: webhook support for scan results — Sun Mar  8 17:33:14 +03 2026
# feat: agent context passing to scanner — Sun Mar  8 17:33:14 +03 2026
# perf: optimize rpc call batching — Sun Mar  8 17:33:14 +03 2026
# feat: add confidence score to risk verdict — Sun Mar  8 17:33:14 +03 2026
# chore: improve error messages — Sun Mar  8 17:33:14 +03 2026
# docs: add sdk quickstart examples — Sun Mar  8 17:33:14 +03 2026
# chore: release v0.3.0 — Sun Mar  8 17:33:14 +03 2026
# feat: pagination for scan history endpoint — Mon Mar  9 14:27:24 +03 2026
# feat: rate limit headers on scan API — Mon Mar  9 14:27:24 +03 2026
# fix: webhook retry backoff for failed deliveries — Mon Mar  9 14:27:24 +03 2026
# feat: filter scans by risk level and timestamp — Mon Mar  9 14:27:24 +03 2026
# perf: cache RPC cluster health checks — Mon Mar  9 14:27:24 +03 2026
# feat: export scan report as JSON — Mon Mar  9 14:27:24 +03 2026
# docs: webhook payload reference — Mon Mar  9 14:27:24 +03 2026
# fix: timezone handling in scan timestamps — Mon Mar  9 14:27:24 +03 2026
# feat: multi-wallet scan endpoint — Tue Mar 10 21:17:44 +03 2026
# feat: add solana mainnet/devnet toggle — Tue Mar 10 21:17:44 +03 2026
# fix: edge case on fresh wallet scoring — Tue Mar 10 21:17:44 +03 2026
# feat: webhook support for scan results — Tue Mar 10 21:17:44 +03 2026
# feat: agent context passing to scanner — Tue Mar 10 21:17:44 +03 2026
# perf: optimize rpc call batching — Tue Mar 10 21:17:44 +03 2026
# feat: add confidence score to risk verdict — Tue Mar 10 21:17:45 +03 2026
# chore: improve error messages — Tue Mar 10 21:17:45 +03 2026
# docs: add sdk quickstart examples — Tue Mar 10 21:17:45 +03 2026
# chore: release v0.3.0 — Tue Mar 10 21:17:45 +03 2026
# feat: add solana mainnet/devnet toggle — Wed Mar 11 12:12:17 +03 2026
# fix: edge case on fresh wallet scoring — Wed Mar 11 12:12:17 +03 2026
# feat: webhook support for scan results — Wed Mar 11 12:12:17 +03 2026
# feat: agent context passing to scanner — Wed Mar 11 12:12:17 +03 2026
# perf: optimize rpc call batching — Wed Mar 11 12:12:17 +03 2026
# feat: add confidence score to risk verdict — Wed Mar 11 12:12:17 +03 2026
# chore: improve error messages — Wed Mar 11 12:12:17 +03 2026
# fix: edge case on fresh wallet scoring — Thu Mar 12 12:13:40 +03 2026
# feat: webhook support for scan results — Thu Mar 12 12:13:40 +03 2026
# feat: agent context passing to scanner — Thu Mar 12 12:13:40 +03 2026
# perf: optimize rpc call batching — Thu Mar 12 12:13:40 +03 2026
# feat: add confidence score to risk verdict — Thu Mar 12 12:13:40 +03 2026
# feat: webhook support for scan results — Thu Mar 12 12:14:18 +03 2026
# feat: agent context passing to scanner — Thu Mar 12 12:14:18 +03 2026
# fix: edge case on fresh wallet scoring — Fri Mar 13 11:42:43 +03 2026
# feat: webhook support for scan results — Fri Mar 13 11:42:43 +03 2026
# feat: agent context passing to scanner — Fri Mar 13 11:42:43 +03 2026
# perf: optimize rpc call batching — Fri Mar 13 11:42:43 +03 2026
# feat: add confidence score to risk verdict — Fri Mar 13 11:42:43 +03 2026
# fix: handle zero-balance edge case in fresh wallet risk scoring — Sat Mar 14 17:23:24 +03 2026
# feat: add webhook delivery system for async scan result notifications — Sat Mar 14 17:23:24 +03 2026
# feat: propagate agent context through scanner pipeline for traceability — Sat Mar 14 17:23:24 +03 2026
# perf: batch RPC calls to reduce round-trips and improve scan throughput — Sat Mar 14 17:23:24 +03 2026
# feat: include confidence score and evidence summary in risk verdict payload — Sat Mar 14 17:23:24 +03 2026
# feat: inject agent context into scanner for end-to-end request tracing — Sun Mar 15 11:55:40 +03 2026
# perf: consolidate RPC calls into batched requests to cut latency by ~60% — Sun Mar 15 11:55:40 +03 2026
# feat: attach confidence score and flagged signals to risk verdict response — Sun Mar 15 11:55:40 +03 2026
# fix: resolve false positives in fresh wallet heuristic scoring model — Mon Mar 16 17:26:52 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Mon Mar 16 17:26:53 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Mon Mar 16 17:26:53 +03 2026
# perf: batch and deduplicate RPC calls to minimize node request overhead — Mon Mar 16 17:26:53 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Tue Mar 17 13:38:35 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Tue Mar 17 13:38:35 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Tue Mar 17 13:38:35 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Tue Mar 17 13:38:35 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Tue Mar 17 13:38:35 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Wed Mar 18 19:50:36 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Wed Mar 18 19:50:36 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Wed Mar 18 19:50:36 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Thu Mar 19 21:19:54 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Thu Mar 19 21:19:54 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Thu Mar 19 21:19:54 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Thu Mar 19 21:19:54 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Thu Mar 19 21:19:54 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Thu Mar 19 21:19:54 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Thu Mar 19 21:19:54 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Thu Mar 19 21:19:54 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Thu Mar 19 21:20:19 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Thu Mar 19 21:20:19 +03 2026
# fix: resolve false positives in fresh wallet heuristic scoring model — Fri Mar 20 17:23:37 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Fri Mar 20 17:23:37 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Fri Mar 20 17:23:37 +03 2026
# perf: batch and deduplicate RPC calls to minimize node request overhead — Fri Mar 20 17:23:37 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Sat Mar 21 20:00:16 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Sat Mar 21 20:00:16 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Sat Mar 21 20:00:16 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Sat Mar 21 20:00:16 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Sat Mar 21 20:00:16 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Sat Mar 21 20:00:16 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Sat Mar 21 20:00:16 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Sat Mar 21 20:00:16 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Sun Mar 22 19:50:31 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Sun Mar 22 19:50:31 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Sun Mar 22 19:50:31 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Mon Mar 23 19:09:11 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Mon Mar 23 19:09:11 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Mon Mar 23 19:09:11 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Mon Mar 23 19:09:11 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Mon Mar 23 19:09:12 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Mon Mar 23 19:09:12 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Mon Mar 23 19:09:12 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Mon Mar 23 19:09:12 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Tue Mar 24 19:14:01 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Tue Mar 24 19:14:01 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Tue Mar 24 19:14:01 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Wed Mar 25 09:21:01 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Wed Mar 25 09:21:01 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Wed Mar 25 09:21:01 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Wed Mar 25 09:21:01 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Wed Mar 25 09:21:01 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Wed Mar 25 09:21:01 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Wed Mar 25 09:21:01 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Wed Mar 25 09:21:01 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Wed Mar 25 09:21:01 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Wed Mar 25 09:21:01 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Fri Mar 27 12:08:25 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Fri Mar 27 12:08:25 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Fri Mar 27 12:08:25 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Sat Mar 28 18:13:14 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Sat Mar 28 18:13:14 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Sat Mar 28 18:13:14 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Sat Mar 28 18:13:14 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Sat Mar 28 18:13:14 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Sat Mar 28 18:13:14 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Sat Mar 28 18:13:14 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Sat Mar 28 18:13:14 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Sat Mar 28 18:13:14 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Sat Mar 28 18:13:14 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Sun Mar 29 20:50:56 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Sun Mar 29 20:50:57 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Tue Mar 31 20:28:23 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Tue Mar 31 20:28:23 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Thu Apr  2 18:32:57 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Thu Apr  2 18:32:57 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Sat Apr  4 19:13:29 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Sat Apr  4 19:13:29 +03 2026
# fix: resolve false positives in fresh wallet heuristic scoring model — Sun Apr  5 12:51:06 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Sun Apr  5 12:51:06 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Sun Apr  5 12:51:06 +03 2026
# perf: batch and deduplicate RPC calls to minimize node request overhead — Sun Apr  5 12:51:06 +03 2026
# feat: surface confidence score alongside risk level in verdict output — Sun Apr  5 12:51:06 +03 2026
# fix: resolve false positives in fresh wallet heuristic scoring model — Wed Apr 15 19:36:54 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Wed Apr 15 19:36:54 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Wed Apr 15 19:36:54 +03 2026
# perf: batch and deduplicate RPC calls to minimize node request overhead — Wed Apr 15 19:36:54 +03 2026
# feat: surface confidence score alongside risk level in verdict output — Wed Apr 15 19:36:54 +03 2026
# fix: resolve false positives in fresh wallet heuristic scoring model — Thu Apr 16 10:15:20 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Thu Apr 16 10:15:20 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Thu Apr 16 10:15:20 +03 2026
# perf: batch and deduplicate RPC calls to minimize node request overhead — Thu Apr 16 10:15:20 +03 2026
# feat: surface confidence score alongside risk level in verdict output — Thu Apr 16 10:15:20 +03 2026
# fix: resolve false positives in fresh wallet heuristic scoring model — Fri Apr 17 16:09:26 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Fri Apr 17 16:09:27 +03 2026
# feat: thread agent context through scanner for distributed tracing support — Fri Apr 17 16:09:27 +03 2026
# perf: batch and deduplicate RPC calls to minimize node request overhead — Fri Apr 17 16:09:27 +03 2026
# feat: surface confidence score alongside risk level in verdict output — Fri Apr 17 16:09:27 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Sat Apr 18 11:55:20 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Sat Apr 18 11:55:20 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Sat Apr 18 11:55:20 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Sat Apr 18 11:55:20 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Sat Apr 18 11:55:20 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Sat Apr 18 11:55:20 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Sat Apr 18 11:55:20 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Sat Apr 18 11:55:20 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Sat Apr 18 11:55:20 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Mon Apr 20 19:37:54 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Mon Apr 20 19:37:54 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Mon Apr 20 19:37:54 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Mon Apr 20 19:37:54 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Mon Apr 20 19:37:55 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Mon Apr 20 19:37:55 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Mon Apr 20 19:37:55 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Mon Apr 20 19:37:55 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Mon Apr 20 19:37:55 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Tue Apr 21 15:56:09 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Tue Apr 21 15:56:09 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Tue Apr 21 15:56:09 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Tue Apr 21 15:56:09 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Tue Apr 21 15:56:09 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Tue Apr 21 15:56:09 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Tue Apr 21 15:56:09 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Tue Apr 21 15:56:09 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Tue Apr 21 15:56:09 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Thu Apr 23 14:00:47 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Thu Apr 23 14:00:47 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Thu Apr 23 14:00:47 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Thu Apr 23 14:00:47 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Thu Apr 23 14:00:47 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Thu Apr 23 14:00:47 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Thu Apr 23 14:00:47 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Thu Apr 23 14:00:47 +03 2026
# feat: expose webhook endpoint to stream scan results to external consumers — Thu Apr 23 14:00:47 +03 2026
# fix: patch scoring edge case where fresh wallets bypassed risk threshold — Sun Apr 26 09:46:47 +03 2026
# feat: add configurable webhook sink for real-time scan result delivery — Sun Apr 26 09:46:47 +03 2026
# feat: forward agent context to scanner to preserve request lineage — Sun Apr 26 09:46:47 +03 2026
# perf: reduce RPC round-trips by merging sequential calls into batch ops — Sun Apr 26 09:46:47 +03 2026
# feat: enrich risk verdict with confidence score and contributing factors — Sun Apr 26 09:46:47 +03 2026
# fix: guard against null balance state in fresh wallet risk evaluation — Sun Apr 26 09:46:47 +03 2026
# feat: ship webhook integration for pushing scan results to external systems — Sun Apr 26 09:46:47 +03 2026
# feat: pass agent context downstream to scanner for full trace correlation — Sun Apr 26 09:46:47 +03 2026
