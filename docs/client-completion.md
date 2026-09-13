# Client completion and daemon readiness

Two independently reproduced races are corrected. Full hosted qualification of this change remains pending. Phases 6 and 7 are not complete.

## Final client read

The framing reader can consume the last DATA frame and process FIN while `Conn.Read` is still performing its post-read authority check. Previously, the automatic client ACK let the connector complete and close the carrier during that check. The last read could then fail despite successful connector completion.

`TestClientCompletionCannotOvertakeFinalRead` pauses exactly at that post-read check, using fixture clock functions without changing production clock bounds. On the prior implementation, it fails because the connector closes before the read returns. The client now withholds its final ACK until `WaitFinished` is called after both local forwarding workers succeed. That method also requires a live caller context and a validated peer FIN. It retains acknowledgment ordering, joins transport workers, and checks final completion. A canceled-forwarding regression verifies that abandonment cannot acquire the ACK.

No frame format, production timeout, authorization, revocation or clock-health bound changes. Framing-only unit fixtures explicitly omit the application handoff gate; the new completion tests use the production client constructor. The real Linux half-close/renewal fixture now calls `WaitFinished` after consuming its output.

The final native workload/client/agent race run passed 35 top-level tests and 121 subcases, with no failures or skips. Package durations were 12.545, 39.046 and 13.341 seconds. The prior-source failure and final results are retained in the [source-bound evidence](phase-6-client-completion-evidence.json).

## Daemon readiness

The restart test previously waited only for the socket pathname to exist. Linux creates that pathname before the listener applies its required 0600 mode and starts serving. The strict client correctly rejects a request during that interval.

A compiler-only overlay inserts a 50 ms delay between bind and permission setup inside a NIC-less Linux guest. It is guarded by two fixture environment flags and is absent from production source. The original test failed all ten attempts at its initial status request.

The test now waits for a successful status response, still requiring the locked state and all production path, mode and peer-UID checks. Cleanup cancels and joins the child even when an assertion fails. The first revision retained a three-second startup budget and failed eight of ten attempts during emulated startup; that failed run remains recorded. The final fixture allows ten seconds for readiness and a thirty-second outer child lifetime. Individual RPC deadlines remain unchanged. With the same injected delay, all ten final tests passed, exercising twenty starts and graceful stops, socket removal and unchanged public configuration.

## Qualification limits

Dashboard source `592536d` passed all six hosted workflows before these changes: the verified Linux artifact has 241 top-level passes, 1,146 subcase passes and four skips; the service artifact has four installed-service cases and all 21 HTTPS cases passing. Its tested merge is `ba815a6c422a9671520138abf55f774c9e8ed48a`, with the same tree as the source. These results confirm the evidence-format scanner correction, not the new completion changes.

Main source `159e1c0` still has recorded hosted failures in daemon startup, a live enrolled-agent transfer and one HTTPS positive control. The new regressions establish the startup and final-read bugs, but do not establish that every earlier transfer failure had the same cause. Keep those failures open until source-specific runtime evidence resolves them. The canonical acceptance ledger remains seven implemented and 84 planned out of 91.
