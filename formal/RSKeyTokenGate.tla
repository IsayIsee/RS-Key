--------------------------- MODULE RSKeyTokenGate ---------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 RS-Key contributors                                  *)
(*                                                                         *)
(* The REQUIREMENT half of tier A.  RSKeyTokenAbstract carries the         *)
(* relation; this module carries the gate each operation's requirement     *)
(* names, transcribed from CTAP 2.3 and never read off AllowedEventRel.    *)
(*                                                                         *)
(* Defined the second way the invariant below is algebraically the         *)
(* relation and cannot fail.  That is not a hypothetical: the per-FID      *)
(* projection this tree shipped once had the code for its own oracle and   *)
(* reported 0 divergences over 5^4 inputs.  So the disagreement is         *)
(* MEASURED -- TokenGateOracle.cfg walks the set on which the two differ   *)
(* and carries its size as a floor, and an empty set is a dead run rather  *)
(* than a green one.                                                       *)
(***************************************************************************)
EXTENDS RSKeyTokenAbstract, TLC

CONSTANT BugUnauthorizedEdge

(***************************************************************************)
(* THE ORACLE.  One line per operation, each answering only "what does the *)
(* requirement demand of the PRE-state", never "what does the relation     *)
(* admit".  Where a requirement names something tier A has no vocabulary   *)
(* for -- presence, the reset window, the retry counter, an rpId identity  *)
(* -- the line says TRUE and the obligation is B's; the A map's own        *)
(* section in docs/authorization-slice.md lists all four.                  *)
(***************************************************************************)
RequiredGate(op, s) ==
    CASE op = "Noop" ->
           \* A stutter is no protected operation, so it carries no gate.
           TRUE
      [] op = "IssueToken" ->
           \* getPinToken (CTAP 2.3 6.5.5.7): no PIN, no token. The retry
           \* budget and the soft lock guard it too and neither is in A.
           s.pinSet
      [] op = "RevokeToken" ->
           \* stopUsingPinUvAuthToken (6.5.5.8) needs no authorization: any
           \* holder may drop its own grant.
           TRUE
      [] op = "SetPin" ->
           \* setPIN refuses over an existing PIN; changePIN is the other door.
           ~s.pinSet
      [] op = "ClearPin" ->
           \* Only authenticatorReset (6.6) clears a PIN, and its gate is the
           \* 10 s window and a touch -- neither of which A can see.
           TRUE
      [] op = "MintGrant" ->
           \* Handing a platform the persistent pcmr grant goes through the
           \* PIN door (CTAP 2.2 6.5.5.7.2/.3), so a PIN must already stand.
           s.pinSet
      [] op = "ProvisionGrant" ->
           \* The device writes the record itself -- at a boot, a finished reset
           \* or a vendor backup load -- and hands it to no platform. Those
           \* commands' own gates are B's.
           TRUE
      [] op = "RevokeGrant" ->
           \* Dropping the grant record is not a protected operation.
           TRUE
      [] op = "UseMc" ->
           \* makeCredential 6.1: with a PIN set the request must carry a live
           \* token holding `mc`; with none set the token-less arm is the rule.
           ~s.pinSet \/ (s.live /\ s.permissionMc)
      [] op = "UseGa" ->
           \* getAssertion 6.2, the same rule one permission over.
           ~s.pinSet \/ (s.live /\ s.permissionGa)
      [] op = "UseCm" ->
           \* credentialManagement 6.8: a live token holding `cm`, or the
           \* persistent grant, which 6.8.2 step 4 lets authorize on its own.
           \* A sees the record, not who holds it: that is the token's secrecy.
           (s.live /\ s.permissionCm) \/ s.persistentGrant
      [] op = "UseAcfg" ->
           \* authenticatorConfig 6.11 has no token-less arm.
           s.live /\ s.permissionAcfg
      [] OTHER -> FALSE

(***************************************************************************)
(* THE MUTANT.  One Authorized edge the requirement forbids -- an          *)
(* authenticatorConfig served with no PIN and no live token -- so a green  *)
(* NoAuthorizationBypassA is a run that could have gone red.               *)
(***************************************************************************)
AuthorizedFrom(pre, op, post) ==
    \/ AllowedEventRel(pre, op, "Authorized", post)
    \/ /\ BugUnauthorizedEdge
       /\ op = "UseAcfg" /\ post = pre
       /\ ~pre.pinSet /\ ~pre.live

(***************************************************************************)
(* THE A-LEVEL STATEMENT: every event the relation admits as Authorized     *)
(* had the gate its operation's requirement names.  Written as the SLICE at *)
(* the current state rather than as a walk of AllowedRelation, for one      *)
(* reason and one price.  The reason: over the whole 69 696-tuple           *)
(* comprehension the predicate reads no variable, and TLC then answers      *)
(* "the invariant is equal to FALSE" at startup -- no counterexample, and   *)
(* a verdict column that cannot name the invariant that fell.  The price:   *)
(* the slice covers AllowedRelation only if every A state is reachable, so  *)
(* TokenGate.cfg's floor is a PIN at 44 -- the whole domain -- and not a    *)
(* third of a measurement.                                                  *)
(***************************************************************************)
NoAuthorizationBypassA ==
    \A op \in Ops, post \in AStates :
        AuthorizedFrom(a, op, post) => RequiredGate(op, a)

(***************************************************************************)
(* NON-DEGENERACY.  The relation read as a gate: op is servable from s      *)
(* when some non-Rejected outcome is admitted.  This is the oracle the      *)
(* refuted per-FID projection would have used, and the point of the two     *)
(* definitions below is that it is NOT the one above.                       *)
(***************************************************************************)
GateFromRelation(op, s) ==
    \E outcome \in Outcomes \ {"Rejected"}, post \in AStates :
        AllowedEventRel(s, op, outcome, post)

Disagreements ==
    {p \in AStates \X Ops :
       RequiredGate(p[2], p[1]) # GateFromRelation(p[2], p[1])}

DisagreeStates == {p[1] : p \in Disagreements}

\* E4a's predicate, and it must be RED. The counterexample names one state; the
\* whole set is what TokenGateOracle.cfg prints and floors.
RequiredGateAgreesWithRelation ==
    \A op \in Ops : RequiredGate(op, a) = GateFromRelation(op, a)

\* The enumeration, driven the way StoreInduction.cfg drives its probe: every
\* disagreeing state is an INITIAL state, so the run's distinct-state count IS
\* the size of the set and `floors.txt` can ratchet the non-degeneracy instead of
\* a reader taking it on trust. Each is printed with the operations it disagrees
\* on -- that print is the bundle's enumeration. An oracle transcribed from the
\* relation leaves this INIT with no states at all, which TLC refuses outright.
DisagreeInit ==
    /\ a \in DisagreeStates
    /\ PrintT(<<"DISAGREE", a,
                {op \in Ops : RequiredGate(op, a) # GateFromRelation(op, a)}>>)

DisagreeNext == a' \in DisagreeStates

=============================================================================
