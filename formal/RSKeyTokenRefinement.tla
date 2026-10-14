------------------------ MODULE RSKeyTokenRefinement ------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 RS-Key contributors                                  *)
(*                                                                         *)
(* Native B -> A refinement plus the outcome-labelled action obligation.   *)
(***************************************************************************)
EXTENDS RSKeySecurityState, RSKeyTokenView

CONSTANTS MutateTokenGamma, BugDeadTokenAuthorized

Gamma ==
    IF MutateTokenGamma
      THEN [TokenGamma(pin, gate, tok, NoRp) EXCEPT !.pinSet = ~@]
      ELSE TokenGamma(pin, gate, tok, NoRp)

Abs == INSTANCE RSKeyTokenAbstract WITH a <- Gamma

R1sTokenStateRefinement == Abs!Spec

GammaNext(aop, outcome) == Abs!AllowedEventRel(Gamma, aop, outcome, Gamma')

(***************************************************************************)
(* Each security-visible outcome producer has an owner below.  The equality *)
(* is the coverage guard: adding a name to either side cannot silently leave *)
(* the action-property conjunction incomplete.                              *)
(***************************************************************************)
ObservableTokenActions == TokenOutcomeActions

OutcomeClauseOwners ==
    {"GetPinToken", "WrongPin", "MintPpuat", "LocalPinWrong", "LocalPinOk",
     "SetPinWrite", "ChangePinWrite", "RegisterTouched", "RegisterRefused",
     "RegisterWriteB", "RegisterNdTouched", "RegisterNdRefused",
     "AssertFinish", "ConfigOp", "BackupFinalize",
     "DeviceUnlock", "CmBeginViaToken", "CmBeginViaPpuat", "CmNext",
     "DeleteCredStart", "ResetRefused", "ResetFinish", "ResetAborts"}

R1oOutcomeCoverage == ObservableTokenActions = OutcomeClauseOwners

R1oStep ==
    /\ (\A ps \in PermSets, r \in RPs \cup {NoRp} :
          GetPinToken(ps, r) => GammaNext("IssueToken", "Authorized"))
    /\ (WrongPin => GammaNext("RevokeToken", "Rejected"))
    /\ (MintPpuat => GammaNext("MintGrant", "Authorized"))
    /\ (LocalPinWrong => GammaNext("RevokeToken", "Rejected"))
    /\ (LocalPinOk => GammaNext("Noop", "Authorized"))
    /\ (SetPinWrite => GammaNext("SetPin", "Authorized"))
    /\ (ChangePinWrite => GammaNext("Noop", "Authorized"))
    /\ (RegisterTouched => GammaNext("UseMc", "Silent"))
    /\ (RegisterRefused => GammaNext("Noop", "Rejected"))
    /\ (RegisterWriteB => GammaNext("Noop", "Authorized"))
    \* The token-less non-discoverable registration is a `Noop` and not a
    \* `UseMc`, and the difference is the whole of what tier A can say here: its
    \* `UseMc` admits an Authorized event only under `~pinSet \/ (live /\
    \* permissionMc)`, which is the very rule 6.1.2 step 10 carves out of. B's
    \* own guard admits this action only where `~tok.live`, so alpha does not
    \* move and `post = pre` -- and the refinement is an equality rather than a
    \* widening of A. Widening A is stage 4's, and it is named as such.
    /\ (RegisterNdTouched => GammaNext("Noop", "Authorized"))
    /\ (RegisterNdRefused => GammaNext("Noop", "Rejected"))
    /\ (AssertFinish =>
          GammaNext("UseGa",
            IF BugNoTouchRequired \/ pres.granted = "confirm"
              THEN "Authorized" ELSE "Rejected"))
    /\ (ConfigOp => GammaNext("UseAcfg", "Authorized"))
    /\ (BackupFinalize => GammaNext("Noop", "Authorized"))
    /\ (DeviceUnlock => GammaNext("Noop", "Authorized"))
    /\ (\A ch \in Channels, r \in RPs \cup {NoRp} :
          CmBeginViaToken(ch, r) => GammaNext("UseCm", "Authorized"))
    /\ (\A ch \in Channels :
          CmBeginViaPpuat(ch) => GammaNext("UseCm", "Authorized"))
    /\ (\A ch \in Channels : CmNext(ch) => GammaNext("UseCm", "Authorized"))
    /\ (\A r \in RPs : DeleteCredStart(r) => GammaNext("UseCm", "Authorized"))
    /\ (ResetRefused => GammaNext("Noop", "Rejected"))
    /\ (ResetFinish => GammaNext("ProvisionGrant", "Authorized"))
    /\ (ResetAborts => GammaNext("Noop", "Rejected"))
    /\ (PressDown => GammaNext("UseAcfg",
          IF BugDeadTokenAuthorized /\ ~tok.live THEN "Authorized" ELSE "Rejected"))

R1oTokenOutcomes == [] [R1oStep]_vars

=============================================================================
