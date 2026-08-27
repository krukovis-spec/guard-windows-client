using System;
using System.Collections.Generic;
using Guard.Contracts;
using Guard.Contracts.Relay;

namespace Guard.Domain.Relay
{
    /// <summary>
    /// A separate authoritative aggregate for relay delivery and approval
    /// transactions. A single CAS commit can bind request resolution, the
    /// per-authority/key replay floor, policy ledger revision, reconciliation
    /// intent, signed receipt, encrypted receipt frame, and inbound cursor.
    /// It intentionally does not share DeviceSecurityState's global sequence.
    /// </summary>
    public sealed class RelayTransactionState
    {
        public const int MaximumReplayFloors = 32;
        public const int MaximumTrackedRequests = 128;
        public const int MaximumPolicyLedgerEntries = 128;
        public const int MaximumReconcileIntents = 64;
        public const int MaximumSignedReceipts = 64;
        public const int MaximumOutboxItems = 8;

        private readonly RelayReplayFloor[] _replayFloors;
        private readonly RelayTrackedRequest[] _trackedRequests;
        private readonly RelayPolicyLedgerEntry[] _policyLedger;
        private readonly RelayReconcileIntent[] _reconcileIntents;
        private readonly RelaySignedReceiptRecord[] _signedReceipts;
        private readonly RelayEncryptedOutboxItem[] _outbox;

        public RelayTransactionState(
            string deviceId,
            long version,
            long deviceEpoch,
            long authorityEpoch,
            long committedInboundCursor,
            long highestOutboundCursor,
            long acknowledgedOutboundCursor,
            long policyRevision,
            IEnumerable<RelayReplayFloor>? replayFloors = null,
            IEnumerable<RelayTrackedRequest>? trackedRequests = null,
            IEnumerable<RelayPolicyLedgerEntry>? policyLedger = null,
            IEnumerable<RelayReconcileIntent>? reconcileIntents = null,
            IEnumerable<RelaySignedReceiptRecord>? signedReceipts = null,
            IEnumerable<RelayEncryptedOutboxItem>? outbox = null)
        {
            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical relay device id is required.",
                    nameof(deviceId));
            }

            RequireNonNegative(version, nameof(version));
            RequireNonNegative(deviceEpoch, nameof(deviceEpoch));
            RequireNonNegative(authorityEpoch, nameof(authorityEpoch));
            RequireNonNegative(committedInboundCursor, nameof(committedInboundCursor));
            RequireNonNegative(highestOutboundCursor, nameof(highestOutboundCursor));
            RequireNonNegative(acknowledgedOutboundCursor, nameof(acknowledgedOutboundCursor));
            RequireNonNegative(policyRevision, nameof(policyRevision));
            if (acknowledgedOutboundCursor > highestOutboundCursor)
            {
                throw new ArgumentException(
                    "The acknowledged outbound cursor cannot exceed the published cursor.",
                    nameof(acknowledgedOutboundCursor));
            }

            DeviceId = deviceId;
            Version = version;
            DeviceEpoch = deviceEpoch;
            AuthorityEpoch = authorityEpoch;
            CommittedInboundCursor = committedInboundCursor;
            HighestOutboundCursor = highestOutboundCursor;
            AcknowledgedOutboundCursor = acknowledgedOutboundCursor;
            PolicyRevision = policyRevision;
            _replayFloors = CopyReplayFloors(replayFloors, authorityEpoch);
            _trackedRequests = CopyTrackedRequests(trackedRequests);
            _policyLedger = CopyPolicyLedger(policyLedger, policyRevision);
            _reconcileIntents = CopyReconcileIntents(reconcileIntents, policyRevision);
            _signedReceipts = CopySignedReceipts(signedReceipts);
            _outbox = CopyOutbox(
                outbox,
                acknowledgedOutboundCursor,
                highestOutboundCursor);
        }

        public string DeviceId { get; }

        public long Version { get; }

        public long DeviceEpoch { get; }

        public long AuthorityEpoch { get; }

        /// <summary>
        /// Highest inbound relay cursor whose semantic outcome is already in
        /// this aggregate. A relay ack may be sent only after this commit.
        /// </summary>
        public long CommittedInboundCursor { get; }

        public long HighestOutboundCursor { get; }

        public long AcknowledgedOutboundCursor { get; }

        public long PolicyRevision { get; }

        public IReadOnlyList<RelayReplayFloor> ReplayFloors =>
            Array.AsReadOnly((RelayReplayFloor[])_replayFloors.Clone());

        public IReadOnlyList<RelayTrackedRequest> TrackedRequests =>
            Array.AsReadOnly((RelayTrackedRequest[])_trackedRequests.Clone());

        public IReadOnlyList<RelayPolicyLedgerEntry> PolicyLedger =>
            Array.AsReadOnly((RelayPolicyLedgerEntry[])_policyLedger.Clone());

        public IReadOnlyList<RelayReconcileIntent> ReconcileIntents =>
            Array.AsReadOnly((RelayReconcileIntent[])_reconcileIntents.Clone());

        public IReadOnlyList<RelaySignedReceiptRecord> SignedReceipts =>
            Array.AsReadOnly((RelaySignedReceiptRecord[])_signedReceipts.Clone());

        public IReadOnlyList<RelayEncryptedOutboxItem> Outbox =>
            Array.AsReadOnly((RelayEncryptedOutboxItem[])_outbox.Clone());

        public RelayTransactionState WithPublishedRequest(
            RelayTrackedRequest request,
            RelayEncryptedOutboxItem encryptedRequestOutboxItem)
        {
            if (DeviceEpoch <= 0 || AuthorityEpoch <= 0)
            {
                throw new InvalidOperationException(
                    "Relay requests require completed device and authority enrollment.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (!request.IsPending)
            {
                throw new ArgumentException(
                    "Only a pending request can be published.",
                    nameof(request));
            }

            if (encryptedRequestOutboxItem == null)
            {
                throw new ArgumentNullException(nameof(encryptedRequestOutboxItem));
            }

            if (encryptedRequestOutboxItem.Kind != RelayFrameKind.Request)
            {
                throw new ArgumentException(
                    "A request must publish an encrypted request frame.",
                    nameof(encryptedRequestOutboxItem));
            }

            RequireNextOutboundCursor(encryptedRequestOutboxItem);
            if (_trackedRequests.Length >= MaximumTrackedRequests)
            {
                throw new InvalidOperationException(
                    "The bounded tracked-request capacity is exhausted.");
            }

            if (_outbox.Length >= MaximumOutboxItems)
            {
                throw new InvalidOperationException(
                    "The bounded encrypted relay outbox is full.");
            }

            for (var index = 0; index < _trackedRequests.Length; index++)
            {
                if (string.Equals(
                    _trackedRequests[index].RequestId,
                    request.RequestId,
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The relay request id is already tracked.");
                }
            }

            var nextRequests = Append(_trackedRequests, request);
            var nextOutbox = Append(_outbox, encryptedRequestOutboxItem);
            return CreateSuccessor(
                committedInboundCursor: CommittedInboundCursor,
                highestOutboundCursor: encryptedRequestOutboxItem.OutboundCursor,
                acknowledgedOutboundCursor: AcknowledgedOutboundCursor,
                policyRevision: PolicyRevision,
                replayFloors: _replayFloors,
                trackedRequests: nextRequests,
                policyLedger: _policyLedger,
                reconcileIntents: _reconcileIntents,
                signedReceipts: _signedReceipts,
                outbox: nextOutbox);
        }

        public RelayTransactionState WithCommittedApproval(
            RelayApprovalTransaction transaction)
        {
            if (transaction == null)
            {
                throw new ArgumentNullException(nameof(transaction));
            }

            if (CommittedInboundCursor == long.MaxValue ||
                transaction.InboundCursor != CommittedInboundCursor + 1)
            {
                throw new InvalidOperationException(
                    "An approval must consume exactly the next inbound cursor.");
            }

            RequireNextOutboundCursor(transaction.EncryptedReceiptOutboxItem);
            if (transaction.EncryptedReceiptOutboxItem.Kind != RelayFrameKind.Receipt)
            {
                throw new InvalidOperationException(
                    "An approval transaction must enqueue an encrypted receipt frame.");
            }

            if (_signedReceipts.Length >= MaximumSignedReceipts)
            {
                throw new InvalidOperationException(
                    "The bounded signed-receipt capacity is exhausted.");
            }

            if (_outbox.Length >= MaximumOutboxItems)
            {
                throw new InvalidOperationException(
                    "The bounded encrypted relay outbox is full.");
            }

            var requestIndex = FindRequest(
                transaction.RequestId,
                transaction.RequestRevision,
                transaction.GetSnapshotHashCopy());
            if (requestIndex < 0)
            {
                throw new InvalidOperationException(
                    "The approval does not bind the exact tracked request snapshot.");
            }

            ValidateReplayFloor(transaction.ReplayFloor);
            ValidateReceiptBindings(transaction);
            EnsureCommandIsNew(transaction.ReplayFloor.CommandId);

            var nextRequests = (RelayTrackedRequest[])_trackedRequests.Clone();
            var nextPolicyLedger = _policyLedger;
            var nextReconcileIntents = _reconcileIntents;
            var nextPolicyRevision = PolicyRevision;
            var trackedRequest = _trackedRequests[requestIndex];

            if (transaction.Disposition == RelayApprovalDisposition.AlreadyResolved)
            {
                if (trackedRequest.IsPending ||
                    transaction.PolicyLedgerEntry != null ||
                    transaction.ReconcileIntent != null ||
                    transaction.SignedReceipt.Status !=
                        CommandReceiptStatus.AlreadyResolved)
                {
                    throw new InvalidOperationException(
                        "An AlreadyResolved receipt cannot mutate request or policy state.");
                }
            }
            else
            {
                if (!trackedRequest.IsPending)
                {
                    throw new InvalidOperationException(
                        "Only the first exact decision can resolve a pending request.");
                }

                if (transaction.Disposition == RelayApprovalDisposition.Allowed)
                {
                    ValidateAllowedMutation(transaction);
                    nextPolicyRevision = transaction.PolicyLedgerEntry!.PolicyRevision;
                    nextPolicyLedger = Append(
                        _policyLedger,
                        transaction.PolicyLedgerEntry);
                    nextReconcileIntents = Append(
                        _reconcileIntents,
                        transaction.ReconcileIntent!);
                    nextRequests[requestIndex] = trackedRequest.Resolve(
                        RelayRequestResolution.Allowed,
                        transaction.ReplayFloor.CommandId,
                        transaction.ReplayFloor.GetApprovalHashCopy());
                }
                else
                {
                    ValidateDeniedMutation(transaction);
                    nextRequests[requestIndex] = trackedRequest.Resolve(
                        RelayRequestResolution.Denied,
                        transaction.ReplayFloor.CommandId,
                        transaction.ReplayFloor.GetApprovalHashCopy());
                }
            }

            var nextReplayFloors = UpsertReplayFloor(transaction.ReplayFloor);
            var nextReceipts = Append(_signedReceipts, transaction.SignedReceipt);
            var nextOutbox = Append(
                _outbox,
                transaction.EncryptedReceiptOutboxItem);
            return CreateSuccessor(
                committedInboundCursor: transaction.InboundCursor,
                highestOutboundCursor:
                    transaction.EncryptedReceiptOutboxItem.OutboundCursor,
                acknowledgedOutboundCursor: AcknowledgedOutboundCursor,
                policyRevision: nextPolicyRevision,
                replayFloors: nextReplayFloors,
                trackedRequests: nextRequests,
                policyLedger: nextPolicyLedger,
                reconcileIntents: nextReconcileIntents,
                signedReceipts: nextReceipts,
                outbox: nextOutbox);
        }

        public RelayTransactionState WithAcknowledgedOutboundCursor(long cursor)
        {
            if (cursor <= AcknowledgedOutboundCursor ||
                cursor > HighestOutboundCursor)
            {
                throw new ArgumentOutOfRangeException(nameof(cursor));
            }

            var keep = new List<RelayEncryptedOutboxItem>();
            for (var index = 0; index < _outbox.Length; index++)
            {
                if (_outbox[index].OutboundCursor > cursor)
                {
                    keep.Add(_outbox[index]);
                }
            }

            return CreateSuccessor(
                committedInboundCursor: CommittedInboundCursor,
                highestOutboundCursor: HighestOutboundCursor,
                acknowledgedOutboundCursor: cursor,
                policyRevision: PolicyRevision,
                replayFloors: _replayFloors,
                trackedRequests: _trackedRequests,
                policyLedger: _policyLedger,
                reconcileIntents: _reconcileIntents,
                signedReceipts: _signedReceipts,
                outbox: keep.ToArray());
        }

        public bool TryGetReplayFloor(
            long authorityEpoch,
            string approvalKeyId,
            out RelayReplayFloor replayFloor)
        {
            for (var index = 0; index < _replayFloors.Length; index++)
            {
                if (_replayFloors[index].AuthorityEpoch == authorityEpoch &&
                    string.Equals(
                        _replayFloors[index].ApprovalKeyId,
                        approvalKeyId,
                        StringComparison.Ordinal))
                {
                    replayFloor = _replayFloors[index];
                    return true;
                }
            }

            replayFloor = null!;
            return false;
        }

        private void ValidateReplayFloor(RelayReplayFloor nextFloor)
        {
            if (nextFloor.AuthorityEpoch != AuthorityEpoch)
            {
                throw new InvalidOperationException(
                    "The approval authority epoch does not match the current authority.");
            }

            RelayReplayFloor currentFloor;
            if (TryGetReplayFloor(
                nextFloor.AuthorityEpoch,
                nextFloor.ApprovalKeyId,
                out currentFloor))
            {
                if (currentFloor.HighestAcceptedSequence == long.MaxValue ||
                    nextFloor.HighestAcceptedSequence !=
                        currentFloor.HighestAcceptedSequence + 1)
                {
                    throw new InvalidOperationException(
                        "The approval sequence must advance by exactly one per authority/key.");
                }
            }
            else if (nextFloor.HighestAcceptedSequence != 1)
            {
                throw new InvalidOperationException(
                    "A new approval key must start at sequence one.");
            }
        }

        private void ValidateReceiptBindings(RelayApprovalTransaction transaction)
        {
            var receipt = transaction.SignedReceipt;
            var floor = transaction.ReplayFloor;
            if (!string.Equals(receipt.DeviceId, DeviceId, StringComparison.Ordinal) ||
                receipt.DeviceEpoch != DeviceEpoch ||
                !string.Equals(receipt.CommandId, floor.CommandId, StringComparison.Ordinal) ||
                !string.Equals(receipt.RequestId, transaction.RequestId, StringComparison.Ordinal) ||
                receipt.RequestRevision != transaction.RequestRevision ||
                receipt.AuthorityEpoch != floor.AuthorityEpoch ||
                !string.Equals(
                    receipt.ApprovalKeyId,
                    floor.ApprovalKeyId,
                    StringComparison.Ordinal) ||
                receipt.Sequence != floor.HighestAcceptedSequence ||
                !FixedTimeEquals(
                    receipt.GetApprovalHashCopy(),
                    floor.GetApprovalHashCopy()))
            {
                throw new InvalidOperationException(
                    "The signed receipt does not bind the exact approval transaction.");
            }
        }

        private void ValidateAllowedMutation(RelayApprovalTransaction transaction)
        {
            if (transaction.PolicyLedgerEntry == null ||
                transaction.ReconcileIntent == null ||
                transaction.SignedReceipt.Status !=
                    CommandReceiptStatus.AcceptedPendingReconciliation)
            {
                throw new InvalidOperationException(
                    "An allowed approval requires policy, reconciliation, and a pending receipt.");
            }

            if (_policyLedger.Length >= MaximumPolicyLedgerEntries ||
                _reconcileIntents.Length >= MaximumReconcileIntents)
            {
                throw new InvalidOperationException(
                    "The bounded policy transaction capacity is exhausted.");
            }

            if (PolicyRevision == long.MaxValue ||
                transaction.PolicyLedgerEntry.PolicyRevision != PolicyRevision + 1 ||
                transaction.ReconcileIntent.PolicyRevision !=
                    transaction.PolicyLedgerEntry.PolicyRevision ||
                !string.Equals(
                    transaction.PolicyLedgerEntry.RequestId,
                    transaction.RequestId,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    transaction.PolicyLedgerEntry.CommandId,
                    transaction.ReplayFloor.CommandId,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    transaction.ReconcileIntent.CommandId,
                    transaction.ReplayFloor.CommandId,
                    StringComparison.Ordinal) ||
                !FixedTimeEquals(
                    transaction.PolicyLedgerEntry.GetApprovalHashCopy(),
                    transaction.ReplayFloor.GetApprovalHashCopy()) ||
                !FixedTimeEquals(
                    transaction.ReconcileIntent.GetPolicyDigestCopy(),
                    transaction.PolicyLedgerEntry.ComputeDigest()))
            {
                throw new InvalidOperationException(
                    "The allowed policy mutation is not exactly bound to the approval.");
            }
        }

        private static void ValidateDeniedMutation(
            RelayApprovalTransaction transaction)
        {
            if (transaction.PolicyLedgerEntry != null ||
                transaction.ReconcileIntent != null ||
                transaction.SignedReceipt.Status != CommandReceiptStatus.Applied)
            {
                throw new InvalidOperationException(
                    "A denial cannot create a permissive policy or reconciliation intent.");
            }
        }

        private void EnsureCommandIsNew(string commandId)
        {
            for (var index = 0; index < _signedReceipts.Length; index++)
            {
                if (string.Equals(
                    _signedReceipts[index].CommandId,
                    commandId,
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "A command id cannot create a second receipt.");
                }
            }
        }

        private int FindRequest(
            string requestId,
            long requestRevision,
            byte[] snapshotHash)
        {
            for (var index = 0; index < _trackedRequests.Length; index++)
            {
                var request = _trackedRequests[index];
                if (string.Equals(request.RequestId, requestId, StringComparison.Ordinal) &&
                    request.RequestRevision == requestRevision &&
                    FixedTimeEquals(request.GetSnapshotHashCopy(), snapshotHash))
                {
                    return index;
                }
            }

            return -1;
        }

        private RelayReplayFloor[] UpsertReplayFloor(RelayReplayFloor nextFloor)
        {
            var next = (RelayReplayFloor[])_replayFloors.Clone();
            for (var index = 0; index < next.Length; index++)
            {
                if (next[index].AuthorityEpoch == nextFloor.AuthorityEpoch &&
                    string.Equals(
                        next[index].ApprovalKeyId,
                        nextFloor.ApprovalKeyId,
                        StringComparison.Ordinal))
                {
                    next[index] = nextFloor;
                    return next;
                }
            }

            if (next.Length >= MaximumReplayFloors)
            {
                throw new InvalidOperationException(
                    "The bounded per-key replay-floor capacity is exhausted.");
            }

            return Append(next, nextFloor);
        }

        private void RequireNextOutboundCursor(RelayEncryptedOutboxItem item)
        {
            if (HighestOutboundCursor == long.MaxValue ||
                item.OutboundCursor != HighestOutboundCursor + 1)
            {
                throw new InvalidOperationException(
                    "An encrypted outbox item must use exactly the next outbound cursor.");
            }
        }

        private RelayTransactionState CreateSuccessor(
            long committedInboundCursor,
            long highestOutboundCursor,
            long acknowledgedOutboundCursor,
            long policyRevision,
            RelayReplayFloor[] replayFloors,
            RelayTrackedRequest[] trackedRequests,
            RelayPolicyLedgerEntry[] policyLedger,
            RelayReconcileIntent[] reconcileIntents,
            RelaySignedReceiptRecord[] signedReceipts,
            RelayEncryptedOutboxItem[] outbox)
        {
            return new RelayTransactionState(
                DeviceId,
                checked(Version + 1),
                DeviceEpoch,
                AuthorityEpoch,
                committedInboundCursor,
                highestOutboundCursor,
                acknowledgedOutboundCursor,
                policyRevision,
                replayFloors,
                trackedRequests,
                policyLedger,
                reconcileIntents,
                signedReceipts,
                outbox);
        }

        private static RelayReplayFloor[] CopyReplayFloors(
            IEnumerable<RelayReplayFloor>? values,
            long currentAuthorityEpoch)
        {
            var result = CopyBounded(
                values,
                MaximumReplayFloors,
                "relay replay floors");
            for (var index = 0; index < result.Length; index++)
            {
                if (result[index].AuthorityEpoch > currentAuthorityEpoch)
                {
                    throw new ArgumentException(
                        "A replay floor cannot be from a future authority epoch.",
                        nameof(values));
                }

                for (var other = 0; other < index; other++)
                {
                    if (result[index].AuthorityEpoch == result[other].AuthorityEpoch &&
                        string.Equals(
                            result[index].ApprovalKeyId,
                            result[other].ApprovalKeyId,
                            StringComparison.Ordinal))
                    {
                        throw new ArgumentException(
                            "Relay replay floors must be unique per authority/key.",
                            nameof(values));
                    }
                }
            }

            return result;
        }

        private static RelayTrackedRequest[] CopyTrackedRequests(
            IEnumerable<RelayTrackedRequest>? values)
        {
            var result = CopyBounded(
                values,
                MaximumTrackedRequests,
                "tracked relay requests");
            RequireUnique(
                result,
                value => value.RequestId,
                "Tracked relay request ids must be unique.",
                nameof(values));
            return result;
        }

        private static RelayPolicyLedgerEntry[] CopyPolicyLedger(
            IEnumerable<RelayPolicyLedgerEntry>? values,
            long policyRevision)
        {
            var result = CopyBounded(
                values,
                MaximumPolicyLedgerEntries,
                "relay policy ledger entries");
            long previousRevision = 0;
            for (var index = 0; index < result.Length; index++)
            {
                if (result[index].PolicyRevision <= previousRevision ||
                    result[index].PolicyRevision > policyRevision)
                {
                    throw new ArgumentException(
                        "Relay policy ledger revisions must be strictly increasing and committed.",
                        nameof(values));
                }

                previousRevision = result[index].PolicyRevision;
            }

            if (result.Length == 0)
            {
                if (policyRevision != 0)
                {
                    throw new ArgumentException(
                        "A nonzero relay policy revision requires a ledger entry.",
                        nameof(policyRevision));
                }
            }
            else if (result[result.Length - 1].PolicyRevision != policyRevision)
            {
                throw new ArgumentException(
                    "The relay policy revision must match the ledger head.",
                    nameof(policyRevision));
            }

            RequireUnique(
                result,
                value => value.CommandId,
                "Relay policy command ids must be unique.",
                nameof(values));
            return result;
        }

        private static RelayReconcileIntent[] CopyReconcileIntents(
            IEnumerable<RelayReconcileIntent>? values,
            long policyRevision)
        {
            var result = CopyBounded(
                values,
                MaximumReconcileIntents,
                "relay reconciliation intents");
            for (var index = 0; index < result.Length; index++)
            {
                if (result[index].PolicyRevision > policyRevision)
                {
                    throw new ArgumentException(
                        "A reconciliation intent cannot reference a future policy revision.",
                        nameof(values));
                }
            }

            RequireUnique(
                result,
                value => value.IntentId,
                "Relay reconciliation intent ids must be unique.",
                nameof(values));
            return result;
        }

        private static RelaySignedReceiptRecord[] CopySignedReceipts(
            IEnumerable<RelaySignedReceiptRecord>? values)
        {
            var result = CopyBounded(
                values,
                MaximumSignedReceipts,
                "signed relay receipts");
            RequireUnique(
                result,
                value => value.CommandId,
                "Signed relay receipt command ids must be unique.",
                nameof(values));
            return result;
        }

        private static RelayEncryptedOutboxItem[] CopyOutbox(
            IEnumerable<RelayEncryptedOutboxItem>? values,
            long acknowledgedOutboundCursor,
            long highestOutboundCursor)
        {
            var result = CopyBounded(
                values,
                MaximumOutboxItems,
                "encrypted relay outbox items");
            var previousCursor = acknowledgedOutboundCursor;
            for (var index = 0; index < result.Length; index++)
            {
                if (previousCursor == long.MaxValue ||
                    result[index].OutboundCursor != previousCursor + 1)
                {
                    throw new ArgumentException(
                        "Encrypted relay outbox cursors must be consecutive after the ack floor.",
                        nameof(values));
                }

                previousCursor = result[index].OutboundCursor;
            }

            if (result.Length == 0)
            {
                if (acknowledgedOutboundCursor != highestOutboundCursor)
                {
                    throw new ArgumentException(
                        "An empty relay outbox must be fully acknowledged.",
                        nameof(values));
                }
            }
            else if (result[result.Length - 1].OutboundCursor != highestOutboundCursor)
            {
                throw new ArgumentException(
                    "The encrypted relay outbox must end at the published cursor.",
                    nameof(values));
            }

            RequireUnique(
                result,
                value => value.FrameId,
                "Encrypted relay frame ids must be unique.",
                nameof(values));
            return result;
        }

        private static T[] CopyBounded<T>(
            IEnumerable<T>? values,
            int maximum,
            string fieldName)
            where T : class
        {
            if (values == null)
            {
                return Array.Empty<T>();
            }

            var result = new List<T>();
            foreach (var value in values)
            {
                if (value == null)
                {
                    throw new ArgumentException(
                        fieldName + " cannot contain null.",
                        nameof(values));
                }

                result.Add(value);
                if (result.Count > maximum)
                {
                    throw new ArgumentException(
                        "Too many " + fieldName + " were supplied.",
                        nameof(values));
                }
            }

            return result.ToArray();
        }

        private static void RequireUnique<T>(
            T[] values,
            Func<T, string> selector,
            string message,
            string parameterName)
        {
            for (var index = 0; index < values.Length; index++)
            {
                var value = selector(values[index]);
                for (var other = 0; other < index; other++)
                {
                    if (string.Equals(
                        value,
                        selector(values[other]),
                        StringComparison.Ordinal))
                    {
                        throw new ArgumentException(message, parameterName);
                    }
                }
            }
        }

        private static T[] Append<T>(T[] values, T value)
        {
            var next = new T[values.Length + 1];
            Array.Copy(values, next, values.Length);
            next[next.Length - 1] = value;
            return next;
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            var difference = 0;
            for (var index = 0; index < left.Length; index++)
            {
                difference |= left[index] ^ right[index];
            }

            return difference == 0;
        }

        private static void RequireNonNegative(long value, string parameterName)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(parameterName);
            }
        }
    }
}
