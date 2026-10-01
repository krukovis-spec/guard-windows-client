package app.guard.parent.enrollment

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.biometric.BiometricManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.withResumed
import app.guard.parent.BuildConfig
import app.guard.parent.R
import app.guard.parent.approval.NativeInboxPageCodec
import app.guard.parent.approval.requestDisplayText
import app.guard.parent.approval.ApprovalChoice
import app.guard.parent.approval.ApprovalSigningOperation
import app.guard.parent.approval.VerifiedNativeRequest
import app.guard.parent.protocol.ApprovalDecision
import app.guard.parent.protocol.GuardWire
import app.guard.parent.protocol.RequestSnapshot
import app.guard.parent.security.PendingSignedEnvelope
import app.guard.parent.protocol.EnrollmentOffer
import app.guard.parent.protocol.TargetKind
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.*
import java.text.DateFormat
import java.util.Date

/** No exported intent/clipboard input. Biometric operations are cancelled when the screen stops. */
class EnrollmentActivity : FragmentActivity() {
    private val scope = MainScope()
    private var job: Job? = null
    private var waiting: Job? = null
    private var selectedOffer: EnrollmentOffer? = null
    private var displayedStage: EnrollmentStage? = null
    private var foreground = false
    private var scanning = false
    private var pickingProfile = false
    // Deliberately not saved in Bundle, preferences or intents. A recreated screen needs a new explicit import.
    private var profileSelection: Pair<EnrollmentOffer, String>? = null
    private val profilePicker = registerForActivityResult(object : ActivityResultContracts.OpenDocument() {
        override fun createIntent(context: Context, input: Array<String>): Intent =
            super.createIntent(context, input).putExtra(Intent.EXTRA_LOCAL_ONLY, true)
    }) { uri -> profileSelected(uri) }
    private var transcript: EnrollmentTranscript? = null
    private var signing: EnrollmentSigningOperation? = null
    private var approvalSigning: ApprovalSigningOperation? = null
    private var prompt: BiometricPrompt? = null
    private var stopped = true
    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private val ceremony by lazy { AndroidEnrollmentCeremony(applicationContext) }
    private val binding get() = EnrollmentRelayBinding(BuildConfig.ENROLLMENT_RELAY)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        status = TextView(this).apply {
            textSize = 16f; setPadding(dp(20), dp(12), dp(20), dp(12))
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(8), dp(20), dp(24))
            isSaveEnabled = false
        }
        root.addView(status)
        root.addView(ScrollView(this).apply { addView(content) }, LinearLayout.LayoutParams(-1, 0, 1f))
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom); insets
        }
        setContentView(root)
    }

    override fun onStart() {
        super.onStart(); stopped = false
        if (!scanning && !pickingProfile) selectedOffer?.let { showOffer(it) } ?: showSaved()
    }

    override fun onResume() { super.onResume(); foreground = true; startWaiting() }

    override fun onPause() {
        foreground = false; waiting?.cancel()
        super.onPause()
    }

    override fun onStop() {
        stopped = true
        signing?.cancel(); signing = null
        approvalSigning?.cancel(); approvalSigning = null
        prompt?.cancelAuthentication(); prompt = null
        job?.cancel(); waiting?.cancel()
        transcript?.close(); transcript = null
        super.onStop()
    }

    override fun onDestroy() { scope.cancel(); super.onDestroy() }

    private fun showSaved() = work(R.string.enrollment_loading) {
        selectedOffer = null; displayedStage = null
        val saved = withContext(Dispatchers.IO) { ceremony.listPending() }
        content.removeAllViews()
        label(R.string.enrollment_title, 24f)
        label(R.string.enrollment_scope)
        if (BuildConfig.ENROLLMENT_RELAY.isEmpty()) label(R.string.enrollment_unconfigured)
        else {
            binding // Refuse a malformed release pin before camera or any network.
            button(R.string.enrollment_scan) { scan() }
        }
        if (saved.isEmpty()) label(R.string.enrollment_empty)
        for (state in saved) {
            text(state.offer.deviceLabel, 20f)
            text(state.offer.deviceId)
            button(R.string.enrollment_view) { showOffer(state.offer) }
        }
    }

    private fun scan() {
        if (scanning || stopped || job?.isActive == true) return
        signing?.cancel(); signing = null
        transcript?.close(); transcript = null
        val trusted = runCatching { binding }.getOrElse { status.setText(R.string.enrollment_unconfigured); return }
        scanning = true; setButtons(false); status.setText(R.string.enrollment_scanning)
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).enableAutoZoom().build()
        try {
            GmsBarcodeScanning.getClient(this, options).startScan()
                .addOnSuccessListener { barcode ->
                    if (isDestroyed || isFinishing) return@addOnSuccessListener
                    scope.launch {
                        // Scanner owns a separate Activity. Wait briefly for our visible screen,
                        // never persist raw input or accept it into a background/new Activity.
                        val displayed = withTimeoutOrNull(5000) {
                            lifecycle.withResumed {
                                scanning = false
                                try {
                                    transcript = EnrollmentQrParser.parse(requireNotNull(barcode.rawValue), trusted, System.currentTimeMillis())
                                    showScanned(requireNotNull(transcript))
                                } catch (_: Exception) {
                                    transcript?.close(); transcript = null
                                    status.setText(R.string.enrollment_bad_qr); setButtons(true)
                                }
                                true
                            }
                        }
                        if (displayed == null) { scanning = false; status.setText(R.string.enrollment_scan_again); setButtons(true) }
                    }
                }
                .addOnCanceledListener { scanning = false; if (!isDestroyed) { status.setText(R.string.enrollment_scan_cancelled); setButtons(true) } }
                .addOnFailureListener { scanning = false; if (!isDestroyed) { status.setText(R.string.enrollment_scanner_failed); setButtons(true) } }
        } catch (_: Exception) { scanning = false; status.setText(R.string.enrollment_scanner_failed); setButtons(true) }
    }

    private fun showScanned(scanned: EnrollmentTranscript) {
        content.removeAllViews(); status.setText(R.string.enrollment_review)
        device(scanned.offer)
        label(R.string.enrollment_check_computer)
        button(R.string.enrollment_prepare) {
            work(R.string.enrollment_preparing) {
                val state = withContext(Dispatchers.IO) { ceremony.prepare(scanned) }
                scanned.close(); transcript = null
                render(state, null)
            }
        }
        button(R.string.enrollment_back) { transcript?.close(); transcript = null; showSaved() }
    }

    private fun showOffer(offer: EnrollmentOffer) = work(R.string.enrollment_loading) {
        require(offer.relayEndpoint == binding.canonicalRelayEndpoint)
        val (state, result) = withContext(Dispatchers.IO) { ceremony.inspect(offer) }
        render(state, result)
    }

    private fun render(state: PendingEnrollment, result: app.guard.parent.protocol.EnrollmentResult?) {
        val stage = enrollmentStage(state, result, System.currentTimeMillis())
        selectedOffer = state.offer; displayedStage = stage
        content.removeAllViews(); device(state.offer)
        val message = when (stage) {
            EnrollmentStage.RESCAN -> R.string.enrollment_rescan
            EnrollmentStage.BIOMETRIC -> R.string.enrollment_ready
            EnrollmentStage.WAITING -> R.string.enrollment_waiting
            EnrollmentStage.COMPARE -> R.string.enrollment_compare
            EnrollmentStage.QUERY_ONLY -> R.string.enrollment_query_only
            EnrollmentStage.CONFIRMED -> R.string.enrollment_confirmed
            EnrollmentStage.EXPIRED -> R.string.enrollment_expired
            EnrollmentStage.STOPPED -> R.string.enrollment_stopped
            EnrollmentStage.RECOVERY -> R.string.enrollment_recovery
        }
        label(message)
        if (state.claim != null) {
            label(R.string.enrollment_commitment)
            text(enrollmentComparison(state), 18f).apply {
                typeface = Typeface.MONOSPACE; textDirection = View.TEXT_DIRECTION_LTR
                // Do not enable selection/copy: compare both screens, never paste the code to confirm.
            }
        }
        if (stage == EnrollmentStage.BIOMETRIC) button(R.string.enrollment_sign) { authenticate(state.offer) }
        if (stage == EnrollmentStage.CONFIRMED) button(R.string.native_profile_open) { showNativeProfile(state.offer) }
        if (stage == EnrollmentStage.CONFIRMED) button(R.string.native_inbox_open) { showRequests(state.offer) }
        if (stage == EnrollmentStage.CONFIRMED) button(R.string.approval_pending_open) { showPendingApproval(state.offer) }
        if (stage.canSynchronize) button(R.string.enrollment_update) { showOffer(state.offer) }
        if (!state.abandoned && stage != EnrollmentStage.CONFIRMED) button(R.string.enrollment_stop) {
            AlertDialog.Builder(this).setMessage(R.string.enrollment_stop_warning)
                .setNegativeButton(R.string.enrollment_keep, null)
                .setPositiveButton(R.string.enrollment_stop) { _, _ ->
                    work(R.string.enrollment_loading) {
                        withContext(Dispatchers.IO) { ceremony.abandon(state.offer) }
                        val (current, verified) = withContext(Dispatchers.IO) { ceremony.inspect(state.offer) }
                        render(current, verified)
                    }
                }.show()
        }
        button(R.string.enrollment_back) { showSaved() }
    }

    private fun showNativeProfile(offer: EnrollmentOffer) = work(R.string.native_profile_loading,
        failure = R.string.native_profile_failed) { renderNativeProfile(offer) }

    private fun showRequests(offer: EnrollmentOffer, after: Long = 0): Unit = work(R.string.native_inbox_loading,
        success = R.string.native_inbox_loaded, failure = R.string.native_inbox_failed) {
        // Clear old evidence before a new read; a failed refresh must not leave a stale request looking current.
        content.removeAllViews(); device(offer); label(R.string.native_inbox_unverified)
        button(R.string.native_inbox_refresh) { showRequests(offer) }
        button(R.string.native_profile_back) { showOffer(offer) }
        val page = withContext(Dispatchers.IO) { ceremony.openNativeInbox(offer).use { it.read(after) } }
        content.removeAllViews(); device(offer); label(R.string.native_inbox_title, 22f)
        label(R.string.native_inbox_scope)
        if (page.requests.isEmpty()) label(R.string.native_inbox_empty_page)
        for (request in page.requests) {
            requestDetails(request.snapshot)
            button(R.string.approval_choose) { showDecision(offer, request) }
        }
        if (page.frameCount == NativeInboxPageCodec.PAGE_SIZE)
            button(R.string.native_inbox_next) { showRequests(offer, page.nextCursor) }
        button(R.string.native_inbox_refresh) { showRequests(offer) }
        button(R.string.native_profile_back) { showOffer(offer) }
    }

    private fun requestDetails(request: RequestSnapshot) {
        label(if (request.targetKind == TargetKind.APPLICATION) R.string.native_inbox_application else R.string.native_inbox_website, 20f)
        text(getString(R.string.native_inbox_identity, requestDisplayText(request.targetIdentity)))
        text(getString(R.string.native_inbox_request_id, request.requestId, request.requestRevision))
        for (field in request.evidence) text(getString(R.string.native_inbox_evidence,
            requestDisplayText(field.name), requestDisplayText(field.value)))
        if (request.reason.isNotEmpty()) text(getString(R.string.native_inbox_reason, requestDisplayText(request.reason)))
        text(getString(R.string.native_inbox_expiry, DateFormat.getDateTimeInstance().format(Date(request.pendingExpiryUnixMillis))))
    }

    private fun decisionText(choice: ApprovalChoice): String = when (choice.decision) {
        ApprovalDecision.ALLOW_ALWAYS -> getString(R.string.approval_always)
        ApprovalDecision.ALLOW_TEMPORARY -> getString(R.string.approval_temporary_value, choice.minutes)
        ApprovalDecision.ALLOW_DAILY_QUOTA -> getString(R.string.approval_quota_value, choice.minutes)
        ApprovalDecision.DENY -> getString(R.string.approval_deny)
    }

    private fun showDecision(offer: EnrollmentOffer, request: VerifiedNativeRequest) = work(R.string.approval_checking,
        success = R.string.approval_status_checked, failure = R.string.approval_failed) {
        val pending = withContext(Dispatchers.IO) {
            ceremony.verifyRequest(offer, request); ceremony.pendingApproval(offer)
        }
        if (pending != null) { renderPendingApproval(offer, pending); return@work }
        content.removeAllViews(); device(offer); requestDetails(request.snapshot)
        label(R.string.approval_delivery_scope)
        val choices = RadioGroup(this).apply { orientation = RadioGroup.VERTICAL; isSaveEnabled = false }
        val options = listOf(ApprovalDecision.ALLOW_ALWAYS to R.string.approval_always,
            ApprovalDecision.ALLOW_TEMPORARY to R.string.approval_temporary,
            ApprovalDecision.ALLOW_DAILY_QUOTA to R.string.approval_quota, ApprovalDecision.DENY to R.string.approval_deny)
        val ids = options.associate { (decision, label) ->
            val option = RadioButton(this).apply {
                id = View.generateViewId(); setText(label); textSize = 16f; minHeight = dp(48)
                isSaveEnabled = false; filterTouchesWhenObscured = true
            }
            choices.addView(option); option.id to decision
        }
        content.addView(choices)
        val caption = label(R.string.approval_minutes)
        val minutes = EditText(this).apply {
            id = View.generateViewId(); textSize = 16f; inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(5)); isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO; minHeight = dp(48)
            filterTouchesWhenObscured = true; setText(R.string.approval_default_minutes)
        }
        caption.labelFor = minutes.id; content.addView(minutes)
        caption.visibility = View.GONE; minutes.visibility = View.GONE
        choices.setOnCheckedChangeListener { _, id ->
            val timed = ids[id] in listOf(ApprovalDecision.ALLOW_TEMPORARY, ApprovalDecision.ALLOW_DAILY_QUOTA)
            caption.visibility = if (timed) View.VISIBLE else View.GONE
            minutes.visibility = caption.visibility
        }
        button(R.string.approval_review) {
            val decision = ids[choices.checkedRadioButtonId]
            if (decision == null) { status.setText(R.string.approval_choose); return@button }
            val timed = decision in listOf(ApprovalDecision.ALLOW_TEMPORARY, ApprovalDecision.ALLOW_DAILY_QUOTA)
            val count = if (timed) minutes.text.toString().takeIf { it.matches(Regex("[1-9][0-9]{0,3}")) }?.toIntOrNull() else 0
            if (count == null || timed && count !in 1..1440) {
                minutes.error = getString(R.string.approval_minutes_error); minutes.requestFocus(); return@button
            }
            val choice = ApprovalChoice(decision, count)
            content.removeAllViews(); device(offer); requestDetails(request.snapshot)
            text(decisionText(choice), 22f); label(R.string.approval_delivery_scope)
            button(R.string.approval_sign) { authenticateApproval(offer, request, choice) }
            button(R.string.native_inbox_refresh) { showRequests(offer) }
        }
        button(R.string.native_inbox_refresh) { showRequests(offer) }
    }

    private fun showPendingApproval(offer: EnrollmentOffer) = work(R.string.approval_checking,
        success = R.string.approval_status_checked, failure = R.string.approval_failed) {
        val pending = withContext(Dispatchers.IO) { ceremony.pendingApproval(offer) }
        renderPendingApproval(offer, pending)
    }

    private fun renderPendingApproval(offer: EnrollmentOffer, pending: PendingSignedEnvelope?) {
        content.removeAllViews(); device(offer)
        if (pending == null) label(R.string.approval_pending_empty) else {
            val approval = GuardWire.decodeSignedApproval(pending.exactBytes)
            label(R.string.approval_saved, 22f)
            text(getString(R.string.native_inbox_identity, requestDisplayText(approval.targetIdentity)))
            text(getString(R.string.native_inbox_request_id, approval.requestId, approval.requestRevision))
            text(decisionText(ApprovalChoice(approval.decision, approval.minutes)), 20f)
            text(getString(R.string.approval_deadline, DateFormat.getDateTimeInstance().format(Date(approval.expiryUnixMillis))))
            label(R.string.approval_delivery_scope)
            label(R.string.approval_pending_wait)
            button(R.string.approval_send) {
                work(R.string.approval_sending, success = R.string.approval_published, failure = R.string.approval_delivery_failed) {
                    withContext(Dispatchers.IO) { ceremony.openApprovalDelivery(offer).use { it.publish() } }
                    renderPendingApproval(offer, withContext(Dispatchers.IO) { ceremony.pendingApproval(offer) })
                }
            }
        }
        button(R.string.native_profile_back) { showOffer(offer) }
    }

    private fun authenticateApproval(offer: EnrollmentOffer, request: VerifiedNativeRequest, choice: ApprovalChoice) {
        if (BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            status.setText(R.string.enrollment_biometric_unavailable); return
        }
        work(R.string.approval_checking, success = R.string.approval_prompt, failure = R.string.approval_failed) {
            val operation = withContext(Dispatchers.IO) { ceremony.startApproval(offer, request, choice) }
            approvalSigning = operation
            val currentPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (approvalSigning !== operation || stopped) { operation.cancel(); return }
                    approvalSigning = null; prompt = null
                    work(R.string.approval_saving, success = R.string.approval_saved, failure = R.string.approval_failed) {
                        try {
                            require(result.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
                            val authenticated = requireNotNull(result.cryptoObject?.signature)
                            val pending = withContext(Dispatchers.IO) {
                                val active = coroutineContext
                                operation.finish(authenticated) { active.ensureActive() }
                            }
                            renderPendingApproval(offer, pending)
                        } finally { operation.cancel() }
                    }
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    operation.cancel()
                    if (approvalSigning !== operation) return
                    approvalSigning = null; prompt = null
                    status.setText(R.string.approval_cancelled); setButtons(true)
                }
                override fun onAuthenticationFailed() {
                    if (!stopped && approvalSigning === operation) status.setText(R.string.enrollment_biometric_retry)
                }
            })
            prompt = currentPrompt
            currentPrompt.authenticate(BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.approval_biometric_title)).setSubtitle(decisionText(choice))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(getString(R.string.enrollment_keep)).build(), BiometricPrompt.CryptoObject(operation.signature))
        }
    }

    private suspend fun renderNativeProfile(offer: EnrollmentOffer) {
        val expiry = withContext(Dispatchers.IO) { ceremony.openNativeProfile(offer)?.use { it.expiryUnixMillis } }
        content.removeAllViews(); device(offer)
        label(R.string.native_profile_title, 22f)
        if (expiry != null) {
            text(getString(R.string.native_profile_present, DateFormat.getDateTimeInstance().format(Date(expiry))))
            label(R.string.native_profile_scope)
            button(R.string.native_profile_check) { showNativeProfile(offer) }
        } else {
            label(R.string.native_profile_instructions)
            val caption = label(R.string.native_profile_checksum)
            val checksum = EditText(this).apply {
                id = View.generateViewId(); isSaveEnabled = false
                textSize = 16f; typeface = Typeface.MONOSPACE
                textDirection = View.TEXT_DIRECTION_LTR
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                filters = arrayOf(InputFilter.LengthFilter(65)) // Keep one excess character so oversized input cannot become valid.
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                minHeight = dp(48); filterTouchesWhenObscured = true
                setPadding(dp(8), dp(8), dp(8), dp(8))
            }
            caption.labelFor = checksum.id
            content.addView(checksum, LinearLayout.LayoutParams(-1, -2))
            button(R.string.native_profile_choose) {
                val digest = checksum.text.toString()
                // Do not silently truncate/filter pasted text into a different accepted checksum.
                if (!digest.matches(Regex("[0-9A-Fa-f]{64}"))) {
                    checksum.error = getString(R.string.native_profile_checksum_error); checksum.requestFocus()
                } else {
                    checksum.text.clear()
                    chooseNativeProfile(offer, digest)
                }
            }
        }
        button(R.string.native_profile_back) { showOffer(offer) }
    }

    private fun chooseNativeProfile(offer: EnrollmentOffer, digest: String) {
        check(displayedStage == EnrollmentStage.CONFIRMED && selectedOffer === offer)
        pickingProfile = true; profileSelection = offer to digest
        waiting?.cancel(); setButtons(false); status.setText(R.string.native_profile_choosing)
        try { profilePicker.launch(arrayOf("*/*")) }
        catch (_: Exception) {
            profileSelection = null; pickingProfile = false
            status.setText(R.string.native_profile_failed); setButtons(true)
        }
    }

    private fun profileSelected(uri: Uri?) {
        val selection = profileSelection ?: return // Ignore restored/stale results; no remembered consent.
        profileSelection = null
        scope.launch {
            val returned = withTimeoutOrNull(5000) {
                lifecycle.withResumed {
                    pickingProfile = false
                    if (selectedOffer !== selection.first || displayedStage != EnrollmentStage.CONFIRMED) {
                        status.setText(R.string.native_profile_cancelled); setButtons(true)
                    } else if (uri == null) {
                        status.setText(R.string.native_profile_cancelled); setButtons(true)
                    } else work(R.string.native_profile_loading, success = R.string.native_profile_saved,
                        failure = R.string.native_profile_failed) {
                        val bytes = NativeProfileDocument.read(contentResolver, uri)
                        withContext(Dispatchers.IO) {
                            val active = coroutineContext
                            ceremony.importNativeProfile(selection.first, bytes, selection.second) { active.ensureActive() }
                        }
                        // Reopen the actual saved ciphertext before reporting success; never claim network reachability.
                        renderNativeProfile(selection.first)
                    }
                    true
                }
            }
            if (returned == null) {
                pickingProfile = false
                if (!isDestroyed) { status.setText(R.string.native_profile_cancelled); setButtons(true) }
            }
        }
    }

    private fun authenticate(offer: EnrollmentOffer) {
        if (BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            status.setText(R.string.enrollment_biometric_unavailable); return
        }
        work(R.string.enrollment_biometric_loading) {
            val operation = withContext(Dispatchers.IO) { ceremony.startBiometric(offer) }
            signing = operation
            val currentPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (signing !== operation || stopped) { operation.cancel(); return }
                    signing = null; prompt = null
                    work(R.string.enrollment_signing) {
                        require(result.authenticationType == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
                        val authenticated = requireNotNull(result.cryptoObject?.signature)
                        val state = withContext(Dispatchers.IO) { operation.finish(authenticated) }
                        render(state, null)
                    }
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    operation.cancel()
                    if (signing !== operation) return
                    signing = null; prompt = null
                    status.setText(R.string.enrollment_biometric_cancelled); setButtons(true)
                }
                override fun onAuthenticationFailed() {
                    if (!stopped && signing === operation) status.setText(R.string.enrollment_biometric_retry)
                }
            })
            prompt = currentPrompt
            currentPrompt.authenticate(BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.enrollment_biometric_title))
                .setSubtitle(offer.deviceLabel)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(getString(R.string.enrollment_keep)).build(), BiometricPrompt.CryptoObject(operation.signature))
        }
    }

    private fun startWaiting() {
        if (!foreground || stopped || scanning || pickingProfile || signing != null || approvalSigning != null || job?.isActive == true || waiting?.isActive == true ||
            displayedStage == EnrollmentStage.CONFIRMED) return
        val offer = selectedOffer ?: return
        val previous = waiting
        waiting = scope.launch(start = CoroutineStart.LAZY) {
            try {
                previous?.join()
                ensureActive()
                awaitEnrollment(
                    inspect = {
                        require(offer.relayEndpoint == binding.canonicalRelayEndpoint)
                        withContext(Dispatchers.IO) { ceremony.inspect(offer) }
                    },
                    exchange = { withContext(Dispatchers.IO) { ceremony.synchronize(offer) }; Unit },
                    display = { state, verified, retrying ->
                        val stage = enrollmentStage(state, verified, System.currentTimeMillis())
                        // Preserve scroll position and accessibility focus while the same code is being compared.
                        if (stage != displayedStage) render(state, verified)
                        val message = if (!stage.canSynchronize) R.string.enrollment_scope else if (retrying)
                            R.string.enrollment_retrying else R.string.enrollment_auto_waiting
                        val text = getString(message)
                        if (status.text.toString() != text) status.text = text
                    })
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { if (!stopped) status.setText(R.string.enrollment_failed) }
            finally { if (waiting === coroutineContext.job) waiting = null }
        }
        waiting?.start()
    }

    // User actions first cancel/join polling. Durable files, not Activity/Bundle state, are the restart source.
    private fun work(message: Int, success: Int = R.string.enrollment_scope, failure: Int = R.string.enrollment_failed,
        action: suspend () -> Unit) {
        if (stopped || scanning || pickingProfile || job?.isActive == true || signing != null || approvalSigning != null) return
        val previous = job
        val poll = waiting
        poll?.cancel(); waiting = null
        job = scope.launch(start = CoroutineStart.LAZY) {
            status.setText(message); setButtons(false)
            try {
                previous?.join(); poll?.join(); ensureActive()
                action(); status.setText(success)
            }
            catch (_: TimeoutCancellationException) { ensureActive(); status.setText(failure) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                // Prompt construction/start may throw before it can deliver an error callback.
                // Clear the same busy operation so retry never reuses an authenticated Signature.
                signing?.cancel(); signing = null
                approvalSigning?.cancel(); approvalSigning = null
                prompt?.cancelAuthentication(); prompt = null
                status.setText(failure)
            }
            finally {
                if (job === coroutineContext.job) {
                    job = null
                    if (!stopped && !scanning && !pickingProfile && signing == null && approvalSigning == null) { setButtons(true); startWaiting() }
                }
            }
        }
        job?.start()
    }

    private fun device(offer: EnrollmentOffer) {
        text(offer.deviceLabel, 24f)
        text(getString(R.string.enrollment_device_id, offer.deviceId))
        text(getString(R.string.enrollment_relay, offer.relayEndpoint))
        text(getString(R.string.enrollment_deadline, DateFormat.getDateTimeInstance().format(Date(offer.expiryUnixMillis))))
    }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun label(id: Int, size: Float = 16f) = text(getString(id), size)
    private fun text(value: String, size: Float = 16f) = TextView(this).apply {
        text = value; textSize = size; setPadding(0, dp(8), 0, dp(8)); isSaveEnabled = false
        content.addView(this, LinearLayout.LayoutParams(-1, -2))
    }
    private fun button(id: Int, action: () -> Unit) = Button(this).apply {
        setText(id); isAllCaps = false; minHeight = dp(48); filterTouchesWhenObscured = true
        setOnClickListener { if (!stopped && !scanning && !pickingProfile && job?.isActive != true && signing == null && approvalSigning == null) action() }
        content.addView(this, LinearLayout.LayoutParams(-1, -2))
    }
    private fun setButtons(enabled: Boolean) {
        for (i in 0 until content.childCount) (content.getChildAt(i) as? Button)?.isEnabled = enabled
    }
}
