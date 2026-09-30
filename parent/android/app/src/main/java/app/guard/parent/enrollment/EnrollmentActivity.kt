package app.guard.parent.enrollment

import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.withResumed
import app.guard.parent.BuildConfig
import app.guard.parent.R
import app.guard.parent.protocol.EnrollmentOffer
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
    private var scanning = false
    private var transcript: EnrollmentTranscript? = null
    private var signing: EnrollmentSigningOperation? = null
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
        if (!scanning) showSaved()
    }

    override fun onStop() {
        stopped = true
        signing?.cancel(); signing = null
        prompt?.cancelAuthentication(); prompt = null
        job?.cancel(); job = null
        transcript?.close(); transcript = null
        super.onStop()
    }

    override fun onDestroy() { scope.cancel(); super.onDestroy() }

    private fun showSaved() = work(R.string.enrollment_loading) {
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
        if (stage.canSynchronize) button(R.string.enrollment_update) {
            work(R.string.enrollment_sending) {
                require(state.offer.relayEndpoint == binding.canonicalRelayEndpoint)
                withContext(Dispatchers.IO) { ceremony.synchronize(state.offer) }
                val (current, verified) = withContext(Dispatchers.IO) { ceremony.inspect(state.offer) }
                render(current, verified)
            }
        }
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

    // Single foreground operation. Durable files, not Activity/Bundle state, are the restart source.
    private fun work(message: Int, action: suspend () -> Unit) {
        if (stopped || scanning || job?.isActive == true || signing != null) return
        job = scope.launch {
            status.setText(message); setButtons(false)
            try { action(); status.setText(R.string.enrollment_scope) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                // Prompt construction/start may throw before it can deliver an error callback.
                // Clear the same busy operation so retry never reuses an authenticated Signature.
                signing?.cancel(); signing = null
                prompt?.cancelAuthentication(); prompt = null
                status.setText(R.string.enrollment_failed)
            }
            finally { if (!stopped && !scanning && signing == null) setButtons(true) }
        }
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
        setOnClickListener { if (!stopped && !scanning && job?.isActive != true && signing == null) action() }
        content.addView(this, LinearLayout.LayoutParams(-1, -2))
    }
    private fun setButtons(enabled: Boolean) {
        for (i in 0 until content.childCount) (content.getChildAt(i) as? Button)?.isEnabled = enabled
    }
}
