package app.guard.parent

import android.os.Bundle
import android.content.Intent
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import app.guard.parent.security.LocatorOnlyDeepLink
import app.guard.parent.enrollment.EnrollmentActivity

/**
 * Presentation shell only. A verified snapshot is required before ApprovalSigningOperation is reachable.
 * Production wiring injects encrypted transport + device-signature verifier; no insecure fallback exists.
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        root.addView(TextView(this).apply { setText(R.string.waiting_for_request); textSize = 20f })
        root.addView(TextView(this).apply { setText(R.string.development_notice) })
        root.addView(Button(this).apply {
            setText(R.string.enrollment_open)
            setOnClickListener { startActivity(Intent(this@MainActivity, EnrollmentActivity::class.java)) }
        })
        intent?.data?.let { uri ->
            val locator = runCatching { LocatorOnlyDeepLink.parse(uri) }.getOrNull()
            root.addView(TextView(this).apply { setText(if (locator == null) R.string.invalid_locator else R.string.locator_received) })
        }
        setContentView(root)
    }
}
