package app.guard.parent

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import app.guard.parent.security.LocatorOnlyDeepLink

/**
 * Presentation shell only. A verified snapshot is required before ApprovalCoordinator is reachable.
 * Production wiring injects encrypted transport + device-signature verifier; no insecure fallback exists.
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val language = resources.configuration.locales[0].language
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        root.addView(TextView(this).apply { text = if (language == "ru") "Guard: ожидание проверенного запроса" else "Guard: waiting for a verified request"; textSize = 20f })
        intent?.data?.let { uri ->
            val locator = runCatching { LocatorOnlyDeepLink.parse(uri) }.getOrNull()
            root.addView(TextView(this).apply { text = if (locator == null) "Invalid locator" else "Request locator received" })
        }
        setContentView(root)
    }
}
