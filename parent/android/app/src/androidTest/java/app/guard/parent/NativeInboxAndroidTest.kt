package app.guard.parent

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.guard.parent.approval.NativeInboxPageCodec
import app.guard.parent.protocol.RelayEncryptionKey
import app.guard.parent.protocol.RelayRecipient
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.PrivateKey

/** Exercise Android's ICU grammar, not the desktop JVM. No network, storage or real keys. */
@RunWith(AndroidJUnit4::class)
class NativeInboxAndroidTest {
    @Test fun emptyInboxAcceptsBothFieldOrdersAndRejectsMalformedPages() {
        val unusedKey = object : RelayEncryptionKey {
            override fun privateKey(): PrivateKey = error("Empty page must not decrypt")
            override fun publicKeySec1(): ByteArray = error("Empty page must not use a key")
        }
        val recipient = RelayRecipient("mailbox-test-0001", "phone-test-00001", 1, unusedKey)
        for (cursor in listOf(0L, NativeInboxPageCodec.MAX_CURSOR)) {
            for (json in listOf("{\"frames\":[],\"nextCursor\":$cursor}",
                " \n{ \"nextCursor\" : $cursor, \"frames\" : [ \t\r\n ] }\t")) {
                val (frames, next) = NativeInboxPageCodec.decode(json.toByteArray(), recipient, cursor)
                assertTrue(frames.isEmpty()); assertEquals(cursor, next)
            }
        }
        for (json in listOf("{}", "{\"frames\":[],\"nextCursor\":0,\"nextCursor\":0}",
            "{\"frames\":[],\"nextCursor\":00}", "{\"frames\":[],\"nextCursor\":9007199254740992}",
            "{\"frames\":[],\"nextCursor\":1}", "{\"frames\":[[]],\"nextCursor\":0}",
            "{\"frames\":[],\"nextCursor\":0}}", "{\"frames\":[],\"nextCursor\":0}\u000b")) {
            assertThrows(IllegalArgumentException::class.java) {
                NativeInboxPageCodec.decode(json.toByteArray(), recipient, 0)
            }
        }
    }
}
