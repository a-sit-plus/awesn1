package at.asitplus.awesn1.docs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

private const val SAMPLES_FILE_PROPERTY = "awesn1.docs.samples.file"
private val emitLock = Any()

internal fun emitAsn1JsSample(exampleId: String, der: ByteArray) {
    require(!exampleId.contains('|')) { "Sample id must not contain '|': $exampleId" }
    val targetFile = System.getProperty(SAMPLES_FILE_PROPERTY)?.takeIf { it.isNotBlank() }?.let(Path::of) ?: return
    val hexDer = der.joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
    synchronized(emitLock) {
        targetFile.parent?.let(Files::createDirectories)
        Files.writeString(
            targetFile,
            "$exampleId|$hexDer\n",
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND,
        )
    }
}
