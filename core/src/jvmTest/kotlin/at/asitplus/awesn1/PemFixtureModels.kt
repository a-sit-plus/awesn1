package at.asitplus.awesn1

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PemOpenSslFixtureSet(
    val fixtures: List<PemOpenSslFixture> = emptyList()
)

@Serializable
data class PemOpenSslFixture(
    val file: String,
    @SerialName("expected_labels")
    val expectedLabels: List<String> = emptyList(),
    @SerialName("expected_header_names_by_block")
    val expectedHeaderNamesByBlock: List<List<String>> = emptyList()
)

@Serializable
data class PemQuirkFixtureSet(
    val cases: List<PemQuirkFixture> = emptyList()
)

@Serializable
data class PemQuirkFixture(
    val name: String,
    @SerialName("pem_lines")
    val pemLines: List<String> = emptyList(),
    @SerialName("expected_labels")
    val expectedLabels: List<String> = emptyList(),
    @SerialName("expected_header_names_by_block")
    val expectedHeaderNamesByBlock: List<List<String>> = emptyList(),
    @SerialName("should_fail")
    val shouldFail: Boolean = false
)
