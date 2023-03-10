import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.application.*
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.features.*
import io.ktor.http.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.runBlocking
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Ignore
import org.junit.Test
import org.w3c.dom.Document
import tech.libeufin.nexus.*
import tech.libeufin.nexus.bankaccount.addPaymentInitiation
import tech.libeufin.nexus.bankaccount.fetchBankAccountTransactions
import tech.libeufin.nexus.bankaccount.submitAllPaymentInitiations
import tech.libeufin.nexus.ebics.EbicsBankConnectionProtocol
import tech.libeufin.nexus.ebics.doEbicsUploadTransaction
import tech.libeufin.nexus.ebics.getEbicsSubscriberDetails
import tech.libeufin.nexus.iso20022.NexusPaymentInitiationData
import tech.libeufin.nexus.iso20022.createPain001document
import tech.libeufin.nexus.server.FetchLevel
import tech.libeufin.nexus.server.FetchSpecAllJson
import tech.libeufin.nexus.server.FetchSpecJson
import tech.libeufin.nexus.server.Pain001Data
import tech.libeufin.sandbox.*
import tech.libeufin.util.*
import tech.libeufin.util.ebics_h004.EbicsRequest
import tech.libeufin.util.ebics_h004.EbicsResponse
import tech.libeufin.util.ebics_h004.EbicsTypes

/**
 * Data to make the test server return for EBICS
 * phases.  Currently only init is supported.
 */
data class EbicsResponses(
    val init: String,
    val download: String? = null,
    val receipt: String? = null
)

/**
 * Minimal server responding always the 'init' field of a EbicsResponses
 * object to a download EBICS message.  Suitable to set arbitrary data
 * in said response.  Signs the response assuming the client is the one
 * created in MakeEnv.kt.
 */
fun getCustomEbicsServer(r: EbicsResponses, endpoint: String = "/ebicsweb"): Application.() -> Unit {
    val ret: Application.() -> Unit = {
        install(ContentNegotiation) {
            register(ContentType.Text.Xml, XMLEbicsConverter())
            register(ContentType.Text.Plain, XMLEbicsConverter())
        }
        routing {
            post(endpoint) {
                val requestDocument = this.call.receive<Document>()
                val req = requestDocument.toObject<EbicsRequest>()
                val clientKey = CryptoUtil.loadRsaPublicKey(userKeys.enc.public.encoded)
                val msgId = EbicsOrderUtil.generateTransactionId()
                val resp: EbicsResponse = if (
                    req.header.mutable.transactionPhase == EbicsTypes.TransactionPhaseType.INITIALISATION
                ) {
                    val payload = prepareEbicsPayload(r.init, clientKey)
                    EbicsResponse.createForDownloadInitializationPhase(
                        msgId,
                        1,
                        4096,
                        payload.second, // for key material
                        payload.first // actual payload
                    )
                } else {
                    // msgId doesn't have to match the one used for the init phase.
                    EbicsResponse.createForDownloadReceiptPhase(msgId, true)
                }
                val sigEbics = XMLUtil.signEbicsResponse(
                    resp,
                    CryptoUtil.loadRsaPrivateKey(bankKeys.auth.private.encoded)
                )
                call.respond(sigEbics)
            }
        }
    }
    return ret
}

/**
 * Remove @Ignore, after having put asserts along tests,
 * and having had access to runTask and TaskSchedule, that
 * are now 'private'.
 */
class DownloadAndSubmit {
    /**
     * Download a C52 report from the bank.
     */
    @Test
    fun download() {
        withNexusAndSandboxUser {
            wireTransfer(
                "bank",
                "foo",
                "default",
                "Show up in logging!",
                "TESTKUDOS:1"
            )
            wireTransfer(
                "bank",
                "foo",
                "default",
                "Exist in logging!",
                "TESTKUDOS:5"
            )
            withTestApplication(sandboxApp) {
                runBlocking {
                    fetchBankAccountTransactions(
                        client,
                        fetchSpec = FetchSpecAllJson(
                            level = FetchLevel.REPORT,
                            "foo"
                        ),
                        "foo"
                    )
                }
                transaction {
                    // FIXME: assert on the subject.
                    assert(
                        NexusBankTransactionEntity[1].amount == "1" &&
                                NexusBankTransactionEntity[2].amount == "5"
                    )
                }
            }
        }
    }
    /**
     * Upload one payment instruction to the bank.
     */
    @Test
    fun upload() {
        withNexusAndSandboxUser {
            withTestApplication(sandboxApp) {
                val conn = EbicsBankConnectionProtocol()
                runBlocking {
                    // Create Pain.001 to be submitted.
                    addPaymentInitiation(
                        Pain001Data(
                            creditorIban = getIban(),
                            creditorBic = "SANDBOXX",
                            creditorName = "Tester",
                            subject = "test payment",
                            sum = Amount(1),
                            currency = "TESTKUDOS"
                        ),
                        transaction {
                            NexusBankAccountEntity.findByName(
                                "foo"
                            ) ?: throw Exception("Test failed")
                        }
                    )
                    conn.submitPaymentInitiation(
                        client,
                        1L
                    )
                }
                transaction {
                    val payment = BankAccountTransactionEntity[1]
                    assert(payment.debtorIban == FOO_USER_IBAN &&
                            payment.subject == "test payment" &&
                            payment.direction == "DBIT"
                    )
                }
            }
        }
    }

    /**
     * Upload one payment instruction charging one IBAN
     * that does not belong to the requesting EBICS subscriber.
     */
    @Test
    fun unallowedDebtorIban() {
        withNexusAndSandboxUser {
            withTestApplication(sandboxApp) {
                runBlocking {
                    val bar = transaction { NexusBankAccountEntity.findByName("bar") }
                    val painMessage = createPain001document(
                        NexusPaymentInitiationData(
                            debtorIban = bar!!.iban,
                            debtorBic = bar.bankCode,
                            debtorName = bar.accountHolder,
                            currency = "TESTKUDOS",
                            amount = "1",
                            creditorIban = getIban(),
                            creditorName = "Get",
                            creditorBic = "SANDBOXX",
                            paymentInformationId = "entropy-0",
                            preparationTimestamp = 1970L,
                            subject = "Unallowed",
                            messageId = "entropy-1",
                            endToEndId = null,
                            instructionId = null
                        )
                    )
                    val unallowedSubscriber = transaction { getEbicsSubscriberDetails("foo") }
                    var thrown = false
                    try {
                        doEbicsUploadTransaction(
                            client,
                            unallowedSubscriber,
                            "CCT",
                            painMessage.toByteArray(Charsets.UTF_8),
                            EbicsStandardOrderParams()
                        )
                    } catch (e: EbicsProtocolError) {
                        if (e.ebicsTechnicalCode ==
                                EbicsReturnCode.EBICS_ACCOUNT_AUTHORISATION_FAILED
                        )
                            thrown = true
                    }
                    assert(thrown)
                }
            }
        }
    }

    /**
     * Submit one payment instruction with a invalid Pain.001
     * document, and check that it was marked as invalid.  Hence,
     * the error is expected only by the first submission, since
     * the second won't pick the invalid payment.
     */
    @Test
    fun invalidPain001() {
        withNexusAndSandboxUser {
            withTestApplication(sandboxApp) {
                runBlocking {
                    // Create Pain.001 to be submitted.
                    addPaymentInitiation(
                        Pain001Data(
                            creditorIban = getIban(),
                            creditorBic = "not-a-BIC",
                            creditorName = "Tester",
                            subject = "test payment",
                            sum = Amount(1),
                            currency = "TESTKUDOS"
                        ),
                        transaction {
                            NexusBankAccountEntity.findByName(
                                "foo"
                            ) ?: throw Exception("Test failed")
                        }
                    )
                    // Encounters errors.
                    var thrown = false
                    try {
                        submitAllPaymentInitiations(client, "foo")
                    } catch (e: NexusError) {
                        assert((e.code == LibeufinErrorCode.LIBEUFIN_EC_INVALID_STATE))
                        thrown = true
                    }
                    assert(thrown)
                    // No errors, since it should not retry.
                    submitAllPaymentInitiations(client, "foo")
                }
            }
        }
    }

    @Test
    fun unsupportedCurrency() {
        withNexusAndSandboxUser {
            withTestApplication(sandboxApp) {
                runBlocking {
                    // Create Pain.001 to be submitted.
                    addPaymentInitiation(
                        Pain001Data(
                            creditorIban = getIban(),
                            creditorBic = "SANDBOXX",
                            creditorName = "Tester",
                            subject = "test payment",
                            sum = Amount(1),
                            currency = "EUR"
                        ),
                        transaction {
                            NexusBankAccountEntity.findByName(
                                "foo"
                            ) ?: throw Exception("Test failed")
                        }
                    )
                    var thrown = false
                    try {
                        submitAllPaymentInitiations(client, "foo")
                    } catch (e: EbicsProtocolError) {
                        if (e.ebicsTechnicalCode == EbicsReturnCode.EBICS_PROCESSING_ERROR)
                            thrown = true
                    }
                    assert(thrown)
                }
            }
        }
    }
}