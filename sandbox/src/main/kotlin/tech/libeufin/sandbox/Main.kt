/*
 * This file is part of LibEuFin.
 * Copyright (C) 2019 Stanisci and Dold.

 * LibEuFin is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation; either version 3, or
 * (at your option) any later version.

 * LibEuFin is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General
 * Public License for more details.

 * You should have received a copy of the GNU Affero General Public
 * License along with LibEuFin; see the file COPYING.  If not, see
 * <http://www.gnu.org/licenses/>
 */


/*
General thoughts:

 - since sandbox will run on the public internet for the demobank, all endpoints except
   explicitly public ones should use authentication (basic auth)
 - the authentication should be *very* simple and *not* be part of the database state.
   instead, a LIBEUFIN_SANDBOX_ADMIN_TOKEN environment variable will be used to
   set the authentication.

 - All sandbox will require the ADMIN_TOKEN, except:
   - the /ebicsweb endpoint, because EBICS handles authentication here
     (EBICS subscribers are checked)
   - the /demobank(/...) endpoints (except registration and public accounts),
     because authentication is handled by checking the demobank user credentials
 */

package tech.libeufin.sandbox

import UtilError
import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.core.util.DefaultIndenter
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.exc.MismatchedInputException
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.MissingKotlinParameterException
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.output.CliktHelpFormatter
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.int
import execThrowableOrTerminate
import io.ktor.application.*
import io.ktor.client.statement.*
import io.ktor.features.*
import io.ktor.http.*
import io.ktor.jackson.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.util.*
import io.ktor.util.date.*
import kotlinx.coroutines.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.statements.api.ExposedBlob
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.slf4j.event.Level
import org.w3c.dom.Document
import startServer
import tech.libeufin.util.*
import java.math.BigDecimal
import java.net.BindException
import java.net.URL
import java.security.interfaces.RSAPublicKey
import javax.xml.bind.JAXBContext
import kotlin.system.exitProcess

val logger: Logger = LoggerFactory.getLogger("tech.libeufin.sandbox")
const val SANDBOX_DB_ENV_VAR_NAME = "LIBEUFIN_SANDBOX_DB_CONNECTION"
private val adminPassword: String? = System.getenv("LIBEUFIN_SANDBOX_ADMIN_PASSWORD")
var WITH_AUTH = true // Needed by helpers too, hence not making it private.

// Internal error type.
data class SandboxError(
    val statusCode: HttpStatusCode,
    val reason: String,
    val errorCode: LibeufinErrorCode? = null
) : Exception(reason)

// HTTP response error type.
data class SandboxErrorJson(val error: SandboxErrorDetailJson)
data class SandboxErrorDetailJson(val type: String, val description: String)

class DefaultExchange : CliktCommand("Set default Taler exchange for a demobank.") {
    init {
        context {
            helpFormatter = CliktHelpFormatter(showDefaultValues = true)
        }
    }
    private val exchangeBaseUrl by argument("EXCHANGE-BASEURL", "base URL of the default exchange")
    private val exchangePayto by argument("EXCHANGE-PAYTO", "default exchange's payto-address")
    private val demobank by option("--demobank", help = "Which demobank defaults to EXCHANGE").default("default")

    override fun run() {
        val dbConnString = getDbConnFromEnv(SANDBOX_DB_ENV_VAR_NAME)
        execThrowableOrTerminate {
            dbCreateTables(dbConnString)
            transaction {
                val maybeDemobank: DemobankConfigEntity? = DemobankConfigEntity.find {
                    DemobankConfigsTable.name eq demobank
                }.firstOrNull()
                if (maybeDemobank == null) {
                    println("Error, demobank ${demobank} not found.")
                    exitProcess(1)
                }
                maybeDemobank.suggestedExchangeBaseUrl = exchangeBaseUrl
                maybeDemobank.suggestedExchangePayto = exchangePayto
            }
        }
    }
}

class Config : CliktCommand(
    "Insert one configuration (a.k.a. demobank) into the database."
) {
    init {
        context {
            helpFormatter = CliktHelpFormatter(showDefaultValues = true)
        }
    }

    private val nameArgument by argument(
        "NAME", help = "Name of this configuration.  Currently, only 'default' is admitted."
    )
    private val showOption by option(
        "--show",
        help = "Only show values, other options will be ignored."
    ).flag("--no-show", default = false)
    // FIXME: This really should not be a global option!
    private val captchaUrlOption by option(
        "--captcha-url", help = "Needed for browser wallets."
    ).default("https://bank.demo.taler.net/")
    private val currencyOption by option("--currency").default("EUR")
    private val bankDebtLimitOption by option("--bank-debt-limit").int().default(1000000)
    private val usersDebtLimitOption by option("--users-debt-limit").int().default(1000)
    private val allowRegistrationsOption by option(
        "--with-registrations",
        help = "(default: true)" /* mentioning here as help message did not.  */
    ).flag("--without-registrations", default = true)
    private val withSignupBonusOption by option(
        "--with-signup-bonus",
        help = "Award new customers with 100 units of currency! (default: false)"
    ).flag("--without-signup-bonus", default = false)

    override fun run() {
        val dbConnString = getDbConnFromEnv(SANDBOX_DB_ENV_VAR_NAME)
        if (nameArgument != "default") {
            println("This version admits only the 'default' name")
            exitProcess(1)
        }
        execThrowableOrTerminate {
            dbCreateTables(dbConnString)
            transaction {
                val maybeDemobank = BankAccountEntity.find(
                    BankAccountsTable.label eq "bank"
                ).firstOrNull()
                if (showOption) {
                    if (maybeDemobank != null) {
                        val ret = ObjectMapper()
                        ret.configure(SerializationFeature.INDENT_OUTPUT, true)
                        println(
                            ret.writeValueAsString(object {
                                val currency = maybeDemobank.demoBank.currency
                                val bankDebtLimit = maybeDemobank.demoBank.bankDebtLimit
                                val usersDebtLimit = maybeDemobank.demoBank.usersDebtLimit
                                val allowRegistrations = maybeDemobank.demoBank.allowRegistrations
                                val name = maybeDemobank.demoBank.name // always 'default'
                                val withSignupBonus = maybeDemobank.demoBank.withSignupBonus
                                val captchaUrl = maybeDemobank.demoBank.captchaUrl
                            })
                        )
                        return@transaction
                    }
                    println("Nothing to show")
                    return@transaction
                }
                if (maybeDemobank == null) {
                    val demoBank = DemobankConfigEntity.new {
                        currency = currencyOption
                        bankDebtLimit = bankDebtLimitOption
                        usersDebtLimit = usersDebtLimitOption
                        allowRegistrations = allowRegistrationsOption
                        name = nameArgument
                        this.withSignupBonus = withSignupBonusOption
                        captchaUrl = captchaUrlOption
                    }
                    BankAccountEntity.new {
                        iban = getIban()
                        label = "bank" // used by the wire helper
                        owner = "bank" // used by the person name finder
                        // For now, the model assumes always one demobank
                        this.demoBank = demoBank
                    }
                    return@transaction
                }
                println("Overriding existing values")
                maybeDemobank.demoBank.currency = currencyOption
                maybeDemobank.demoBank.bankDebtLimit = bankDebtLimitOption
                maybeDemobank.demoBank.usersDebtLimit = usersDebtLimitOption
                maybeDemobank.demoBank.allowRegistrations = allowRegistrationsOption
                maybeDemobank.demoBank.withSignupBonus = withSignupBonusOption
                maybeDemobank.demoBank.name = nameArgument
                maybeDemobank.demoBank.captchaUrl = captchaUrlOption
            }
        }
    }
}

/**
 * This command generates Camt53 statements - for all the bank accounts -
 * every time it gets run. The statements are only stored into the database.
 * The user should then query either via Ebics or via the JSON interface,
 * in order to retrieve their statements.
 */
class Camt053Tick : CliktCommand(
    "Make a new Camt.053 time tick; all the fresh transactions" +
            " will be inserted in a new Camt.053 report"
) {
    override fun run() {
        val dbConnString = getDbConnFromEnv(SANDBOX_DB_ENV_VAR_NAME)
        Database.connect(dbConnString)
        dbCreateTables(dbConnString)
        transaction {
            BankAccountEntity.all().forEach { accountIter ->
                // Map of 'account name' -> fresh history
                val histories = mutableMapOf<String, MutableList<RawPayment>>()
                BankAccountFreshTransactionEntity.all().forEach {
                    val bankAccountLabel = it.transactionRef.account.label
                    histories.putIfAbsent(bankAccountLabel, mutableListOf())
                    val historyIter = histories[bankAccountLabel]
                    historyIter?.add(getHistoryElementFromTransactionRow(it))
                }
                /**
                 * Resorting the closing (CLBD) balance of the last statement; will
                 * become the PRCD balance of the _new_ one.
                 */
                val lastBalance = getLastBalance(accountIter)
                val balanceClbd = balanceForAccount(
                    history = histories[accountIter.label] ?: mutableListOf(),
                    baseBalance = lastBalance
                )
                val camtData = buildCamtString(
                    53,
                    accountIter.iban,
                    histories[accountIter.label] ?: mutableListOf(),
                    balanceClbd = balanceClbd,
                    balancePrcd = lastBalance
                )
                BankAccountStatementEntity.new {
                    statementId = camtData.messageId
                    creationTime = getUTCnow().toInstant().epochSecond
                    xmlMessage = camtData.camtMessage
                    bankAccount = accountIter
                    this.balanceClbd = balanceClbd.toPlainString()
                }
            }
            BankAccountFreshTransactionsTable.deleteAll()
        }
    }
}

class MakeTransaction : CliktCommand("Wire-transfer money between Sandbox bank accounts") {
    init {
        context {
            helpFormatter = CliktHelpFormatter(showDefaultValues = true)
        }
    }

    private val creditAccount by option(help = "Label of the bank account receiving the payment").required()
    private val debitAccount by option(help = "Label of the bank account issuing the payment").required()
    private val demobankArg by option("--demobank", help = "Which Demobank books this transaction").default("default")
    private val amount by argument("AMOUNT", "Amount, in the CUR:X.Y format")
    private val subjectArg by argument("SUBJECT", "Payment's subject")

    override fun run() {
        val dbConnString = getDbConnFromEnv(SANDBOX_DB_ENV_VAR_NAME)
        Database.connect(dbConnString)
        // Refuse to operate without a default demobank.
        val demobank = getDemobank("default")
        if (demobank == null) {
            println("Sandbox cannot operate without a 'default' demobank.")
            println("Please make one with the 'libeufin-sandbox config' command.")
            exitProcess(1)
        }
        try {
            wireTransfer(debitAccount, creditAccount, demobankArg, subjectArg, amount)
        } catch (e: SandboxError) {
            print(e.message)
            exitProcess(1)
        } catch (e: Exception) {
            // Here, Sandbox is in a highly unstable state.
            println(e)
            exitProcess(1)
        }
    }
}

class ResetTables : CliktCommand("Drop all the tables from the database") {
    init {
        context {
            helpFormatter = CliktHelpFormatter(showDefaultValues = true)
        }
    }

    override fun run() {
        val dbConnString = getDbConnFromEnv(SANDBOX_DB_ENV_VAR_NAME)
        execThrowableOrTerminate {
            dbDropTables(dbConnString)
            dbCreateTables(dbConnString)
        }
    }
}

class Serve : CliktCommand("Run sandbox HTTP server") {
    init {
        context {
            helpFormatter = CliktHelpFormatter(showDefaultValues = true)
        }
    }
    private val auth by option(
        "--auth",
        help = "Disable authentication."
    ).flag("--no-auth", default = true)
    private val localhostOnly by option(
        "--localhost-only",
        help = "Bind only to localhost.  On all interfaces otherwise"
    ).flag("--no-localhost-only", default = true)
    private val ipv4Only by option(
        "--ipv4-only",
        help = "Bind only to ipv4"
    ).flag(default = false)
    private val logLevel by option()
    private val port by option().int().default(5000)
    private val withUnixSocket by option(
        help = "Bind the Sandbox to the Unix domain socket at PATH.  Overrides" +
                " --port, when both are given", metavar = "PATH"
    )
    override fun run() {
        WITH_AUTH = auth
        setLogLevel(logLevel)
        if (WITH_AUTH && adminPassword == null) {
            println("Error: auth is enabled, but env LIBEUFIN_SANDBOX_ADMIN_PASSWORD is not."
            + " (Option --no-auth exists for tests)")
            exitProcess(1)
        }
        execThrowableOrTerminate { dbCreateTables(getDbConnFromEnv(SANDBOX_DB_ENV_VAR_NAME)) }
        // Refuse to operate without a 'default' demobank.
        val demobank = getDemobank("default")
        if (demobank == null) {
            println("Sandbox cannot operate without a 'default' demobank.")
            println("Please make one with the 'libeufin-sandbox config' command.")
            exitProcess(1)
        }
        if (withUnixSocket != null) {
            startServer(
                withUnixSocket ?: throw Exception("Could not use the Unix domain socket path value!"),
                app = sandboxApp
            )
            exitProcess(0)
        }
        serverMain(port, localhostOnly, ipv4Only)
    }
}

private fun getJsonFromDemobankConfig(fromDb: DemobankConfigEntity): Demobank {
    return Demobank(
        currency = fromDb.currency,
        userDebtLimit = fromDb.usersDebtLimit,
        bankDebtLimit = fromDb.bankDebtLimit,
        allowRegistrations = fromDb.allowRegistrations,
        name = fromDb.name
    )
}
fun findEbicsSubscriber(partnerID: String, userID: String, systemID: String?): EbicsSubscriberEntity? {
    return if (systemID == null) {
        EbicsSubscriberEntity.find {
            (EbicsSubscribersTable.partnerId eq partnerID) and (EbicsSubscribersTable.userId eq userID)
        }
    } else {
        EbicsSubscriberEntity.find {
            (EbicsSubscribersTable.partnerId eq partnerID) and
                    (EbicsSubscribersTable.userId eq userID) and
                    (EbicsSubscribersTable.systemId eq systemID)
        }
    }.firstOrNull()
}

data class SubscriberKeys(
    val authenticationPublicKey: RSAPublicKey,
    val encryptionPublicKey: RSAPublicKey,
    val signaturePublicKey: RSAPublicKey
)

data class EbicsHostPublicInfo(
    val hostID: String,
    val encryptionPublicKey: RSAPublicKey,
    val authenticationPublicKey: RSAPublicKey
)

data class BankAccountInfo(
    val label: String,
    val name: String,
    val iban: String,
    val bic: String,
)

inline fun <reified T> Document.toObject(): T {
    val jc = JAXBContext.newInstance(T::class.java)
    val m = jc.createUnmarshaller()
    return m.unmarshal(this, T::class.java).value
}

fun ensureNonNull(param: String?): String {
    return param ?: throw SandboxError(
        HttpStatusCode.BadRequest, "Bad ID given: $param"
    )
}

class SandboxCommand : CliktCommand(invokeWithoutSubcommand = true, printHelpOnEmptyArgs = true) {
    init {
        versionOption(getVersion())
    }

    override fun run() = Unit
}

fun main(args: Array<String>) {
    SandboxCommand().subcommands(
        Serve(),
        ResetTables(),
        Config(),
        MakeTransaction(),
        Camt053Tick(),
        DefaultExchange()
    ).main(args)
}

suspend inline fun <reified T : Any> ApplicationCall.receiveJson(): T {
    try {
        return this.receive()
    } catch (e: MissingKotlinParameterException) {
        throw SandboxError(HttpStatusCode.BadRequest, "Missing value for ${e.pathReference}")
    } catch (e: MismatchedInputException) {
        // Note: POSTing "[]" gets here but e.pathReference is blank.
        throw SandboxError(HttpStatusCode.BadRequest, "Invalid value for '${e.pathReference}'")
    } catch (e: JsonParseException) {
        throw SandboxError(HttpStatusCode.BadRequest, "Invalid JSON")
    }
}

fun setJsonHandler(ctx: ObjectMapper) {
    ctx.enable(SerializationFeature.INDENT_OUTPUT)
    ctx.setDefaultPrettyPrinter(DefaultPrettyPrinter().apply {
        indentArraysWith(DefaultPrettyPrinter.FixedSpaceIndenter.instance)
        indentObjectsWith(DefaultIndenter("  ", "\n"))
    })
    ctx.registerModule(KotlinModule(nullisSameAsDefault = true))
}

val sandboxApp: Application.() -> Unit = {
    install(CallLogging) {
        this.level = Level.DEBUG
        this.logger = tech.libeufin.sandbox.logger
        this.format { call ->
            "${call.response.status()}, ${call.request.httpMethod.value} ${call.request.path()}"
        }
    }
    install(CORS) {
        anyHost()
        header(HttpHeaders.Authorization)
        header(HttpHeaders.ContentType)
        method(HttpMethod.Options)
        // logger.info("Enabling CORS (assuming no endpoint uses cookies).")
        allowCredentials = true
    }
    install(IgnoreTrailingSlash)
    install(ContentNegotiation) {
        register(ContentType.Text.Xml, XMLEbicsConverter())
        /**
         * Content type "text" must go to the XML parser
         * because Nexus can't set explicitly the Content-Type
         * (see https://github.com/ktorio/ktor/issues/1127) to
         * "xml" and the request made gets somehow assigned the
         * "text/plain" type:  */
        register(ContentType.Text.Plain, XMLEbicsConverter())
        jackson(contentType = ContentType.Application.Json) { setJsonHandler(this) }
        /**
         * Make jackson the default parser.  It runs also when
         * the Content-Type request header is missing. */
        jackson(contentType = ContentType.Any) { setJsonHandler(this) }
    }
    install(StatusPages) {
        // Bank's fault: it should check the operands.  Respond 500
        exception<ArithmeticException> { cause ->
            logger.error("Exception while handling '${call.request.uri}', ${cause.stackTraceToString()}")
            call.respond(
                HttpStatusCode.InternalServerError,
                SandboxErrorJson(
                    error = SandboxErrorDetailJson(
                        type = "sandbox-error",
                        description = cause.message ?: "Bank's error: arithmetic exception."
                    )
                )
            )
        }
        exception<SandboxError> { cause ->
            logger.error("Exception while handling '${call.request.uri}', ${cause.reason}")
            call.respond(
                cause.statusCode,
                SandboxErrorJson(
                    error = SandboxErrorDetailJson(
                        type = "sandbox-error",
                        description = cause.reason
                    )
                )
            )
        }
        exception<UtilError> { cause ->
            logger.error("Exception while handling '${call.request.uri}', ${cause.reason}")
            call.respond(
                cause.statusCode,
                SandboxErrorJson(
                    error = SandboxErrorDetailJson(
                        type = "util-error",
                        description = cause.reason
                    )
                )
            )
        }
        // Catch-all error, respond 500 because the bank didn't handle it.
        exception<Throwable> { cause ->
            logger.error("Exception while handling '${call.request.uri}'", cause.stackTrace)
            call.respond(
                HttpStatusCode.InternalServerError,
                SandboxErrorJson(
                    error = SandboxErrorDetailJson(
                        type = "sandbox-error",
                        description = cause.message ?: "Bank's error: unhandled exception."
                    )
                )
            )
        }
        exception<EbicsRequestError> { e ->
            logger.info("Handling EbicsRequestError: ${e.message}")
            respondEbicsTransfer(call, e.errorText, e.errorCode)
        }
    }
    intercept(ApplicationCallPipeline.Setup) {
        val ac: ApplicationCall = call
        ac.attributes.put(WITH_AUTH_ATTRIBUTE_KEY, WITH_AUTH)
        if (WITH_AUTH) {
            if(adminPassword == null) {
                throw internalServerError(
                    "Sandbox has no admin password defined." +
                            " Please define LIBEUFIN_SANDBOX_ADMIN_PASSWORD in the environment, " +
                            "or launch with --no-auth."

                )
            }
            ac.attributes.put(
                ADMIN_PASSWORD_ATTRIBUTE_KEY,
                adminPassword
            )
        }
        return@intercept
    }
    intercept(ApplicationCallPipeline.Fallback) {
        if (this.call.response.status() == null) {
            call.respondText(
                "Not found (no route matched).\n",
                io.ktor.http.ContentType.Text.Plain,
                io.ktor.http.HttpStatusCode.NotFound
            )
            return@intercept finish()
        }
    }
    routing {

        get("/") {
            call.respondText(
                "Hello, this is the Sandbox\n",
                ContentType.Text.Plain
            )
        }
        // Respond with the last statement of the requesting account.
        // Query details in the body.
        post("/admin/payments/camt") {
            val username = call.request.basicAuth()
            val body = call.receiveJson<CamtParams>()
            if (body.type != 53) throw SandboxError(
                HttpStatusCode.NotFound,
                "Only Camt.053 documents can be generated."
            )
            if (!allowOwnerOrAdmin(username, body.bankaccount))
                throw unauthorized("User '${username}' has no rights over" +
                        " bank account '${body.bankaccount}'")
            val camtMessage = transaction {
                val bankaccount = getBankAccountFromLabel(
                    body.bankaccount,
                    getDefaultDemobank()
                )
                BankAccountStatementEntity.find {
                    BankAccountStatementsTable.bankAccount eq bankaccount.id
                }.lastOrNull()?.xmlMessage ?: throw SandboxError(
                    HttpStatusCode.NotFound,
                    "Could not find any statements; please wait next tick"
                )
            }
            call.respondText(
                camtMessage, ContentType.Text.Xml, HttpStatusCode.OK
            )
            return@post
        }

        /**
         * Create a new bank account, no EBICS relation.  Okay
         * to let a user, since having a particular username allocates
         * already a bank account with such label.
         */
        post("/admin/bank-accounts/{label}") {
            val username = call.request.basicAuth()
            val body = call.receiveJson<BankAccountInfo>()
            if (!allowOwnerOrAdmin(username, body.label))
                throw unauthorized("User '$username' has no rights over" +
                        " bank account '${body.label}'"
                )
            transaction {
                val maybeBankAccount = BankAccountEntity.find {
                    BankAccountsTable.label eq body.label
                }.firstOrNull()
                if (maybeBankAccount != null)
                    throw conflict("Bank account '${body.label}' exist already")
                BankAccountEntity.new {
                    iban = body.iban
                    bic = body.bic
                    label = body.label
                    /**
                     * The null username case exist when auth is
                     * disabled.  In this case, we assign the bank
                     * account to 'admin'.
                     */
                    owner = username ?: "admin"
                    demoBank = getDefaultDemobank()
                }
            }
            call.respond(object {})
            return@post
        }

        // Information about one bank account.
        get("/admin/bank-accounts/{label}") {
            val username = call.request.basicAuth()
            val label = call.getUriComponent("label")
            val ret = transaction {
                val demobank = getDefaultDemobank()
                val bankAccount = getBankAccountFromLabel(label, demobank)
                if (!allowOwnerOrAdmin(username, label))
                    throw unauthorized("'${username}' has no rights over '$label'")
                val balance = balanceForAccount(bankAccount)
                object {
                    val balance = "${bankAccount.demoBank.currency}:${balance}"
                    val iban = bankAccount.iban
                    val bic = bankAccount.bic
                    val label = bankAccount.label
                }
            }
            call.respond(ret)
            return@get
        }

        // Book one incoming payment for the requesting account.
        // The debtor is not required to have an account at this Sandbox.
        post("/admin/bank-accounts/{label}/simulate-incoming-transaction") {
            call.request.basicAuth(onlyAdmin = true)
            val body = call.receiveJson<IncomingPaymentInfo>()
            val accountLabel = ensureNonNull(call.parameters["label"])
            val reqDebtorBic = body.debtorBic
            if (reqDebtorBic != null && !validateBic(reqDebtorBic)) {
                throw SandboxError(
                    HttpStatusCode.BadRequest,
                    "invalid BIC"
                )
            }
            val (amount, currency) = parseAmountAsString(body.amount)
            transaction {
                val demobank = getDefaultDemobank()
                /**
                 * This API needs compatibility with the currency-less format.
                 */
                if (currency != null) {
                    if (currency != demobank.currency)
                        throw SandboxError(HttpStatusCode.BadRequest, "Currency ${currency} not supported.")
                }
                val account = getBankAccountFromLabel(
                    accountLabel, demobank
                )
                val randId = getRandomString(16)
                val customer = getCustomer(accountLabel)
                BankAccountTransactionEntity.new {
                    creditorIban = account.iban
                    creditorBic = account.bic
                    creditorName = customer.name ?: "Name not given."
                    debtorIban = body.debtorIban
                    debtorBic = reqDebtorBic
                    debtorName = body.debtorName
                    subject = body.subject
                    this.amount = amount
                    date = getUTCnow().toInstant().toEpochMilli()
                    accountServicerReference = "sandbox-$randId"
                    this.account = account
                    direction = "CRDT"
                    this.demobank = demobank
                    this.currency = demobank.currency
                }
            }
            call.respond(object {})
        }
        // Associates a new bank account with an existing Ebics subscriber.
        post("/admin/ebics/bank-accounts") {
            call.request.basicAuth(onlyAdmin = true)
            val body = call.receiveJson<EbicsBankAccountRequest>()
            if (body.owner != body.label)
                throw conflict(
                    "Customer username '${body.owner}'" +
                            " differs from bank account name '${body.label}'"
                )
            if (!validateBic(body.bic)) {
                throw SandboxError(HttpStatusCode.BadRequest, "invalid BIC (${body.bic})")
            }
            transaction {
                val subscriber = getEbicsSubscriberFromDetails(
                    body.subscriber.userID,
                    body.subscriber.partnerID,
                    body.subscriber.hostID
                )
                if (subscriber.bankAccount != null)
                    throw conflict("subscriber has already a bank account: ${subscriber.bankAccount?.label}")
                val demobank = getDefaultDemobank()
                /**
                 * Checking that the default demobank doesn't have already the
                 * requested IBAN and bank account label.
                 */
                val check = BankAccountEntity.find {
                    BankAccountsTable.iban eq body.iban or (
                            (BankAccountsTable.label eq body.label) and (
                                    BankAccountsTable.demoBank eq demobank.id
                                    )
                            )
                }.count()
                if (check > 0) throw SandboxError(
                    HttpStatusCode.BadRequest,
                    "Either IBAN or account label were already taken; please choose fresh ones"
                )
                subscriber.bankAccount = BankAccountEntity.new {
                    iban = body.iban
                    bic = body.bic
                    label = body.label
                    owner = body.owner
                    demoBank = demobank
                }
            }
            call.respondText("Bank account created")
            return@post
        }

        // Information about all the default demobank's bank accounts
        get("/admin/bank-accounts") {
            call.request.basicAuth(onlyAdmin = true)
            val accounts = mutableListOf<BankAccountInfo>()
            transaction {
                val demobank = getDefaultDemobank()
                BankAccountEntity.find {
                    BankAccountsTable.demoBank eq demobank.id
                }.forEach {
                    accounts.add(
                        BankAccountInfo(
                            label = it.label,
                            bic = it.bic,
                            iban = it.iban,
                            name = "Bank account owner's name"
                        )
                    )
                }
            }
            call.respond(accounts)
        }

        // Details of all the transactions of one bank account.
        get("/admin/bank-accounts/{label}/transactions") {
            val username = call.request.basicAuth()
            val ret = AccountTransactions()
            val accountLabel = ensureNonNull(call.parameters["label"])
            if (!allowOwnerOrAdmin(username, accountLabel))
                throw unauthorized("Requesting user '${username}'" +
                        " has no rights over bank account '${accountLabel}'"
            )
            transaction {
                val demobank = getDefaultDemobank()
                val account = getBankAccountFromLabel(accountLabel, demobank)
                BankAccountTransactionEntity.find {
                    BankAccountTransactionsTable.account eq account.id
                }.forEach {
                    ret.payments.add(
                        PaymentInfo(
                            accountLabel = account.label,
                            creditorIban = it.creditorIban,
                            accountServicerReference = it.accountServicerReference,
                            paymentInformationId = it.pmtInfId,
                            debtorIban = it.debtorIban,
                            subject = it.subject,
                            date = GMTDate(it.date).toHttpDate(),
                            amount = it.amount,
                            creditorBic = it.creditorBic,
                            creditorName = it.creditorName,
                            debtorBic = it.debtorBic,
                            debtorName = it.debtorName,
                            currency = it.currency,
                            creditDebitIndicator = when (it.direction) {
                                "CRDT" -> "credit"
                                "DBIT" -> "debit"
                                else -> throw Error("invalid direction")
                            }
                        )
                    )
                }
            }
            call.respond(ret)
        }
        /**
         * Generate one incoming and one outgoing transactions for
         * one bank account.  Counterparts do not need to have an account
         * at this Sandbox.
         */
        post("/admin/bank-accounts/{label}/generate-transactions") {
            call.request.basicAuth(onlyAdmin = true)
            transaction {
                val accountLabel = ensureNonNull(call.parameters["label"])
                val demobank = getDefaultDemobank()
                val account = getBankAccountFromLabel(accountLabel, demobank)
                val transactionReferenceCrdt = getRandomString(8)
                val transactionReferenceDbit = getRandomString(8)

                run {
                    val amount = kotlin.random.Random.nextLong(5, 25)
                    BankAccountTransactionEntity.new {
                        creditorIban = account.iban
                        creditorBic = account.bic
                        creditorName = "Creditor Name"
                        debtorIban = "DE64500105178797276788"
                        debtorBic = "DEUTDEBB101"
                        debtorName = "Max Mustermann"
                        subject = "sample transaction $transactionReferenceCrdt"
                        this.amount = amount.toString()
                        date = getUTCnow().toInstant().toEpochMilli()
                        accountServicerReference = transactionReferenceCrdt
                        this.account = account
                        direction = "CRDT"
                        this.demobank = demobank
                        currency = demobank.currency
                    }
                }

                run {
                    val amount = kotlin.random.Random.nextLong(5, 25)

                    BankAccountTransactionEntity.new {
                        debtorIban = account.iban
                        debtorBic = account.bic
                        debtorName = "Debitor Name"
                        creditorIban = "DE64500105178797276788"
                        creditorBic = "DEUTDEBB101"
                        creditorName = "Max Mustermann"
                        subject = "sample transaction $transactionReferenceDbit"
                        this.amount = amount.toString()
                        date = getUTCnow().toInstant().toEpochMilli()
                        accountServicerReference = transactionReferenceDbit
                        this.account = account
                        direction = "DBIT"
                        this.demobank = demobank
                        currency = demobank.currency
                    }
                }
            }
            call.respond(object {})
        }

        /**
         * Create a new EBICS subscriber without associating
         * a bank account to it.  Currently every registered
         * user is allowed to call this.
         */
        post("/admin/ebics/subscribers") {
            call.request.basicAuth(onlyAdmin = true)
            val body = call.receiveJson<EbicsSubscriberObsoleteApi>()
            transaction {
                // Check it exists first.
                val maybeSubscriber = EbicsSubscriberEntity.find {
                    EbicsSubscribersTable.userId eq body.userID and (
                            EbicsSubscribersTable.partnerId eq body.partnerID
                            ) and (
                            EbicsSubscribersTable.systemId eq body.systemID
                                    )
                }.firstOrNull()
                if (maybeSubscriber != null) throw conflict("EBICS subscriber exists already")
                EbicsSubscriberEntity.new {
                    partnerId = body.partnerID
                    userId = body.userID
                    systemId = null
                    hostId = body.hostID
                    state = SubscriberState.NEW
                    nextOrderID = 1
                }
            }
            call.respondText(
                "Subscriber created.",
                ContentType.Text.Plain, HttpStatusCode.OK
            )
            return@post
        }

        // Shows details of all the EBICS subscribers of this Sandbox.
        get("/admin/ebics/subscribers") {
            call.request.basicAuth(onlyAdmin = true)
            val ret = AdminGetSubscribers()
            transaction {
                EbicsSubscriberEntity.all().forEach {
                    ret.subscribers.add(
                        EbicsSubscriberInfo(
                            userID = it.userId,
                            partnerID = it.partnerId,
                            hostID = it.hostId,
                            demobankAccountLabel = it.bankAccount?.label ?: "not associated yet"
                        )
                    )
                }
            }
            call.respond(ret)
            return@get
        }

        // Change keys used in the EBICS communications.
        post("/admin/ebics/hosts/{hostID}/rotate-keys") {
            call.request.basicAuth(onlyAdmin = true)
            val hostID: String = call.parameters["hostID"] ?: throw SandboxError(
                io.ktor.http.HttpStatusCode.BadRequest, "host ID missing in URL"
            )
            transaction {
                val host = EbicsHostEntity.find {
                    EbicsHostsTable.hostID eq hostID
                }.firstOrNull() ?: throw SandboxError(
                    HttpStatusCode.NotFound, "Host $hostID not found"
                )
                val pairA = CryptoUtil.generateRsaKeyPair(2048)
                val pairB = CryptoUtil.generateRsaKeyPair(2048)
                val pairC = CryptoUtil.generateRsaKeyPair(2048)
                host.authenticationPrivateKey = ExposedBlob(pairA.private.encoded)
                host.encryptionPrivateKey = ExposedBlob(pairB.private.encoded)
                host.signaturePrivateKey = ExposedBlob(pairC.private.encoded)
            }
            call.respondText(
                "Keys of '${hostID}' rotated.",
                ContentType.Text.Plain,
                HttpStatusCode.OK
            )
            return@post
        }

        // Create a new EBICS host
        post("/admin/ebics/hosts") {
            call.request.basicAuth(onlyAdmin = true)
            val req = call.receiveJson<EbicsHostCreateRequest>()
            val pairA = CryptoUtil.generateRsaKeyPair(2048)
            val pairB = CryptoUtil.generateRsaKeyPair(2048)
            val pairC = CryptoUtil.generateRsaKeyPair(2048)
            transaction {
                EbicsHostEntity.new {
                    this.ebicsVersion = req.ebicsVersion
                    this.hostId = req.hostID
                    this.authenticationPrivateKey = ExposedBlob(pairA.private.encoded)
                    this.encryptionPrivateKey = ExposedBlob(pairB.private.encoded)
                    this.signaturePrivateKey = ExposedBlob(pairC.private.encoded)
                }
            }
            call.respondText(
                "Host '${req.hostID}' created.",
                ContentType.Text.Plain,
                HttpStatusCode.OK
            )
            return@post
        }

        // Show the names of all the Ebics hosts
        get("/admin/ebics/hosts") {
            call.request.basicAuth(onlyAdmin = true)
            val ebicsHosts = transaction {
                EbicsHostEntity.all().map { it.hostId }
            }
            call.respond(EbicsHostsResponse(ebicsHosts))
        }
        // Process one EBICS request
        post("/ebicsweb") {
            try {
                call.ebicsweb()
            }
            /**
             * The catch blocks try to extract a EBICS error message from the
             * exception type being handled.  NOT (double) logging under each
             * catch block as ultimately the registered exception handler is expected
             * to log. */
            catch (e: UtilError) {
                throw EbicsProcessingError("Serving EBICS threw unmanaged UtilError: ${e.reason}")
            }
            catch (e: SandboxError) {
                val payload: String = e.message ?: e.stackTraceToString()
                logger.info(payload)
                // Should translate to EBICS error code.
                when (e.errorCode) {
                    LibeufinErrorCode.LIBEUFIN_EC_INVALID_STATE -> throw EbicsProcessingError("Invalid bank state.")
                    LibeufinErrorCode.LIBEUFIN_EC_INCONSISTENT_STATE -> throw EbicsProcessingError("Inconsistent bank state.")
                    else -> throw EbicsProcessingError("Unknown LibEuFin error code: ${e.errorCode}.")
                }
            }
            catch (e: EbicsNoDownloadDataAvailable) {
                respondEbicsTransfer(call, e.errorText, e.errorCode)
            }
            catch (e: EbicsRequestError) {
                // Preventing the last catch-all block
                // from capturing a known type.
                throw e
            }
            catch (e: Exception) {
                throw EbicsProcessingError("Could not map error to EBICS code: $e")
            }
            return@post
        }

        /**
         * Create a new demobank instance with a particular currency,
         * debt limit and possibly other configuration
         * (could also be a CLI command for now)
         */
        post("/demobanks") {
            throw NotImplementedError("Feature only available at the libeufin-sandbox CLI")
        }

        get("/demobanks") {
            expectAdmin(call.request.basicAuth())
            val ret = object { val demoBanks = mutableListOf<Demobank>() }
            transaction {
                DemobankConfigEntity.all().forEach {
                    ret.demoBanks.add(getJsonFromDemobankConfig(it))
                }
            }
            call.respond(ret)
            return@get
        }

        /**
         * Requests falling here may only be generated by links
         * defined after the Python bank.  This redirect is a workaround
         * to avoid 404.
         */
        get("/demobanks/{demobankid}/{lang?}/{register?}") {
            val demobankId = ensureNonNull(call.parameters["demobankid"])
            var url = "${call.request.getBaseUrl()}demobanks/$demobankId"
            call.respondRedirect(url,true)
            return@get
        }
        get("/demobanks/{demobankid}") {
            val demobank = ensureDemobank(call)
            expectAdmin(call.request.basicAuth())
            call.respond(getJsonFromDemobankConfig(demobank))
            return@get
        }

        route("/demobanks/{demobankid}") {
            // NOTE: TWG assumes that username == bank account label.
            route("/taler-wire-gateway") {
                post("/{exchangeUsername}/admin/add-incoming") {
                    val username = call.getUriComponent("exchangeUsername")
                    val usernameAuth = call.request.basicAuth()
                    if (username != usernameAuth) {
                        throw forbidden(
                            "Bank account name and username differ: $username vs $usernameAuth"
                        )
                    }
                    logger.debug("TWG add-incoming passed authentication")
                    val body = try {
                        call.receiveJson<TWGAdminAddIncoming>()
                    } catch (e: Exception) {
                        logger.error("/admin/add-incoming failed at parsing the request body")
                        throw SandboxError(
                            HttpStatusCode.BadRequest,
                            "Invalid request"
                        )
                    }
                    transaction {
                        val demobank = ensureDemobank(call)
                        val bankAccountCredit = getBankAccountFromLabel(username, demobank)
                        if (bankAccountCredit.owner != username) throw forbidden(
                            "User '$username' cannot access bank account with label: $username."
                        )
                        val bankAccountDebit = getBankAccountFromPayto(body.debit_account)
                        logger.debug("TWG add-incoming about to wire transfer")
                        wireTransfer(
                            bankAccountDebit.label,
                            bankAccountCredit.label,
                            demobank.name,
                            body.reserve_pub,
                            body.amount
                        )
                        logger.debug("TWG add-incoming has wire transferred")
                    }
                    call.respond(object {})
                    return@post
                }
            }
            // Talk to wallets.
            route("/integration-api") {
                get("/config") {
                    val demobank = ensureDemobank(call)
                    call.respond(SandboxConfig(
                        name = "taler-bank-integration",
                        version = "0:0:0",
                        currency = demobank.currency
                    ))
                    return@get
                }
                post("/withdrawal-operation/{wopid}") {
                    val wopid: String = ensureNonNull(call.parameters["wopid"])
                    val body = call.receiveJson<TalerWithdrawalSelection>()
                    val transferDone = transaction {
                        val wo = TalerWithdrawalEntity.find {
                            TalerWithdrawalsTable.wopid eq java.util.UUID.fromString(wopid)
                        }.firstOrNull() ?: throw SandboxError(
                            HttpStatusCode.NotFound, "Withdrawal operation $wopid not found."
                        )
                        if (wo.confirmationDone) {
                            return@transaction true
                        }
                        if (wo.selectionDone) {
                            if (body.reserve_pub != wo.reservePub) throw SandboxError(
                                HttpStatusCode.Conflict,
                                "Selecting a different reserve from the one already selected"
                            )
                            if (body.selected_exchange != wo.selectedExchangePayto) throw SandboxError(
                                HttpStatusCode.Conflict,
                                "Selecting a different exchange from the one already selected"
                            )
                            return@transaction false
                        }
                        // Flow here means never selected, hence must as well never be paid.
                        if (wo.confirmationDone) throw internalServerError(
                            "Withdrawal ${wo.wopid} knew NO exchange and reserve pub, " +
                                    "but is marked as paid!"
                        )
                        wo.reservePub = body.reserve_pub
                        wo.selectedExchangePayto = body.selected_exchange
                        wo.selectionDone = true
                        false
                    }
                    call.respond(object {
                        val transfer_done: Boolean = transferDone
                    })
                    return@post
                }
                get("/withdrawal-operation/{wopid}") {
                    val wopid: String = ensureNonNull(call.parameters["wopid"])
                    val wo = transaction {
                        TalerWithdrawalEntity.find {
                            TalerWithdrawalsTable.wopid eq java.util.UUID.fromString(wopid)
                        }.firstOrNull() ?: throw SandboxError(
                            HttpStatusCode.NotFound,
                            "Withdrawal operation: $wopid not found"
                        )
                    }
                    val demobank = ensureDemobank(call)
                    var captcha_page = demobank.captchaUrl
                    if (captcha_page == null) logger.warn("CAPTCHA URL not found")
                    val ret = TalerWithdrawalStatus(
                        selection_done = wo.selectionDone,
                        transfer_done = wo.confirmationDone,
                        amount = "${demobank.currency}:${wo.amount}",
                        suggested_exchange = demobank.suggestedExchangeBaseUrl,
                        aborted = wo.aborted,
                        confirm_transfer_url = captcha_page
                    )
                    call.respond(ret)
                    return@get
                }
            }
            // Talk to Web UI.
            route("/access-api") {
                post("/accounts/{account_name}/transactions") {
                    val bankAccount = getBankAccountWithAuth(call)
                    val req = call.receiveJson<NewTransactionReq>()
                    val payto = parsePayto(req.paytoUri)
                    val amount: String? = payto.amount ?: req.amount
                    if (amount == null) throw badRequest("Amount is missing")
                    val amountParsed = parseAmountAsString(amount)
                    /**
                     * The transaction block below lets the 'demoBank' field
                     * of 'bankAccount' be correctly accessed.  */
                    transaction {
                        if ((amountParsed.second != null)
                            && (bankAccount.demoBank.currency != amountParsed.second))
                            throw badRequest("Currency '${amountParsed.second}' is wrong")
                        wireTransfer(
                            debitAccount = bankAccount,
                            creditAccount = getBankAccountFromIban(payto.iban),
                            demobank = bankAccount.demoBank,
                            subject = payto.message ?: throw badRequest(
                                "'message' query parameter missing in Payto address"
                            ),
                            amount = amountParsed.first
                        )
                    }
                    call.respond(object {})
                    return@post
                }
                // Information about one withdrawal.
                get("/accounts/{account_name}/withdrawals/{withdrawal_id}") {
                    val op = getWithdrawalOperation(call.getUriComponent("withdrawal_id"))
                    val demobank = ensureDemobank(call)
                    if (!op.selectionDone && op.reservePub != null) throw internalServerError(
                        "Unselected withdrawal has a reserve public key",
                        LibeufinErrorCode.LIBEUFIN_EC_INCONSISTENT_STATE
                    )
                    call.respond(object {
                        val amount = "${demobank.currency}:${op.amount}"
                        val aborted = op.aborted
                        val confirmation_done = op.confirmationDone
                        val selection_done = op.selectionDone
                        val selected_reserve_pub = op.reservePub
                        val selected_exchange_account = op.selectedExchangePayto
                    })
                    return@get
                }
                // Create a new withdrawal operation.
                post("/accounts/{account_name}/withdrawals") {
                    var username = call.request.basicAuth()
                    if (username == null && (!WITH_AUTH)) {
                        logger.info("Authentication is disabled to facilitate tests, defaulting to 'admin' username")
                        username = "admin"
                    }
                    val demobank = ensureDemobank(call)
                    /**
                     * Check here if the user has the right over the claimed bank account.  After
                     * this check, the withdrawal operation will be allowed only by providing its
                     * UID. */
                    val maybeOwnedAccount = getBankAccountFromLabel(
                        call.getUriComponent("account_name"),
                        demobank
                    )
                    if (maybeOwnedAccount.owner != username && WITH_AUTH) throw unauthorized(
                        "Customer '$username' has no rights over bank account '${maybeOwnedAccount.label}'"
                    )
                    val req = call.receiveJson<WithdrawalRequest>()
                    // Check for currency consistency
                    val amount = parseAmount(req.amount)
                    if (amount.currency != demobank.currency) throw badRequest(
                        "Currency ${amount.currency} differs from Demobank's: ${demobank.currency}"
                    )
                    val wo: TalerWithdrawalEntity = transaction {
                        TalerWithdrawalEntity.new {
                        this.amount = amount.amount.toPlainString()
                        walletBankAccount = maybeOwnedAccount
                        }
                    }
                    val baseUrl = URL(call.request.getBaseUrl())
                    val withdrawUri = url {
                        protocol = URLProtocol(
                            "taler".plus(if (baseUrl.protocol.lowercase() == "http") "+http" else ""),
                            -1
                        )
                        host = "withdraw"
                        pathComponents(
                            /**
                             * encodes the hostname(+port) of the actual
                             * bank that will serve the withdrawal request.
                             */
                            baseUrl.host.plus(
                                if (baseUrl.port != -1)
                                    ":${baseUrl.port}"
                                else ""
                            ),
                            baseUrl.path, // has x-forwarded-prefix, or single slash.
                            "demobanks",
                            demobank.name,
                            "integration-api",
                            wo.wopid.toString()
                        )
                    }
                    call.respond(object {
                        val withdrawal_id = wo.wopid.toString()
                        val taler_withdraw_uri = withdrawUri
                    })
                    return@post
                }
                // Confirm a withdrawal: no basic auth, because the ID should be unguessable.
                post("/accounts/{account_name}/withdrawals/{withdrawal_id}/confirm") {
                    val withdrawalId = call.getUriComponent("withdrawal_id")
                    transaction {
                        val wo = getWithdrawalOperation(withdrawalId)
                        if (wo.aborted) throw SandboxError(
                            HttpStatusCode.Conflict,
                            "Cannot confirm an aborted withdrawal."
                        )
                        if (!wo.selectionDone) throw SandboxError(
                            HttpStatusCode.UnprocessableEntity,
                            "Cannot confirm a unselected withdrawal: " +
                                    "specify exchange and reserve public key via Integration API first."
                        )
                        /**
                         * The wallet chose not to select any exchange, use the default.
                         */
                        val demobank = ensureDemobank(call)
                        if (wo.selectedExchangePayto == null) {
                            wo.selectedExchangePayto = demobank.suggestedExchangePayto
                        }
                        val exchangeBankAccount = getBankAccountFromPayto(
                            wo.selectedExchangePayto ?: throw internalServerError(
                                "Cannot withdraw without an exchange."
                            )
                        )
                        if (!wo.confirmationDone) {
                            // Need the exchange bank account!
                            wireTransfer(
                                debitAccount = wo.walletBankAccount,
                                creditAccount = exchangeBankAccount,
                                amount = wo.amount,
                                subject = wo.reservePub ?: throw internalServerError(
                                    "Cannot transfer funds without reserve public key."
                                ),
                                // provide the currency.
                                demobank = ensureDemobank(call)
                            )
                            wo.confirmationDone = true
                        }
                        wo.confirmationDone
                    }
                    call.respond(object {})
                    return@post
                }
                post("/accounts/{account_name}/withdrawals/{withdrawal_id}/abort") {
                    val withdrawalId = call.getUriComponent("withdrawal_id")
                    val operation = getWithdrawalOperation(withdrawalId)
                    if (operation.confirmationDone) throw conflict("Cannot abort paid withdrawal.")
                    transaction { operation.aborted = true }
                    call.respond(object {})
                    return@post
                }
                // Bank account basic information.
                get("/accounts/{account_name}") {
                    val username = call.request.basicAuth()
                    val accountAccessed = call.getUriComponent("account_name")
                    val demobank = ensureDemobank(call)
                    val bankAccount = transaction {
                        val res = BankAccountEntity.find {
                            (BankAccountsTable.label eq accountAccessed).and(
                                BankAccountsTable.demoBank eq demobank.id
                            )
                        }.firstOrNull()
                        res
                    } ?: throw notFound("Account '$accountAccessed' not found")
                    // Check rights.
                    if (
                        WITH_AUTH
                        && (bankAccount.owner != username && username != "admin")
                    ) throw forbidden(
                            "Customer '$username' cannot access bank account '$accountAccessed'"
                        )
                    val balance = balanceForAccount(bankAccount)
                    call.respond(object {
                        val balance = object {
                            val amount = "${demobank.currency}:${balance.abs(). toPlainString()}"
                            val credit_debit_indicator = if (balance < BigDecimal.ZERO) "debit" else "credit"
                        }
                        val paytoUri = buildIbanPaytoUri(
                            iban = bankAccount.iban,
                            bic = bankAccount.bic,
                            receiverName = getPersonNameFromCustomer(username ?: "admin")
                        )
                        val iban = bankAccount.iban
                    })
                    return@get
                }
                get("/accounts/{account_name}/transactions/{tId}") {
                    val demobank = ensureDemobank(call)
                    val bankAccount = getBankAccountFromLabel(
                        call.getUriComponent("account_name"),
                        demobank
                    )
                    val authOk: Boolean = bankAccount.isPublic || (!WITH_AUTH)
                    if (!authOk && (call.request.basicAuth() != bankAccount.owner)) throw forbidden(
                        "Cannot access bank account ${bankAccount.label}"
                    )
                    // Flow here == Right on the bank account.
                    val tId = call.parameters["tId"] ?: throw badRequest("URI didn't contain the transaction ID")
                    val tx: BankAccountTransactionEntity? = transaction {
                        BankAccountTransactionEntity.find {
                            BankAccountTransactionsTable.accountServicerReference eq tId
                        }.firstOrNull()
                    }
                    if (tx == null) throw notFound("Transaction $tId wasn't found")
                    call.respond(getHistoryElementFromTransactionRow(tx))
                    return@get
                }
                get("/accounts/{account_name}/transactions") {
                    val demobank = ensureDemobank(call)
                    val bankAccount = getBankAccountFromLabel(
                        call.getUriComponent("account_name"),
                        demobank
                    )
                    val authOk: Boolean = bankAccount.isPublic || (!WITH_AUTH)
                    if (!authOk && (call.request.basicAuth() != bankAccount.owner)) throw forbidden(
                        "Cannot access bank account ${bankAccount.label}"
                    )

                    val page: Int = Integer.decode(call.request.queryParameters["page"] ?: "0")
                    val size: Int = Integer.decode(call.request.queryParameters["size"] ?: "5")

                    val ret = mutableListOf<RawPayment>()
                    /**
                     * Case where page number wasn't given,
                     * therefore the results starts from the last transaction. */
                    transaction {
                        /**
                         * Get a history page - from the calling bank account - having
                         * 'firstElementId' as the latest transaction in it.  */
                        fun getPage(firstElementId: Long): Iterable<BankAccountTransactionEntity> {
                            logger.debug("History page from tx $firstElementId, including $size txs in the past.")
                            return BankAccountTransactionEntity.find {
                                (BankAccountTransactionsTable.id lessEq firstElementId) and
                                        (BankAccountTransactionsTable.account eq bankAccount.id)
                            }.sortedByDescending { it.id.value }.take(size)
                        }
                        val lt: BankAccountTransactionEntity? = bankAccount.lastTransaction
                        if (lt == null) return@transaction
                        var nextPageIdUpperLimit: Long = lt.id.value
                        /**
                         * This loop fetches (and discards) pages until the
                         * desired one is found.  */
                        for (i in 0..(page)) {
                            val pageBuf = getPage(nextPageIdUpperLimit)
                            logger.debug("Processing page:")
                            pageBuf.forEach { logger.debug("${it.id} ${it.subject} ${it.amount}") }
                            if (pageBuf.none()) return@transaction
                            nextPageIdUpperLimit = pageBuf.last().id.value - 1
                            if (i == page) pageBuf.forEach {
                                ret.add(getHistoryElementFromTransactionRow(it))
                            }
                        }
                    }
                    call.respond(object {val transactions = ret})
                    return@get
                }
                get("/public-accounts") {
                    val demobank = ensureDemobank(call)
                    val ret = object {
                        val publicAccounts = mutableListOf<PublicAccountInfo>()
                    }
                    transaction {
                        BankAccountEntity.find {
                            BankAccountsTable.isPublic eq true and(
                                    BankAccountsTable.demoBank eq demobank.id
                            )
                        }.forEach {
                            val balanceIter = balanceForAccount(it)
                            ret.publicAccounts.add(
                                PublicAccountInfo(
                                    balance = "${demobank.currency}:$balanceIter",
                                    iban = it.iban,
                                    accountLabel = it.label
                                )
                            )
                        }
                    }
                    call.respond(ret)
                    return@get
                }
                delete("accounts/{account_name}") {
                    // Check demobank was created.
                    ensureDemobank(call)
                    transaction {
                        val bankAccount = getBankAccountWithAuth(call)
                        val customerAccount = getCustomer(bankAccount.owner)
                        bankAccount.delete()
                        customerAccount.delete()
                    }
                    call.respond(object {})
                    return@delete
                }
                // Keeping the prefix "testing" not to break tests.
                post("/testing/register") {
                    // Check demobank was created.
                    val demobank = ensureDemobank(call)
                    if (!demobank.allowRegistrations) {
                        throw SandboxError(
                            HttpStatusCode.UnprocessableEntity,
                            "The bank doesn't allow new registrations at the moment."
                        )
                    }
                    val req = call.receiveJson<CustomerRegistration>()
                    val checkExist = transaction {
                        DemobankCustomerEntity.find {
                            DemobankCustomersTable.username eq req.username
                        }.firstOrNull()
                    }
                    /**
                     * Not allowing 'bank' username, as it's been assigned
                     * to the default bank's bank account.
                     */
                    if (checkExist != null || req.username == "bank") {
                        throw SandboxError(
                            HttpStatusCode.Conflict,
                            "Username ${req.username} not available."
                        )
                    }
                    // Create new customer.
                    requireValidResourceName(req.username)
                    val bankAccount = transaction {
                        val bankAccount = BankAccountEntity.new {
                            iban = req.iban ?: getIban()
                            /**
                             * For now, keep same semantics of Pybank: a username
                             * is AS WELL a bank account label.  In other words, it
                             * identifies a customer AND a bank account.
                             */
                            label = req.username
                            owner = req.username
                            this.demoBank = demobank
                            isPublic = req.isPublic
                        }
                        DemobankCustomerEntity.new {
                            username = req.username
                            passwordHash = CryptoUtil.hashpw(req.password)
                            name = req.name // nullable
                        }
                        if (demobank.withSignupBonus)
                            bankAccount.bonus("${demobank.currency}:100")
                        bankAccount
                    }
                    val balance = balanceForAccount(bankAccount)
                    call.respond(object {
                        val balance = object {
                            val amount = "${demobank.currency}:$balance"
                            val credit_debit_indicator = "CRDT"
                        }
                        val paytoUri = buildIbanPaytoUri(
                            iban = bankAccount.iban,
                            bic = bankAccount.bic,
                            receiverName = getPersonNameFromCustomer(req.username)
                        )
                        val iban = bankAccount.iban
                    })
                    return@post
                }
            }
            route("/ebics") {
                /**
                 * Associate an existing bank account to one EBICS subscriber.
                 * If the subscriber is not found, it is created.
                 */
                post("/subscribers") {
                    // Only the admin can create Ebics subscribers.
                    val user = call.request.basicAuth()
                    if (user != "admin") throw forbidden("Only the Admin can create Ebics subscribers.")
                    val body = call.receiveJson<EbicsSubscriberInfo>()
                    // Create or get the Ebics subscriber that is found.
                    transaction {
                        val subscriber: EbicsSubscriberEntity = EbicsSubscriberEntity.find {
                            (EbicsSubscribersTable.partnerId eq body.partnerID).and(
                                EbicsSubscribersTable.userId eq body.userID
                            ).and(EbicsSubscribersTable.hostId eq body.hostID)
                        }.firstOrNull() ?: EbicsSubscriberEntity.new {
                            partnerId = body.partnerID
                            userId = body.userID
                            systemId = null
                            hostId = body.hostID
                            state = SubscriberState.NEW
                            nextOrderID = 1
                        }
                        val bankAccount = getBankAccountFromLabel(
                            body.demobankAccountLabel,
                            ensureDemobank(call)
                        )
                        subscriber.bankAccount = bankAccount
                    }
                    call.respond(object {})
                    return@post
                }
            }
        }
    }
}

fun serverMain(port: Int, localhostOnly: Boolean, ipv4Only: Boolean) {
    val server = embeddedServer(
        Netty,
        environment = applicationEngineEnvironment{
            connector {
                this.port = port
                this.host = if (localhostOnly) "127.0.0.1" else "0.0.0.0"
            }
            if (!ipv4Only) connector {
                this.port = port
                this.host = if (localhostOnly) "[::1]" else "[::]"
            }
            parentCoroutineContext = Dispatchers.Main
            module(sandboxApp)
        },
        configure = {
            connectionGroupSize = 1
            workerGroupSize = 1
            callGroupSize = 1
        }
    )
    logger.info("LibEuFin Sandbox running on port $port")
    try {
        server.start(wait = true)
    } catch (e: BindException) {
        logger.error(e.message)
        exitProcess(1)
    }
}
