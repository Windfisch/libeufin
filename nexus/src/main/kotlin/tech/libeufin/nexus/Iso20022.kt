/*
 * This file is part of LibEuFin.
 * Copyright (C) 2020 Taler Systems S.A.

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

package tech.libeufin.nexus

/**
 * Parse ISO 20022 messages
 */

import com.fasterxml.jackson.annotation.JsonInclude
import org.w3c.dom.Document
import tech.libeufin.util.XmlElementDestructor
import tech.libeufin.util.destructXml

enum class CreditDebitIndicator {
    DBIT, CRDT
}

enum class TransactionStatus {
    BOOK, PENDING
}

data class TransactionDetails(
    /**
     * Related parties as JSON.
     */
    val relatedParties: RelatedParties,
    val amountDetails: AmountDetails,
    val references: References,
    /**
     * Unstructured remittance information (=subject line) of the transaction,
     * or the empty string if missing.
     */
    val unstructuredRemittanceInformation: String
)

data class BankTransaction(
    val accountIdentifier: String,
    /**
     * Scheme used for the account identifier.
     */
    val accountScheme: String,
    val currency: String,
    val amount: String,
    /**
     * Booked, pending, etc.
     */
    val status: TransactionStatus,
    /**
     * Is this transaction debiting or crediting the account
     * it is reported for?
     */
    val creditDebitIndicator: CreditDebitIndicator,
    /**
     * Code that describes the type of bank transaction
     * in more detail
     */
    val bankTransactionCode: BankTransactionCode,
    /**
     * Is this a batch booking?
     */
    val isBatch: Boolean,
    val details: List<TransactionDetails>
)

abstract class TypedEntity(val type: String)

@JsonInclude(JsonInclude.Include.NON_NULL)
class Agent(
    val name: String?,
    val bic: String
) : TypedEntity("agent")

@JsonInclude(JsonInclude.Include.NON_NULL)
class Party(
    val name: String?
) : TypedEntity("party")

@JsonInclude(JsonInclude.Include.NON_NULL)
class Account(
    val iban: String?
) : TypedEntity("party")


@JsonInclude(JsonInclude.Include.NON_NULL)
data class BankTransactionCode(
    /**
     * Standardized bank transaction code, as "$domain/$family/$subfamily"
     */
    val iso: String?,

    /**
     * Proprietary code, as "$issuer/$code".
     */
    val proprietary: String?
)

data class AmountAndCurrencyExchangeDetails(
    val amount: String,
    val currency: String
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class AmountDetails(
    val instructedAmount: AmountAndCurrencyExchangeDetails?,
    val transactionAmount: AmountAndCurrencyExchangeDetails?
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class References(
    val endToEndIdentification: String?
)

/**
 * This structure captures both "TransactionParties6" and "TransactionAgents5"
 * of ISO 20022.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class RelatedParties(
    val debtor: Party?,
    val debtorAccount: Account?,
    val debtorAgent: Agent?,
    val creditor: Party?,
    val creditorAccount: Account?,
    val creditorAgent: Agent?
)

class CamtParsingError(msg: String) : Exception(msg)

private fun XmlElementDestructor.extractAgent(): Agent {
    return Agent(
        name = maybeUniqueChildNamed("FinInstnId") {
            maybeUniqueChildNamed("Nm") {
                it.textContent
            }
        },
        bic = requireUniqueChildNamed("FinInstnId") {
            requireUniqueChildNamed("BIC") {
                it.textContent
            }
        }
    )
}

private fun XmlElementDestructor.extractAccount(): Account {
    return Account(
        iban = requireUniqueChildNamed("Id") {
            maybeUniqueChildNamed("IBAN") {
                it.textContent
            }
        }
    )
}

private fun XmlElementDestructor.extractParty(): Party {
    return Party(
        name = maybeUniqueChildNamed("Nm") { it.textContent }
    )
}

private fun XmlElementDestructor.extractPartiesAndAgents(): RelatedParties {
    return RelatedParties(
        debtor = maybeUniqueChildNamed("RltdPties") {
            maybeUniqueChildNamed("Dbtr") {
                extractParty()
            }
        },
        creditor = maybeUniqueChildNamed("RltdPties") {
            maybeUniqueChildNamed("Cdtr") {
                extractParty()
            }
        },
        creditorAccount = maybeUniqueChildNamed("RltdPties") {
            maybeUniqueChildNamed("CdtrAcct") {
                extractAccount()
            }
        },
        debtorAccount = maybeUniqueChildNamed("RltdPties") {
            maybeUniqueChildNamed("DbtrAcct") {
                extractAccount()
            }
        },
        creditorAgent = maybeUniqueChildNamed("RltdAgts") {
            maybeUniqueChildNamed("CdtrAgt") {
                extractAgent()
            }
        },
        debtorAgent = maybeUniqueChildNamed("RltdAgts") {
            maybeUniqueChildNamed("DbtrAgt") {
                extractAgent()
            }
        }
    )
}

private fun XmlElementDestructor.extractAmountAndCurrencyExchangeDetails(): AmountAndCurrencyExchangeDetails {
    return AmountAndCurrencyExchangeDetails(
        amount = requireUniqueChildNamed("Amt") { it.textContent},
        currency = requireUniqueChildNamed("Amt") { it.getAttribute("Ccy") }
    )
}

private fun XmlElementDestructor.extractTransactionDetails(): List<TransactionDetails> {
    return requireUniqueChildNamed("NtryDtls") {
        mapEachChildNamed("TxDtls") {
            TransactionDetails(
                relatedParties = extractPartiesAndAgents(),
                amountDetails = maybeUniqueChildNamed("AmtDtls") {
                    AmountDetails(
                        instructedAmount = maybeUniqueChildNamed("InstrAmt") { extractAmountAndCurrencyExchangeDetails() },
                        transactionAmount = maybeUniqueChildNamed("TxAmt") { extractAmountAndCurrencyExchangeDetails() }
                    )
                } ?: AmountDetails(null, null),
                references = maybeUniqueChildNamed("Refs") {
                    References(
                        endToEndIdentification = maybeUniqueChildNamed("EndToEndId") { it.textContent }
                    )
                } ?: References(null),
                unstructuredRemittanceInformation = maybeUniqueChildNamed("RmtInf") {
                    requireUniqueChildNamed("Ustrd") { it.textContent }
                } ?: ""
            )
        }
    }
}

private fun XmlElementDestructor.extractInnerTransactions(): List<BankTransaction> {
    val iban = requireUniqueChildNamed("Acct") {
        requireUniqueChildNamed("Id") {
            requireUniqueChildNamed("IBAN") {
                it.textContent
            }
        }
    }

    return mapEachChildNamed("Ntry") {
        val amount = requireUniqueChildNamed("Amt") { it.textContent }
        val currency = requireUniqueChildNamed("Amt") { it.getAttribute("Ccy") }
        val status = requireUniqueChildNamed("Sts") { it.textContent }.let {
            TransactionStatus.valueOf(it)
        }
        val creditDebitIndicator = requireUniqueChildNamed("CdtDbtInd") { it.textContent }.let {
            CreditDebitIndicator.valueOf(it)
        }
        val btc = requireUniqueChildNamed("BkTxCd") {
            BankTransactionCode(
                proprietary = maybeUniqueChildNamed("Prtry") {
                    val cd = requireUniqueChildNamed("Cd") { it.textContent }
                    val issr = requireUniqueChildNamed("Issr") { it.textContent }
                    "$issr:$cd"
                },
                iso = maybeUniqueChildNamed("Domn") {
                    val cd = requireUniqueChildNamed("Cd") { it.textContent }
                    val r = requireUniqueChildNamed("Fmly") {
                        object {
                            val fmlyCd = requireUniqueChildNamed("Cd") { it.textContent }
                            val subFmlyCd = requireUniqueChildNamed("SubFmlyCd") { it.textContent }
                        }
                    }
                    "$cd/${r.fmlyCd}/${r.subFmlyCd}"
                }
            )
        }
        val details = extractTransactionDetails()
        BankTransaction(
            accountIdentifier = iban,
            accountScheme = "iban",
            amount = amount,
            currency = currency,
            status = status,
            creditDebitIndicator = creditDebitIndicator,
            bankTransactionCode = btc,
            details = details,
            isBatch = details.size > 1
        )
    }
}

/**
 * Extract a list of transactions from an ISO20022 camt.052 / camt.053 message.
 */
fun getTransactions(doc: Document): List<BankTransaction> {
    return destructXml(doc) {
        requireRootElement("Document") {
            // Either bank to customer statement or report
            requireOnlyChild() {
                when (it.localName) {
                    "BkToCstmrAcctRpt" -> {
                        mapEachChildNamed("Rpt") {
                            extractInnerTransactions()
                        }
                    }
                    "BkToCstmrStmt" -> {
                        mapEachChildNamed("Stmt") {
                            extractInnerTransactions()
                        }
                    }
                    else -> {
                        throw CamtParsingError("expected statement or report")
                    }
                }
            }
        }
    }.flatten()
}