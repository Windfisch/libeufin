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

package tech.libeufin.sandbox

import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.gson.gson
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.request.receiveText
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.LoggerFactory
import org.w3c.dom.Document
import org.w3c.dom.Element
import tech.libeufin.messages.ebics.hev.HEVResponseDataType
import tech.libeufin.messages.ebics.keyrequest.EbicsUnsecuredRequest
import tech.libeufin.messages.ebics.keyrequest.UnsecuredReqOrderDetailsType
import java.text.DateFormat
import javax.xml.bind.JAXBElement

val logger = LoggerFactory.getLogger("tech.libeufin.sandbox")
val xmlProcess = XML()

/**
 * Sometimes, JAXB is not able to figure out to which type
 * a certain XML node should be bound to.  This happens when
 * one element name can have multiple definitions therefore
 * JAXB renders it as a abstract class.  In that case, the
 * object factory must be instructed about the subtype to create,
 * and this is done via injecting the xsi:type attribute to the
 * "overloaded" XML element.
 *
 * Alternative methods of addressing this?
 *
 * @param document the XML Document to modify
 * @param node the name of the overloaded element (ideally this
 * parameter should be a XPATH address)
 * @param type the type to downcast @a node to
 * @return the modified document
 */
fun downcastXml(document: Document, node: String, type: String) : Document {

    val x: Element = document.getElementsByTagName("OrderDetails")?.item(0) as Element

    x.setAttributeNS(
        "http://www.w3.org/2001/XMLSchema-instance",
        "type",
        type
    )

    return document
}

private suspend fun ApplicationCall.adminCustomers() {
    val body = try {
        receive<CustomerRequest>()
    } catch (e: Exception) {
        e.printStackTrace()
        respond(
            HttpStatusCode.BadRequest,
            SandboxError(e.message.toString())
        )
        return
    }
    logger.info(body.toString())

    val returnId = transaction {
        var myUserId = EbicsUser.new { }
        val myPartnerId = EbicsPartner.new { }
        val mySystemId = EbicsSystem.new { }
        val subscriber = EbicsSubscriber.new {
            userId = myUserId
            partnerId = myPartnerId
            systemId = mySystemId
            state = SubscriberStates.NEW
        }
        println("subscriber ID: ${subscriber.id.value}")
        val customer = BankCustomer.new {
            name = body.name
            ebicsSubscriber = subscriber
        }
        println("name: ${customer.name}")
        return@transaction customer.id.value
    }

    respond(
        HttpStatusCode.OK,
        CustomerResponse(id = returnId)
    )
}

private suspend fun ApplicationCall.adminCustomersInfo() {
    val id: Int = try {
        parameters["id"]!!.toInt()
    } catch (e: NumberFormatException) {
        respond(
            HttpStatusCode.BadRequest,
            SandboxError(e.message.toString())
        )
        return
    }

    val customerInfo = transaction {
        val customer = BankCustomer.findById(id) ?: return@transaction null
        CustomerInfo(
            customer.name,
            ebicsInfo = CustomerEbicsInfo(
                customer.ebicsSubscriber.userId.userId!!
            )
        )
    }

    if (null == customerInfo) {
        respond(
            HttpStatusCode.NotFound,
            SandboxError("id $id not found")
        )
        return
    }

    respond(HttpStatusCode.OK, customerInfo)
}

private suspend fun ApplicationCall.adminCustomersKeyletter() {
    val body = try {
        receive<IniHiaLetters>()
    } catch (e: Exception) {
        e.printStackTrace()
        respond(
            HttpStatusCode.BadRequest,
            SandboxError(e.message.toString())
        )
        return
    }

    /**********************************************/

    // Extract keys and compare them to what was
    // received via the INI and HIA orders.

    /**********************************************/

    respond(
        HttpStatusCode.NotImplemented,
        SandboxError("Not properly implemented")
    )
}

private suspend fun ApplicationCall.ebicsweb() {

    val body: String = receiveText()
    val bodyDocument: Document? = xmlProcess.parseStringIntoDom(body)
    if (bodyDocument == null) {
        respondText(
            contentType = ContentType.Application.Xml,
            status = HttpStatusCode.BadRequest
        ) { "Bad request / Could not parse the body" }
        return

    }

    if (!xmlProcess.validateFromDom(bodyDocument)) {
        logger.error("Invalid request received")
        respondText(
            contentType = ContentType.Application.Xml,
            status = HttpStatusCode.BadRequest
        ) { "Bad request / invalid document" }
        return
    }

    logger.info("Processing ${bodyDocument.documentElement.localName}")

    when (bodyDocument.documentElement.localName) {
        "ebicsUnsecuredRequest" -> {

            /* Manage request.  */

            val bodyJaxb = xmlProcess.convertDomToJaxb<EbicsUnsecuredRequest>(
                "tech.libeufin.messages.ebics.keyrequest",
                downcastXml(
                    bodyDocument,
                    "OrderDetails",
                    "UnsecuredReqOrderDetailsType"
                )
            )

            logger.info("Serving a ${bodyJaxb.header.static.orderDetails.orderType} request")

            respond(
                HttpStatusCode.NotImplemented,
                SandboxError("Not implemented")
            )
            return
        }

        "ebicsHEVRequest" -> {
            val hevResponse = HEVResponse(
                "000000",
                "EBICS_OK",
                arrayOf(
                    ProtocolAndVersion("H003", "02.40"),
                    ProtocolAndVersion("H004", "02.50")
                )
            )

            val jaxbHEV: JAXBElement<HEVResponseDataType> = hevResponse.makeHEVResponse()
            val responseText: String? = xmlProcess.getStringFromJaxb(
                "tech.libeufin.messages.ebics.hev",
                jaxbHEV
            )

            respondText(
                contentType = ContentType.Application.Xml,
                status = HttpStatusCode.OK
            ) { responseText.toString() }
            return
        }
        else -> {
            /* Log to console and return "unknown type" */
            logger.info("Unknown message, just logging it!")
            respondText(
                contentType = ContentType.Application.Xml,
                status = HttpStatusCode.NotFound
            ) { "Not found" }
            return
        }
    }


}

fun main() {
    dbCreateTables()
    val server = embeddedServer(Netty, port = 5000) {

        install(CallLogging)
        install(ContentNegotiation) {
            gson {
                setDateFormat(DateFormat.LONG)
                setPrettyPrinting()
            }
        }
        routing {
            get("/") {
                logger.debug("GET: not implemented")
                call.respondText("Hello LibEuFin!\n", ContentType.Text.Plain)
                return@get
            }

            post("/admin/customers") {
                call.adminCustomers()
                return@post
            }

            get("/admin/customers/{id}") {

                call.adminCustomersInfo()
                return@get
            }

            post("/admin/customers/{id}/ebics/keyletter") {
                call.adminCustomersKeyletter()
                return@post

            }

            post("/ebicsweb") {
                call.ebicsweb()
                return@post
            }
        }
    }
    logger.info("Up and running")
    server.start(wait = true)
}