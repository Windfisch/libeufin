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

package tech.libeufin.nexus

import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.client.*
import io.ktor.client.features.ServerResponseException
import io.ktor.client.request.get
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.gson.gson
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.request.uri
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.jetbrains.exposed.sql.transactions.transaction
import org.slf4j.LoggerFactory
import tech.libeufin.sandbox.CryptoUtil
import tech.libeufin.sandbox.EbicsSubscribers
import tech.libeufin.sandbox.SandboxError
import java.text.DateFormat
import javax.sql.rowset.serial.SerialBlob


fun main() {
    dbCreateTables()
    val logger = LoggerFactory.getLogger("tech.libeufin.nexus")

    val server = embeddedServer(Netty, port = 5001) {

        install(ContentNegotiation) {
            gson {
                setDateFormat(DateFormat.LONG)
                setPrettyPrinting()
            }
        }
        install(StatusPages) {
            exception<Throwable> { cause ->
                tech.libeufin.sandbox.logger.error("Exception while handling '${call.request.uri}'", cause)
                call.respondText("Internal server error.", ContentType.Text.Plain, HttpStatusCode.InternalServerError)
            }
        }

        intercept(ApplicationCallPipeline.Fallback) {
            if (this.call.response.status() == null) {
                call.respondText("Not found (no route matched).\n", ContentType.Text.Plain, HttpStatusCode.NotFound)
                return@intercept finish()
            }
        }

        routing {
            get("/") {
                call.respondText("Hello by Nexus!\n")
                return@get
            }

            post("/ebics/subscribers") {
                val body = try {
                    call.receive<EbicsSubscriberInfoRequest>()
                } catch (e: Exception) {
                    e.printStackTrace()
                    call.respond(
                        HttpStatusCode.BadRequest,
                        NexusError(e.message.toString())
                    )
                    return@post
                }

                val pairA = CryptoUtil.generateRsaKeyPair(2048)
                val pairB = CryptoUtil.generateRsaKeyPair(2048)
                val pairC = CryptoUtil.generateRsaKeyPair(2048)

                val id = transaction {


                    EbicsSubscriberEntity.new {
                        ebicsURL = body.ebicsURL
                        hostID = body.hostID
                        partnerID = body.partnerID
                        userID = body.userID
                        systemID = body.systemID
                        signaturePrivateKey = SerialBlob(pairA.private.encoded)
                        encryptionPrivateKey = SerialBlob(pairB.private.encoded)
                        authenticationPrivateKey = SerialBlob(pairC.private.encoded)

                    }.id.value
                }

                call.respond(
                    HttpStatusCode.OK,
                    EbicsSubscriberInfoResponse(id)
                )

                return@post
            }

            post("/nexus") {
                val client = HttpClient()
                val content = try {
                    client.get<ByteArray>(
                        "https://ebicstest1.libeufin.tech/"
                    )
                } catch (e: ServerResponseException) {
                    logger.info("Request ended bad (${e.response.status}).")
                }

                call.respondText("Not implemented!\n")
                return@post
            }
        }
    }

    logger.info("Up and running")
    server.start(wait = true)
}
