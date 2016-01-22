/*
 * Copyright 2016 HM Revenue & Customs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.gov.hmrc.avscanner.clamav

import java.io._

import play.api.Logger

import scala.concurrent.{ExecutionContext, Future}

class ClamAntiVirus() {

  import uk.gov.hmrc.avscanner.config.ClamAvConfig.clamAvConfig

  private val socket = clamAvConfig.socket
  private val toClam = new DataOutputStream(socket.getOutputStream)
  private lazy val fromClam = socket.getInputStream

  toClam.write(clamAvConfig.instream.getBytes())

  def sendBytesToClamd(bytes: Array[Byte])(implicit ec : ExecutionContext): Future[Unit] = {
    Future{
      toClam.writeInt(bytes.length)
      toClam.write(bytes)
      toClam.flush()
    }
  }

  def checkForVirus()(implicit ec : ExecutionContext): Future[Unit] = {
    Future {
      try {
        toClam.writeInt(0)
        toClam.flush()

        val virusInformation = responseFromClamd()

        if (!clamAvConfig.okClamAvResponse.equals(virusInformation)) {
          Logger.warn(s"Virus detected : $virusInformation")
          throw new VirusDetectedException(virusInformation)
        }

        Logger.info("File clean")
      }
      finally {
        terminate()
      }
    }
  }

  private [avscanner] def terminate() = {
    try {
      socket.close()
    }
    catch {
      case e: IOException =>
        Logger.warn("Error closing socket to clamd", e)
    }
    try {
      toClam.close()
    }
    catch {
      case e: IOException =>
        Logger.warn("Error closing socket to clamd", e)
    }
  }

  private def responseFromClamd() = {
    val response = new String(
      Iterator.continually(fromClam.read)
        .takeWhile(_ != -1)
        .map(_.toByte)
        .toArray)

    Logger.info(s"Response from clamd: $response")
    response.trim()
  }

}

class VirusDetectedException(val virusInformation: String) extends Exception(s"Virus detected: $virusInformation")
