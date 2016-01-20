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

class ClamAntiVirus (streamCopyFunction: (InputStream) => Unit = DevNull.nullStream(_),
                      virusDetectedFunction: => Unit = (),
                      allowedMimeTypes: Set[String]) {

  import uk.gov.hmrc.avscanner.config.ClamAvConfig.clamAvConfig

  private val copyInputStream = new PipedInputStream()
  private val copyOutputStream = new PipedOutputStream(copyInputStream)

  private val socket = clamAvConfig.socket
  private val toClam = new DataOutputStream(socket.getOutputStream)
  private val fromClam = socket.getInputStream

  private val streamCopyThread = runStreamCopyThread()

//  @volatile private var mimeTypeDetected: String = null

  toClam.write(clamAvConfig.instream.getBytes())

  def sendBytesToClamd(bytes: Array[Byte]) {
//    if (mimeTypeDetected == null)
//      mimeTypeDetected = detectMimeType(bytes)

    toClam.writeInt(bytes.length)
    toClam.write(bytes)
    copyOutputStream.write(bytes)
    toClam.flush()
    copyOutputStream.flush()
  }

  def checkForVirus() {
    try {
      toClam.writeInt(0)
      toClam.flush()
      copyOutputStream.flush()
      copyOutputStream.close()

      val virusInformation = responseFromClamd()

      if ((!clamAvConfig.okClamAvResponse.equals(virusInformation)) || !isValidMimeType) {
        streamCopyThread.interrupt()
        virusDetectedFunction

        Logger.error(s"Virus detected $virusInformation")
        raiseError(virusInformation)
      } else {
        streamCopyThread.join()
      }
    }
    finally {
      terminate()
    }
  }

  def terminate() {
    try {
      copyInputStream.close()
      copyOutputStream.close()
      socket.close()
      toClam.close()
    }
    catch {
      case e: IOException =>
        Logger.warn("Error closing socket to clamd", e)
    }
  }

  private def raiseError(responseFromClamd: String): Nothing =
//    if (!isValidMimeType)
//      throw new InvalidMimeTypeException(mimeTypeDetected)
//    else
      throw new VirusDetectedException(responseFromClamd)

  private def isValidMimeType = true
//    if (allowedMimeTypes.contains(mimeTypeDetected)) {
//      true
//    } else {
//      false
//    }

  private def detectMimeType(bytes: Array[Byte]) = {
//    val mimeType = Magic.getMagicMatch(bytes).getMimeType
//
//    if (mimeType == null)
      "[unknown mime type]"
//    else
//      mimeType
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

  private def runStreamCopyThread() = {
    val thread = new Thread(new Runnable() {
      def run() {
        streamCopyFunction(copyInputStream)
      }
    })

    thread.start()
    thread
  }
}

private object DevNull {
  def nullStream(inputStream: InputStream) =
    Iterator.continually(inputStream.read())
      .takeWhile(_ != -1)
      .foreach {
      b => // no-op. We just throw the bytes away
    }
}
