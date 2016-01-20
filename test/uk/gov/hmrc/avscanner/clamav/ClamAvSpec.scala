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

import java.io.{ByteArrayOutputStream, InputStream}

import uk.gov.hmrc.play.test.{WithFakeApplication, UnitSpec}

class ClamAvSpec extends UnitSpec with WithFakeApplication {

  private val virusSig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\u0000"
  private val testPdfFileName = "/162000101.pdf"
  private val validMimeTypes = Set("application/pdf", "text/plain")

  "Can upload pdf files into the system" in {
    val clamAv = new ClamAntiVirus(allowedMimeTypes = validMimeTypes)
    val bytes = chunkOfFile(testPdfFileName)

    try {
      clamAv.sendBytesToClamd(bytes)
      clamAv.checkForVirus()
    }
    finally {
      clamAv.terminate()
    }
  }

  "Cannot upload pdf files if they are not registered as a valid mime type" in pendingUntilFixed {

    //mime types have been commented for the timebeing so therefore not running this test

    val clamAv = new ClamAntiVirus(allowedMimeTypes = Set())
    val bytes = chunkOfFile(testPdfFileName)

    try {
      intercept[InvalidMimeTypeException] {
        clamAv.sendBytesToClamd(bytes)
        clamAv.checkForVirus()
      }
    }
    finally {
      clamAv.terminate()
    }
  }

  "Can scan stream without virus" in {

    val clamAv = new ClamAntiVirus(allowedMimeTypes = validMimeTypes)

    try {
      clamAv.sendBytesToClamd(getBytes(payloadSize = 10000))
      clamAv.checkForVirus()
    }
    finally {
      clamAv.terminate()
    }
  }

  "Can stream multiple clean blocks to clam" in {
    val clamAv = new ClamAntiVirus(allowedMimeTypes = validMimeTypes)

    try {
      clamAv.sendBytesToClamd(getBytes(payloadSize = 1000))
      clamAv.sendBytesToClamd(getBytes(payloadSize = 1000))
      clamAv.checkForVirus()
    }
    finally {
      clamAv.terminate()
    }
  }

  "Can detect a small stream with a virus at the beginning" in {
    val clamAv = new ClamAntiVirus(allowedMimeTypes = validMimeTypes)

    try {
      intercept[VirusDetectedException] {
        clamAv.sendBytesToClamd(getBytes(shouldInsertVirusAtPosition = Some(0)))
        clamAv.checkForVirus()
      }
    }
    finally {
      clamAv.terminate()
    }
  }

  "Calls cleanup function when a virus is detected" in {
    var cleanupCalled = false

    def cleanup() {
      cleanupCalled = true
    }

    val clamAv = new ClamAntiVirus(virusDetectedFunction = cleanup(), allowedMimeTypes = validMimeTypes)

    try {
      intercept[VirusDetectedException] {
        clamAv.sendBytesToClamd(getBytes(shouldInsertVirusAtPosition = Some(0)))
        clamAv.checkForVirus()
      }
    }
    finally {
      clamAv.terminate()
    }

    cleanupCalled should be(true)
  }

  private def getPayload(payloadSize: Int = 0, shouldInsertVirusAtPosition: Option[Int] = None) = {
    val payloadData = shouldInsertVirusAtPosition match {
      case Some(position) =>
        val virusStartPosition = math.min(position, payloadSize - virusSig.length)
        val virusEndPosition = virusStartPosition + virusSig.length

        0.until(virusStartPosition).map(_ => "a") ++ virusSig ++ virusEndPosition.until(payloadSize).map(_ => "a")

      case _ =>
        0.until(payloadSize).map(_ => "a")
    }

    val payload = payloadData.mkString

    shouldInsertVirusAtPosition match {
      case Some(position) =>
        payload.contains(virusSig) should be(true)
        payload.length should be(math.max(virusSig.length, payloadSize))
      case _ =>
        payload.length should be(payloadSize)
    }

    payload
  }

  private def getBytes(payloadSize: Int = 0,
                       shouldInsertVirusAtPosition: Option[Int] = None) =
    getPayload(payloadSize, shouldInsertVirusAtPosition).getBytes()

  private def chunkOfFile(filename: String) = {
    val stream = getClass.getResourceAsStream(filename)

    if (stream == null)
      throw new Exception("Could not open stream to: " + filename)

    Iterator.continually(stream.read)
      .takeWhile(_ != -1)
      .take(1000)
      .map(_.toByte)
      .toArray
  }

}
