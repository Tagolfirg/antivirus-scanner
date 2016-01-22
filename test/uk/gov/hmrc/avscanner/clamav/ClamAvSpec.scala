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

import uk.gov.hmrc.play.test.{UnitSpec, WithFakeApplication}

class ClamAvSpec extends UnitSpec with WithFakeApplication {

  import scala.concurrent.ExecutionContext.Implicits.global

  private val virusSig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\u0000"
  private val virusFileWithSig = "/eicar-standard-av-test-file"
  private val virusClamTestVirus = "/clamav.hdb"
  private val testPdfFileName = "/162000101.pdf"

  "Scanning files" should {
    "allow clean files" in {
      val clamAv = new ClamAntiVirus()
      val bytes = chunkOfFile(testPdfFileName)

      try {
        await(clamAv.sendBytesToClamd(bytes))
        await(clamAv.checkForVirus())
      }
      finally {
        clamAv.terminate()
      }
    }

    "detect a virus in a file" in {
      val clamAv = new ClamAntiVirus()
      val bytes = chunkOfFile(virusFileWithSig)

      try {
        intercept[VirusDetectedException] {
          await(clamAv.sendBytesToClamd(bytes))
          await(clamAv.checkForVirus())
        }
      }
      finally {
        clamAv.terminate()
      }
    }
  }


  "Can scan stream without virus" in {

    val clamAv = new ClamAntiVirus()

    try {
      await(clamAv.sendBytesToClamd(getBytes(payloadSize = 10000)))
      await(clamAv.checkForVirus())
    }
    finally {
      clamAv.terminate()
    }
  }

  "Can stream multiple clean blocks to clam" in {
    val clamAv = new ClamAntiVirus()

    try {
      await(clamAv.sendBytesToClamd(getBytes(payloadSize = 1000)))
      await(clamAv.sendBytesToClamd(getBytes(payloadSize = 1000)))
      await(clamAv.checkForVirus())
    }
    finally {
      clamAv.terminate()
    }
  }

  "Can detect a small stream with a virus at the beginning" in {
    val clamAv = new ClamAntiVirus()

    try {
      intercept[VirusDetectedException] {
        await(clamAv.sendBytesToClamd(getBytes(shouldInsertVirusAtPosition = Some(0))))
        await(clamAv.checkForVirus())
      }
    }
    finally {
      clamAv.terminate()
    }
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
