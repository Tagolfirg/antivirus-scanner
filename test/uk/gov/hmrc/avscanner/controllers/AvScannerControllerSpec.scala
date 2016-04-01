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

package uk.gov.hmrc.avscanner.controllers

import play.api.libs.json.JsString
import play.api.mvc.Result
import uk.gov.hmrc.avscanner.FileBytes
import uk.gov.hmrc.avscanner.clamav.{ClamAvFailedException, VirusChecker, VirusDetectedException}
import uk.gov.hmrc.play.test.{UnitSpec, WithFakeApplication}

import scala.concurrent.{ExecutionContext, Future}

class AvScannerControllerSpec extends UnitSpec with WithFakeApplication {
  "anti virus controller" should {
    "provide a 200 response for no virus present" in {
      val avScannerController = fakeAvScannerController {
        Future.successful(())
      }

      status(avScannerController.av(FileBytes(SpecConstants.cleanFile))) shouldBe 200
    }

    "provide a 422 response for a discovered virus" in {
      val avScannerController = fakeAvScannerController {
        Future.failed(new VirusDetectedException("stream: Eicar-Test-Signature FOUND"))
      }

      val result = avScannerController.av(FileBytes(SpecConstants.cleanFile))
      status(result) shouldBe 422

      val body = jsonBodyOf(result)
      val reason = body \ "reason"
      reason shouldBe JsString("Virus detected")
    }

    "provide a 500 response with a description of the failure when ClamAV fails" in {
      val avScannerController = fakeAvScannerController {
        Future.failed(new ClamAvFailedException("test ClamAv failure"))
      }

      val result = avScannerController.av(FileBytes(SpecConstants.cleanFile))
      status(result) shouldBe 500

      val body = jsonBodyOf(result)
      val reason = body \ "reason"
      reason shouldBe JsString("ClamAV failed")
      val detail = body \ "detail"
      detail shouldBe JsString("test ClamAv failure")
    }
  }

  def fakeAvScannerController(fakeCheckForVirus: => Future[Unit]): AvScannerController = {
    new AvScannerController {
      override val maxLength: Int = Int.MaxValue

      override def newVirusChecker = {
        new VirusChecker {
          override def checkForVirus()(implicit ec: ExecutionContext): Future[Unit] = {
            fakeCheckForVirus
          }

          override def sendBytesToClamd(bytes: Array[Byte])(implicit ec: ExecutionContext): Future[Unit] = {
            Future.successful(())
          }
        }
      }
    }
  }
}
