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

import play.api.test.FakeRequest
import uk.gov.hmrc.avscanner.FileBytes
import uk.gov.hmrc.play.test.{UnitSpec, WithFakeApplication}

class AvScannerControllerWiringSpec extends UnitSpec with WithFakeApplication {

  "anti virus controller in conjunction with clamd" should {
    "provide a 200 response for no virus present" in {
      val result = new AvScannerController {}.scan().apply(FakeRequest("POST", "/avscanner/scan").withBody[Array[Byte]](FileBytes(SpecConstants.cleanFile))).run
      status(result) shouldBe 200
    }

    "provide a 403 response for a discovered virus" in {
      val result = new AvScannerController {}.scan().apply(FakeRequest("POST", "/avscanner/scan").withBody[Array[Byte]](FileBytes(SpecConstants.virusFile))).run
      status(result) shouldBe 403
    }
  }
}
