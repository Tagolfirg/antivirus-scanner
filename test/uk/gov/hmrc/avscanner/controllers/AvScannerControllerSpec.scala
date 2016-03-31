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

import uk.gov.hmrc.avscanner.FileBytes
import uk.gov.hmrc.play.test.{UnitSpec, WithFakeApplication}

class AvScannerControllerSpec extends UnitSpec with WithFakeApplication {

  val avScannerController = new AvScannerController{
    override val maxLength: Int = Int.MaxValue
  }

  val cleanFile = "/testfile.txt"
  val virusFile = "/eicar-standard-av-test-file"

  "anti virus scanning" should {
    "provide a 200 response for no virus present" in {

      status(avScannerController.av(FileBytes(cleanFile))) shouldBe 200
    }

    "provide a 400 for a discovered virus" in {

      status(avScannerController.av(FileBytes(virusFile))) shouldBe 400
    }
  }
}
