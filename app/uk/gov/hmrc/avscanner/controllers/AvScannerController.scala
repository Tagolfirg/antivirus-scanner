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

import play.api.Logger
import play.api.libs.json.Json
import play.api.mvc._
import uk.gov.hmrc.avscanner.clamav.ClamAntiVirus
import uk.gov.hmrc.avscanner.{VirusChecker, VirusDetectedException, VirusScannerFailureException}
import uk.gov.hmrc.play.microservice.controller.BaseController

trait AvScannerController extends BaseController {

  import scala.concurrent.Future

  def scan() = Action.async(StreamingBodyParser(newVirusChecker)) {
    implicit request =>
      request.body match {
        case Finished => Future.successful(Ok)

        case Error(e: VirusDetectedException) =>
          Logger.warn(s"Antivirus scanner detected a virus: ${e.getMessage}", e)
          Future.successful(Forbidden)

        case Error(e: VirusScannerFailureException) =>
          Logger.warn(s"Antivirus scanner failed with error: ${e.getMessage}", e)
          Future.successful(InternalServerError(
            Json.obj(
              "reason" -> "Antivirus scanner failed",
              "detail" -> e.message
            )))

        case Error(e) =>
          Logger.warn(s"Internal error: ${e.getMessage}", e)
          Future.successful(InternalServerError)

        case _ =>
          Logger.warn(s"An unknown error occurred returning from Antivirus scanning")
          Future.successful(InternalServerError)
      }
  }

  private[controllers] def newVirusChecker: VirusChecker = {
    new ClamAntiVirus()
  }
}

object AvScannerController extends AvScannerController {}