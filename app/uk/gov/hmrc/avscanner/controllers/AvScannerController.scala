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

import play.api.libs.json.Json
import play.api.mvc._
import play.api.{Logger, Play}
import uk.gov.hmrc.avscanner.clamav.ClamAntiVirus
import uk.gov.hmrc.avscanner.{VirusChecker, VirusDetectedException, VirusScannerFailureException}
import uk.gov.hmrc.play.microservice.controller.BaseController

import scala.concurrent.Future

trait AvScannerController extends BaseController {
  val maxLength: Int

  def scan() = Action.async(
    parse.maxLength(maxLength, parser = StreamingBodyParser(newVirusChecker))) {
    implicit request =>
      request.body match {
        case Left(_: MaxSizeExceeded) => Future.successful(BadRequest("Content exceeded maxLength"))

        case Right(eventualStreamingResult) =>
          handleStreamingResult(eventualStreamingResult)
      }
  }

  def handleStreamingResult(eventualStreamingResult: Future[StreamingResult]): Future[Result] = {
    import play.api.libs.concurrent.Execution.Implicits._
    eventualStreamingResult.map {
      case Finished => Ok

      case Error(e: VirusDetectedException) =>
        Logger.warn(s"Antivirus scanner detected a virus: ${e.getMessage}", e)
        Forbidden

      case Error(e: VirusScannerFailureException) =>
        Logger.warn(s"Antivirus scanner failed with error: ${e.getMessage}", e)
        InternalServerError(
          Json.obj(
            "reason" -> "Antivirus scanner failed",
            "detail" -> e.message
          ))

      case Error(e) =>
        Logger.warn(s"Internal error: ${e.getMessage}", e)
        InternalServerError

      case unknown =>
        Logger.warn(s"An unknown result was returning from Antivirus scanning: $unknown")
        InternalServerError
    }
  }

  private[controllers] def newVirusChecker: VirusChecker = {
    new ClamAntiVirus()
  }
}

object AvScannerController extends AvScannerController {
  import play.api.Play.current

  val maxLength: Int = Play.configuration.getInt(s"clam.antivirus.maxLength")
    .getOrElse(throw new RuntimeException(s"The 'clam.antivirus.maxLength' config is missing"))
}