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
import uk.gov.hmrc.avscanner.clamav.{ClamAntiVirus, ClamAvFailedException, VirusChecker, VirusDetectedException}
import uk.gov.hmrc.play.microservice.controller.BaseController

trait AvScannerController extends BaseController {

  import scala.concurrent.ExecutionContext.Implicits.global
  import scala.concurrent.Future

  val maxLength: Int

  def scan() = Action.async(parse.raw) {
    implicit request =>

      request.body.asBytes(maxLength).map {
        bytes =>
          av(bytes)

      }.getOrElse {
        Future.successful(BadRequest("Content exceeded maxLength"))
      }
  }

  private[controllers] def av(bytes: Array[Byte]) = {
    val av = newVirusChecker
    av.sendBytesToClamd(bytes)
      .flatMap {
        case u =>
          av.checkForVirus().flatMap {
            case checked =>
              Future.successful(Ok)
          }.recoverWith {
            case virus: VirusDetectedException =>
              Future.successful(Forbidden)
            case f: ClamAvFailedException =>
              Future.successful(InternalServerError(
                Json.obj(
                  "reason" -> "ClamAV failed",
                  "detail" -> f.message
                )))
            case t: Throwable =>
              Logger.warn("Unexpected error occurred whilst scanning file", t)
              throw t
          }
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