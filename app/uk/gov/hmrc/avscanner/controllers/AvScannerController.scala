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


import java.nio.file.Files

import play.api.mvc._
import play.api.{Play, Logger, mvc}
import uk.gov.hmrc.avscanner.clamav.{ClamAntiVirus, VirusDetectedException}
import uk.gov.hmrc.play.microservice.controller.BaseController

import scala.concurrent.Future

trait AvScannerController extends BaseController {

  import scala.concurrent.ExecutionContext.Implicits.global

  private[controllers] def av(bytes: Array[Byte]) = {
    val av = new ClamAntiVirus()
    av.sendBytesToClamd(bytes)
      .flatMap {
        case u =>
          av.checkForVirus().flatMap {
            case checked =>
              Future.successful(Ok)
          }.recoverWith {
            case virus: VirusDetectedException =>
              Future.successful(Forbidden)
            case t: Throwable =>
              Logger.warn("Unexpected error occurred whilst scanning file", t)
              throw t
          }
      }
  }
}

object AvScannerController extends AvScannerController {
  import play.api.Play.current

  val maxLength: Int = Play.configuration.getInt(s"clam.antivirus.maxLength")
    .getOrElse(throw new RuntimeException(s"The 'clam.antivirus.maxLength' config is missing"))

  def scan() = Action.async(parse.raw) {
    implicit request =>

      request.body.asBytes(maxLength).map {
        bytes =>
          av(bytes)

      }.getOrElse {
        Future.successful(BadRequest("Content exceeded maxLength"))
      }
  }
}