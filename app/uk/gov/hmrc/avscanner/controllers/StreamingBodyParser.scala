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
import play.api.libs.iteratee.{Cont, Done, Input, Iteratee}
import play.api.mvc.{BodyParser, RequestHeader, Result}
import uk.gov.hmrc.avscanner.Streamer

import scala.concurrent.Future


sealed trait StreamingResult
case object Finished extends StreamingResult
case class Error(t: Throwable) extends StreamingResult


case class StreamingBodyParser(streamer: Streamer) extends BodyParser[Future[StreamingResult]] {
  import scala.concurrent.ExecutionContext.Implicits.global

  override def apply(rh: RequestHeader): Iteratee[Array[Byte], Either[Result, Future[StreamingResult]]] = {
    step()
  }

  def step(): Iteratee[Array[Byte], Either[Result, Future[StreamingResult]]] = Cont {
    case Input.El(arr) =>
      Logger.debug(s"Sending chunk of ${arr.length} bytes to scanner instance")

      val eventualIteratee = streamer.send(arr).map {
        _ => step()
      }

      Iteratee.flatten(eventualIteratee)

    case Input.Empty | Input.EOF =>
      val eventualResult: Future[StreamingResult] = streamer.finish()
        .map(_ => Finished)
        .recover { case t => Error(t) }

      Done(Right(eventualResult))
  }
}
