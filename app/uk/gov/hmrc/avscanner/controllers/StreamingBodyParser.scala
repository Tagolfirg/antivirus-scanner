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
import play.api.libs.iteratee.{Done, Input, Iteratee}
import play.api.mvc.{BodyParser, RequestHeader, Result}
import uk.gov.hmrc.avscanner.Streamer

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, TimeoutException}

sealed trait StreamingState

final case class Init() extends StreamingState
final case class DataSent() extends StreamingState
final case class Finished() extends StreamingState
final case class Error(message: String, exception: Throwable = ???) extends StreamingState

case class StreamingBodyParser(streamTo: Streamer)(implicit ec: ExecutionContext) extends BodyParser[StreamingState] {
  override def apply(rh: RequestHeader): Iteratee[Array[Byte], Either[Result, StreamingState]] = {
    Iteratee.foreach[Array[Byte]] { arr =>
      Logger.debug(s"Sending chunk of ${arr.length} bytes to scanner instance")
      streamTo.send(arr)
    }(ec).flatMap[Either[Result,StreamingState]] { a =>
      try {
        Await.result(streamTo.finish(), 5 seconds span)
        Done[Array[Byte], Either[Result, StreamingState]](Right(Finished()), Input.EOF)
      }
      catch {
        case e: TimeoutException =>
          Logger.info("Timeout detected")
          Done[Array[Byte], Either[Result, StreamingState]](Right(Error(e.getMessage, e)), Input.EOF)
        case e: Throwable =>
          Done[Array[Byte], Either[Result, StreamingState]](Right(Error(e.getMessage, e)), Input.EOF)
      }
    }
  }
}

