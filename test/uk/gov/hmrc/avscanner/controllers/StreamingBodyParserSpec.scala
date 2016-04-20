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

import play.api.libs.iteratee.{Input, Iteratee}
import play.api.mvc.{RequestHeader, Result}
import play.api.test.FakeRequest
import uk.gov.hmrc.avscanner.{VirusChecker, VirusDetectedException}
import uk.gov.hmrc.play.test.UnitSpec

import scala.collection.mutable
import scala.concurrent.{ExecutionContext, Future}

class StreamingBodyParserSpec extends UnitSpec {
  "StreamingBodyParser" should {
    "return Success when the streamer does not throw an exception" in {
      val bodyParser = new StreamingBodyParser(fakeVirusChecker(Future.successful(())))
      val requestHeader: RequestHeader = FakeRequest()

      val parserIteratee: Iteratee[Array[Byte], Either[Result, Future[StreamingResult]]] = bodyParser(requestHeader)

      val runResult: Either[Result, Future[StreamingResult]] = await(parserIteratee.run)
      runResult match {
        case Right(eventualStreamingResult) =>
          val streamingResult: StreamingResult = await(eventualStreamingResult)
          streamingResult shouldBe Finished
        case _ => fail
      }
    }

    "return Failure when the streamer throws an exception" in {
      val thrownException = new VirusDetectedException("info")
      val bodyParser = new StreamingBodyParser(fakeVirusChecker(Future.failed(thrownException)))
      val requestHeader: RequestHeader = FakeRequest()

      val parserIteratee: Iteratee[Array[Byte], Either[Result, Future[StreamingResult]]] = bodyParser(requestHeader)


      val runResult: Either[Result, Future[StreamingResult]] = await(parserIteratee.run)
      runResult match {
        case Right(eventualStreamingResult) =>
          val streamingResult: StreamingResult = await(eventualStreamingResult)
          streamingResult match {
            case Error(e) =>
              e should be theSameInstanceAs thrownException
            case _ =>
              fail
          }
        case _ => fail
      }
    }

    "send input to the virus checker" in {
      val capturingVirusChecker = new VirusChecker {
        val sent = mutable.ListBuffer[Array[Byte]]()

        override def finish()(implicit ec: ExecutionContext): Future[Unit] = {}
        override def send(bytes: Array[Byte])(implicit ec: ExecutionContext): Future[Unit] = {
          sent += bytes
          Future.successful(())
        }
      }

      val bodyParser = new StreamingBodyParser(capturingVirusChecker)
      val requestHeader: RequestHeader = FakeRequest()

      val parserIteratee: Iteratee[Array[Byte], Either[Result, Future[StreamingResult]]] = bodyParser(requestHeader)
      val bytes1: Array[Byte] = Array[Byte](1, 2, 3)
      val bytes2: Array[Byte] = Array[Byte](4, 5, 6)
      parserIteratee.feed(Input.El(bytes1))
      parserIteratee.feed(Input.El(bytes2))

      val runResult: Either[Result, Future[StreamingResult]] = await(parserIteratee.run)
      runResult match {
        case Right(eventualStreamingResult) =>
          val streamingResult: StreamingResult = await(eventualStreamingResult)
          streamingResult shouldBe Finished

          capturingVirusChecker.sent.length shouldBe 2
          capturingVirusChecker.sent(0) shouldBe bytes1
          capturingVirusChecker.sent(1) shouldBe bytes2
        case _ => fail
      }
    }
  }
}
