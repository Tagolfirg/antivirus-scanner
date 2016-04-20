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

import play.api.libs.iteratee.{Cont, Done, Input, Iteratee}
import play.api.libs.iteratee.Iteratee
import play.api.mvc.{RequestHeader, Result}
import play.api.test.FakeRequest
import uk.gov.hmrc.avscanner.{VirusChecker, VirusDetectedException, VirusScannerFailureException}
import uk.gov.hmrc.play.test.{UnitSpec, WithFakeApplication}

import scala.collection.mutable
import scala.concurrent.{ExecutionContext, Future}

class StreamingBodyParserSpec extends UnitSpec {
  "StreamingBodyParser" should {
    "return Success when the streamer does not throw an exception" in {
      val bodyParser = new StreamingBodyParser(fakeVirusChecker(Future.successful(())))
      val requestHeader: RequestHeader = FakeRequest()

      val parserIteratee: Iteratee[Array[Byte], Either[Result, StreamingResult]] = bodyParser(requestHeader)

      await(parserIteratee.run) shouldBe Right(Finished)
    }

    "return Failure when the streamer throws an exception" in {
      val thrownException = new VirusDetectedException("info")
      val bodyParser = new StreamingBodyParser(fakeVirusChecker(Future.failed(thrownException)))
      val requestHeader: RequestHeader = FakeRequest()

      val parserIteratee: Iteratee[Array[Byte], Either[Result, StreamingResult]] = bodyParser(requestHeader)


      await(parserIteratee.run) match {
        case Right(Error(e)) =>
          e should be theSameInstanceAs thrownException
        case _ =>
          fail
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

      val parserIteratee: Iteratee[Array[Byte], Either[Result, StreamingResult]] = bodyParser(requestHeader)
      val bytes1: Array[Byte] = Array[Byte](1, 2, 3)
      val bytes2: Array[Byte] = Array[Byte](4, 5, 6)
      parserIteratee.feed(Input.El(bytes1))
      parserIteratee.feed(Input.El(bytes2))

      val runResult: Either[Result, StreamingResult] = await(parserIteratee.run)

      capturingVirusChecker.sent.length shouldBe 2
      capturingVirusChecker.sent(0) shouldBe bytes1
      capturingVirusChecker.sent(1) shouldBe bytes2

      runResult shouldBe Right(Finished)
    }
  }
}
