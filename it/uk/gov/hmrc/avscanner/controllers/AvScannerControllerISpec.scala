package uk.gov.hmrc.avscanner.controllers

import java.io.{ByteArrayOutputStream, File}
import java.nio.file.Files

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration._
import com.ning.http.client.FluentCaseInsensitiveStringsMap
import com.ning.http.multipart._
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach}
import org.scalatestplus.play.OneServerPerSuite
import play.api.Logger
import play.api.http.{ContentTypeOf, Writeable}
import play.api.libs.ws.WS
import uk.gov.hmrc.play.http.HeaderNames
import uk.gov.hmrc.play.http.ws.WSHttpResponse
import uk.gov.hmrc.play.test.UnitSpec

import scala.collection.mutable.ListBuffer
import scala.io.Source

class AvScannerControllerISpec extends UnitSpec with OneServerPerSuite with ScalaFutures with IntegrationPatience with BeforeAndAfterAll with BeforeAndAfterEach {

  val requestingAppName = "itstreamingattachments"

  override lazy val port = 9000

  val stubPort = 11111
  val stubHost = "localhost"
  val wireMockServer = new WireMockServer(wireMockConfig().port(stubPort))

  override def beforeAll() = {
    wireMockServer.start()
    WireMock.configureFor(stubHost, stubPort)
  }

  override def afterAll() = {
    wireMockServer.stop()
  }

  override def beforeEach() = {
    WireMock.reset()
  }

  val testVirus = new File("./test/resources/eicar-standard-av-test-file")
  val testFile = new File("./test/resources/testfile.txt")
  val largeFile = new File("./test/resources/test20Mb")

  val scanEndpoint = s"/avscanner/scan"

  "anti virus scanning fail" should {

    "provide a 403 response for virus present" in {

      resource("/ping/ping").status shouldBe 200

      val result = postAttachment(scanEndpoint)

      result.status shouldBe 403
    }

  }

  "anti virus scanning pass" should {

    "provide a 200 response for no virus present" in {

      resource("/ping/ping").status shouldBe 200

      val result = postAttachment(scanEndpoint, Some(testFile))

      result.status shouldBe 200
    }

  }

  "large file" should {

    "provide a 400 response as its too large" in {

      resource("/ping/ping").status shouldBe 200

      val result = postAttachment(scanEndpoint, Some(largeFile))

      result.status shouldBe 400
    }

  }

  def postAttachment(
                      path: String,
                      file: Option[File] = Some(testVirus)
                      ) = {

    val url = s"http://localhost:$port$path"

    Logger.debug(s"Posting file as bytes to : $url")

    WS.url(url).post(Source.fromFile(file.get).map(_.toByte).toArray)(Writeable.wBytes, ContentTypeOf.contentTypeOf_ByteArray)
  }



  val hdrs = Seq(HeaderNames.xRequestId -> "someRequestId", HeaderNames.xSessionId -> "someSessionId")
  def resource(path: String, queryString: Seq[(String,String)] = Seq.empty, header : Seq[(String, String)] = hdrs) = {
    WS.url(s"http://localhost:$port$path")
      .withHeaders(hdrs : _*)
      .withQueryString(queryString: _*)
      .get().futureValue
  }


}
