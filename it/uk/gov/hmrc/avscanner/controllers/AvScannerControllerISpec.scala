package uk.gov.hmrc.avscanner.controllers

import java.io.{ByteArrayOutputStream, File}

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
import uk.gov.hmrc.play.test.UnitSpec

import scala.collection.mutable.ListBuffer

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

  val scanEndpoint = s"/avscanner/scan/"

  "anti virus scanning" should {

    "provide a 403 response for no virus present" in {

      val result = postAttachment(scanEndpoint)

      result.status shouldBe 403
    }

  }


  def postAttachment(
                      path: String,
                      file: Option[File] = Some(testVirus),
                      postPort: Int = port,
                      filePartKey : String = "to-scan"
                      ) = {

    val parts = ListBuffer[Part]()
    if (file.isDefined) {
      parts += new FilePart(filePartKey, file.get, "plain/text", "UTF-8") //"multipart/form-data"
    }

    val mpre = new MultipartRequestEntity(parts.toArray, new FluentCaseInsensitiveStringsMap)
    val baos = new ByteArrayOutputStream
    mpre.writeRequest(baos)
    val bytes = baos.toByteArray
    val contentType = mpre.getContentType

    val url = s"http://localhost:$postPort$path"

    Logger.debug(s"Posting file to : $url")

    WS.url(url).post(bytes)(Writeable.wBytes, ContentTypeOf(Some(contentType))).futureValue
  }

}
