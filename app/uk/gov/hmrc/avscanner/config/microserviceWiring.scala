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

package uk.gov.hmrc.avscanner.config

import uk.gov.hmrc.avscanner.config.ClamAvConfig._
import uk.gov.hmrc.play.audit.http.HttpAuditing
import uk.gov.hmrc.play.audit.http.config.LoadAuditingConfig
import uk.gov.hmrc.play.audit.http.connector.AuditConnector
import uk.gov.hmrc.play.auth.controllers.AuthParamsControllerConfig
import uk.gov.hmrc.play.auth.microservice.connectors.AuthConnector
import uk.gov.hmrc.play.config.{AppName, RunMode, ServicesConfig}
import uk.gov.hmrc.play.http.ws._

object WSHttp extends WSGet with WSPut with WSPost with WSDelete with WSPatch with AppName with RunMode with HttpAuditing {
  override val hooks = Seq(AuditingHook)
  override val auditConnector = MicroserviceAuditConnector
}

object AuthParamsControllerConfiguration extends AuthParamsControllerConfig {
  lazy val controllerConfigs = ControllerConfiguration.controllerConfigs
}

case class ClamAvConfig(enabled : Boolean,
                        chunkSize : Int,
                        protocol : String,
                        host : String,
                        port : Int,
                        timeout : Int,
                        threadPoolSize : Int){

  val url = s"$protocol://$host:$port"
  val instream = "zINSTREAM\u0000"
  val ping = "zPING\u0000"
  val status = "nSTATS\n"

  val okClamAvResponse = "stream: OK"

  def socket = {
    import java.net.{InetSocketAddress, Socket}

    val sock = new Socket
    sock.setSoTimeout(clamAvConfig.timeout)
    sock.connect(new InetSocketAddress(clamAvConfig.host, clamAvConfig.port))
    sock
  }
}

object ClamAvConfig {

  import play.api.Play
  import net.ceedubs.ficus.readers.ArbitraryTypeReader._
  import net.ceedubs.ficus.Ficus._

  lazy val clamAvConfig = Play.current.configuration.underlying.as[ClamAvConfig]("clam.antivirus")
}


//Connectors
object MicroserviceAuditConnector extends AuditConnector with RunMode {
  override lazy val auditingConfig = LoadAuditingConfig(s"$env.auditing")
}

object MicroserviceAuthConnector extends AuthConnector with ServicesConfig {
  override val authBaseUrl = baseUrl("auth")
}
