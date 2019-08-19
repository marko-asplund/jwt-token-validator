package com.practicingtechie.jwt

import java.security.cert.Certificate

import cats.effect._
import cats.effect.concurrent.Ref
import org.http4s.client.Client
import org.http4s.client.dsl.Http4sClientDsl

case class TokenSigningCertificates(certificates: Map[String, Certificate])

trait CertificateStore[F[_]] {
  def getCertificateById(id: String): F[Either[String, Certificate]]
}

class HttpCertStore[F[_] : Effect : Timer](httpClient: Client[F], d: Ref[F, TokenSigningCertificates]) extends CertificateStore[F] with Http4sClientDsl[F] {
  import java.security.cert.CertificateFactory
  import org.http4s.Uri
  import cats.implicits._
  import fs2.Stream
  import scala.concurrent.duration._

  val TokenVerificationCertificateUrlStrings = List(
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
    "https://www.googleapis.com/oauth2/v1/certs"
  )
  val TokenVerificationCertificateUrls = TokenVerificationCertificateUrlStrings.map(org.http4s.Uri.unsafeFromString)
  val certificateFactory = CertificateFactory.getInstance("X.509")
  val signingCertificateUpdateInterval = 2.seconds

  Stream.awakeEvery[F](signingCertificateUpdateInterval).evalMap { _ =>
    loadCertificates(TokenVerificationCertificateUrls).flatMap(certs => d.set(certs))
  }

  def loadCertificates(uris: List[Uri]) = {
    import cats.Traverse
    import cats.instances.list._
    import JsonCodec._

    def convertCertificateFromPem(pem: String): Either[String, Certificate] =
      Either.catchNonFatal(certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(pem.getBytes)))
        .leftMap(_.getMessage)

    Traverse[List].sequence(uris.map { uri =>
      httpClient.expect[Map[String, String]](uri).map(_.toList)
    }).map { data =>
      TokenSigningCertificates(data.flatten.map {
        case (kid, certPem) => kid -> convertCertificateFromPem(certPem).toOption
      }.filter(_._2.isDefined).map(kv => kv._1 -> kv._2.get).toMap)
    }
  }

  object JsonCodec {
    import org.http4s.EntityDecoder
    import org.http4s.circe._

    implicit val stringMapDecoder: EntityDecoder[F, Map[String, String]] = jsonOf[F, Map[String, String]]
  }

  override def getCertificateById(id: String): F[Either[String, Certificate]] = {
    d.get.map(s => Either.fromOption[String, Certificate](s.certificates.get(id), "cert not found"))
  }
}

object HttpCertStore {
  def apply[F[_]]: F[HttpCertStore[F]] = ???
}

class JwtTokenValidator[F[_] : Sync](certificateStore : CertificateStore[F]) {
  import java.security.cert.CertificateFactory
  import cats.data.EitherT
  import cats.implicits._
  import pdi.jwt.JwtCirce
  import pdi.jwt.algorithms
  import pdi.jwt.JwtClaim
  import cats.Id

  val SupportedJwtAlgorithmNames = pdi.jwt.JwtAlgorithm.allRSA().map(_.name).toSet

  def parseAndValidateToken(jwt: String): F[Either[String, JwtClaim]] = {
    val base64Header = jwt.split("\\.").headOption

    def base64Decode(s: String) = Either.catchNonFatal(java.util.Base64.getDecoder.decode(s))
      .map(new String(_))
      .leftMap(_.toString)

    def getAlgorithmNameAndKeyId(hdr: Map[String, String]) = for {
      alg <- EitherT.fromOptionF(hdr.get("alg").pure[F], "no alg")
      kid <- EitherT.fromOptionF(hdr.get("kid").pure[F], "no kid")
    } yield alg -> kid

    def getAlgorithm(algName: String) =
      if (SupportedJwtAlgorithmNames.contains(algName)) {
        Right(pdi.jwt.JwtAlgorithm.fromString(algName).asInstanceOf[algorithms.JwtRSAAlgorithm])
      } else {
        Left(s"unsupported algorithm $algName")
      }

    (for {
      decoded <- EitherT.fromEither[F](base64Decode(base64Header.get))
      jwtJson <- EitherT.fromEither[F](io.circe.jawn.parse(decoded).leftMap(_.message))
      jwtHeader <- EitherT.fromEither[F](jwtJson.as[Map[String, String]].leftMap(_.message))
      algNameAndKid <- getAlgorithmNameAndKeyId(jwtHeader)
      (algName, kid) = algNameAndKid
      algorithm <- EitherT.fromEither[F](getAlgorithm(algName))
      certificate <- EitherT(certificateStore.getCertificateById(kid))
      token <- EitherT.fromEither[F](JwtCirce.decode(jwt, certificate.getPublicKey, Seq(algorithm)).toEither.leftMap(_.getMessage))
    } yield token).value
  }

}
