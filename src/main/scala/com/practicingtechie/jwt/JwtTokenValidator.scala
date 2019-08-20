package com.practicingtechie.jwt

import cats.effect._
import cats.effect.concurrent.Ref
import com.typesafe.scalalogging.Logger
import java.security.cert.Certificate
import org.http4s.client.Client


case class TokenSigningCertificates(certificates: Map[String, Certificate])

trait CertificateStore[F[_]] {
  def getCertificateById(id: String): F[Either[String, Certificate]]
}

trait HttpCertStoreSupport {
  import org.http4s.Uri

  def loadCertificates[F[_] : Effect](uris: List[Uri], httpClient: Client[F]): F[TokenSigningCertificates] = {
    import cats.implicits._
    import org.http4s.EntityDecoder
    import org.http4s.circe._
    import HttpCertStore.certificateFactory

    //logger.debug("loading certs")
    println("loading certs")
    implicit val stringMapDecoder: EntityDecoder[F, Map[String, String]] = jsonOf[F, Map[String, String]]

    def convertCertificateFromPem(pem: String) =
      Either.catchNonFatal(certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(pem.getBytes)))
        .leftMap(_.getMessage)

    uris.traverse { uri =>
      httpClient.expect[Map[String, String]](uri).map(_.toList)
    }.map { data =>
      TokenSigningCertificates(data.flatten.map {
        case (kid, certPem) => kid -> convertCertificateFromPem(certPem).toOption
      }.filter(_._2.isDefined).map(kv => kv._1 -> kv._2.get).toMap)
    }
  }

}

class HttpCertStore[F[_] : Effect : Timer](d: Ref[F, TokenSigningCertificates], httpClient: Client[F]) extends CertificateStore[F] with HttpCertStoreSupport {
  import cats.implicits._
  import fs2.Stream
  import HttpCertStore._

  val logger = Logger(this.getClass)

  Stream.awakeEvery[F](signingCertificateUpdateInterval).evalMap { _ =>
    println("awoke")
    loadCertificates(tokenVerificationCertificateUrls, httpClient).flatMap(certs => d.modify(old => certs -> old))
  }

  override def getCertificateById(id: String): F[Either[String, Certificate]] = {
    d.get.map(s => Either.fromOption[String, Certificate](s.certificates.get(id), s"cert $id not found"))
  }
}

object HttpCertStore extends HttpCertStoreSupport {
  import cats.implicits._
  import scala.concurrent.duration._
  import java.security.cert.CertificateFactory

  val logger = Logger(this.getClass)

  val signingCertificateUpdateInterval = 30.seconds
  val tokenVerificationCertificateUrlStrings = List(
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
    "https://www.googleapis.com/oauth2/v1/certs"
  )
  val tokenVerificationCertificateUrls = tokenVerificationCertificateUrlStrings.map(org.http4s.Uri.unsafeFromString)
  val certificateFactory = CertificateFactory.getInstance("X.509")

  def apply[F[_]: Effect : Timer](httpClient: Client[F]): F[HttpCertStore[F]] = for {
    certs <- loadCertificates(tokenVerificationCertificateUrls, httpClient)
    ref <- Ref.of[F, TokenSigningCertificates](certs)
  } yield new HttpCertStore[F](ref, httpClient)
}

class JwtTokenValidator[F[_] : Sync](certificateStore : CertificateStore[F]) {
  import cats.data.EitherT
  import cats.implicits._
  import pdi.jwt.JwtCirce
  import pdi.jwt.algorithms
  import pdi.jwt.JwtClaim

  val logger = Logger(this.getClass)

  val SupportedJwtAlgorithmNames = pdi.jwt.JwtAlgorithm.allRSA().map(_.name).toSet

  def parseAndValidateToken(jwt: String): F[Either[String, JwtClaim]] = {
    val base64Header = jwt.split("\\.").headOption

    def base64Decode(s: String) = Either.catchNonFatal(java.util.Base64.getDecoder.decode(s))
      .map(new String(_))
      .leftMap(_.toString)

    def getAlgorithmNameAndKeyId(hdr: Map[String, String]) = for {
      alg <- EitherT.fromOptionF(hdr.get("alg").pure[F], s"no alg: $hdr")
      kid <- EitherT.fromOptionF(hdr.get("kid").pure[F], s"no kid: $hdr")
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
    } yield token).value.map { r =>
      println(s"r: $r")
      r
    }
  }

}
