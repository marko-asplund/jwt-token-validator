package com.practicingtechie.jwt

import cats.effect._
import cats.effect.concurrent.Ref
import com.typesafe.scalalogging.Logger
import java.security.cert.X509Certificate
import org.http4s.client.Client


case class TokenSigningCertificates(certificates: Map[String, X509Certificate])

trait CertificateStore[F[_]] {
  def getCertificateById(id: String): F[Either[String, X509Certificate]]
  def startCertUpdaterStream: fs2.Stream[F, Unit]
}


trait HttpCertStoreSupport {
  self: { def logger: Logger } =>

  import org.http4s.Uri

  def loadCertificates[F[_] : Effect](uris: List[Uri], httpClient: Client[F]): F[TokenSigningCertificates] = {
    import cats.implicits._
    import org.http4s.EntityDecoder
    import org.http4s.circe._
    import HttpCertStore.certificateFactory

    logger.debug("loading certificates")
    implicit val stringMapDecoder: EntityDecoder[F, Map[String, String]] = jsonOf[F, Map[String, String]]

    def convertCertificateFromPem(pem: String) =
      Either.catchNonFatal(certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(pem.getBytes)).asInstanceOf[X509Certificate])
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

  def startCertUpdaterStream = Stream.awakeEvery[F](signingCertificateUpdateInterval).evalMap { _ =>
    logger.debug("refreshing certificates")
    loadCertificates(tokenVerificationCertificateUrls, httpClient).flatMap { certs =>
      d.modify { old =>
        val now = java.time.Instant.now
        val validCerts = old.certificates.filter{ case (_, cert) => now.isBefore(cert.getNotAfter.toInstant) }
        val newCerts = TokenSigningCertificates(certs.certificates ++ validCerts)
        logger.debug(s"stats: old: ${old.certificates.size}; valid old: ${validCerts.size}; new: ${newCerts.certificates.size}")
        newCerts -> old
      }.map(_ => ())
    }
  }

  override def getCertificateById(id: String): F[Either[String, X509Certificate]] = {
    d.get.map(s => Either.fromOption[String, X509Certificate](s.certificates.get(id), s"cert $id not found"))
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
  import pdi.jwt.{JwtAlgorithm, JwtCirce, JwtClaim, JwtOptions}
  import pdi.jwt.algorithms.JwtRSAAlgorithm

  val logger = Logger(this.getClass)

  val SupportedJwtAlgorithmNames = Seq(JwtAlgorithm.RS256).map(_.name).toSet
  val headerParseOpts = JwtOptions.DEFAULT.copy(signature = false)

  def parseAndValidateToken(jwt: String): F[Either[String, JwtClaim]] =
    (for {
      hdrClaimSig <- EitherT.fromEither[F](JwtCirce.decodeAll(jwt, headerParseOpts).toEither.leftMap(_.getMessage))
      (jwtHeader, _, _) = hdrClaimSig
      algo <- EitherT.fromOption[F](jwtHeader.algorithm, s"algorithm not specified: $jwtHeader")
      algorithm <- EitherT.cond[F](SupportedJwtAlgorithmNames.contains(algo.name), algo.asInstanceOf[JwtRSAAlgorithm], s"unsupported algorithm $algo")
      kid <- EitherT.fromOption[F](jwtHeader.keyId, s"keyId not specified: $jwtHeader")
      certificate <- EitherT(certificateStore.getCertificateById(kid))
      token <- EitherT.fromEither[F](JwtCirce.decode(jwt, certificate.getPublicKey, Seq(algorithm)).toEither.leftMap(_.getMessage))
    } yield token).value

}
