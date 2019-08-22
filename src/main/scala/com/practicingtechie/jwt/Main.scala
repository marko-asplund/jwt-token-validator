package com.practicingtechie.jwt

import cats.effect._


object Main extends IOApp {
  import org.http4s.client.blaze._
  import scala.concurrent.ExecutionContext.global
  import cats.implicits._
  import fs2.Stream

  def run(args: List[String]): IO[ExitCode] =
    (for {
      client <- BlazeClientBuilder[IO](global).stream
      store <- Stream.eval(HttpCertStore[IO](client))
      validator <- Stream.eval(new JwtTokenValidator[IO](store).pure[IO])
      res <- Stream.eval(validator.parseAndValidateToken(token))
    } yield res match {
      case r @ Right(c) =>
        println(c.toJson)
        r
      case r =>
        println(r)
        r
    }).compile.drain.as(ExitCode.Success)
}