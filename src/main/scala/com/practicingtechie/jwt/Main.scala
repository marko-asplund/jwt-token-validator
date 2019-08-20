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
      res <- Stream.eval(validator.parseAndValidateToken("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn"))
    } yield res).compile.drain.as(ExitCode.Success)
}