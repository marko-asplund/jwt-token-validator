name := "jwt-token-validator"

version := "0.1"

scalaVersion := "2.12.9"

val scalaLoggingV = "3.9.0"
val logBackV = "1.2.3"
val http4sV = "0.20.10"
val circeV = "0.11.1"
val specs2V = "4.6.0"
val jwtV = "0.18.0"

libraryDependencies ++= Seq(
  "org.http4s"          %% "http4s-dsl"           % http4sV,
  "org.http4s"          %% "http4s-blaze-client"  % http4sV,
  "org.http4s"          %% "http4s-circe"         % http4sV,
  "io.circe"            %% "circe-generic"        % circeV,
  "io.circe"            %% "circe-literal"        % circeV,
  "io.circe"            %% "circe-generic-extras" % circeV,
  "com.pauldijou"       %% "jwt-core"             % jwtV,
  "com.pauldijou"       %% "jwt-circe"            % jwtV,
)
