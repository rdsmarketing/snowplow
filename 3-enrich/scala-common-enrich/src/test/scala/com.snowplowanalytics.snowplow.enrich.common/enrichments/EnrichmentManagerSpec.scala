/*
 * Copyright (c) 2012-2020 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.common
package enrichments

import org.specs2.mutable.Specification
import org.specs2.matcher.ValidatedMatchers

import cats.Eval
import cats.implicits._

import io.circe.literal._

import org.joda.time.DateTime

import com.snowplowanalytics.snowplow.badrows._

import com.snowplowanalytics.iglu.core.{SchemaKey, SchemaVer}
import com.snowplowanalytics.iglu.client.ClientError.ValidationError

import loaders._
import adapters.RawEvent
import utils.Clock._
import utils.ConversionUtils
import enrichments.registry.JavascriptScriptEnrichment

class EnrichmentManagerSpec extends Specification with ValidatedMatchers {
  val enrichmentReg = EnrichmentRegistry[Eval]()
  val client = SpecHelpers.client
  val processor = Processor("ssc-tests", "0.0.0")
  val timestamp = DateTime.now()

  val api = CollectorPayload.Api("com.snowplowanalytics.snowplow", "tp2")
  val source = CollectorPayload.Source("clj-tomcat", "UTF-8", None)
  val context = CollectorPayload.Context(
    DateTime.parse("2013-08-29T00:18:48.000+00:00").some,
    "37.157.33.123".some,
    None,
    None,
    Nil,
    None
  )

  "enrichEvent" should {
    "emit a SchemaViolation if the input event contains an invalid context" >> {
      val parameters = Map(
        "e" -> "ue",
        "tv" -> "js-0.13.1",
        "p" -> "web",
        "co" -> """
          {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
              {
                "schema":"iglu:com.acme/email_sent/jsonschema/1-0-0",
                "data": {
                  "foo": "hello@world.com",
                  "emailAddress2": "foo@bar.org"
                }
              }
            ]
          }
        """,
        "ue_pr" -> """
          {
            "schema":"iglu:com.snowplowanalytics.snowplow/unstruct_event/jsonschema/1-0-0",
            "data":{
              "schema":"iglu:com.acme/email_sent/jsonschema/1-0-0",
              "data": {
                "emailAddress": "hello@world.com",
                "emailAddress2": "foo@bar.org"
              }
            }    
          }"""
      )
      val rawEvent = RawEvent(api, parameters, None, source, context)
      val enriched = EnrichmentManager.enrichEvent(
        enrichmentReg,
        client,
        processor,
        timestamp,
        rawEvent
      )
      enriched.value must beInvalid.like {
        case (errs, _)
            if errs.size == 1 && errs.head.isInstanceOf[FailureDetails.SchemaViolation] =>
          ok
        case (errs, _) => ko(s"failures [$errs] is not one SchemaViolation")
      }
    }

    "emit a SchemaViolation if the input event contains an invalid unstructured event" >> {
      val parameters = Map(
        "e" -> "ue",
        "tv" -> "js-0.13.1",
        "p" -> "web",
        "co" -> """
          {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
              {
                "schema":"iglu:com.acme/email_sent/jsonschema/1-0-0",
                "data": {
                  "emailAddress": "hello@world.com",
                  "emailAddress2": "foo@bar.org"
                }
              }
            ]
          }
        """,
        "ue_pr" -> """
          {
            "schema":"iglu:com.snowplowanalytics.snowplow/unstruct_event/jsonschema/1-0-0",
            "data":{
              "schema":"iglu:com.acme/email_sent/jsonschema/1-0-0",
              "data": {
                "emailAddress": "hello@world.com",
                "emailAddress2": "foo@bar.org",
                "emailAddress3": "foo@bar.org"
              }
            }    
          }"""
      )
      val rawEvent = RawEvent(api, parameters, None, source, context)
      val enriched = EnrichmentManager.enrichEvent(
        enrichmentReg,
        client,
        processor,
        timestamp,
        rawEvent
      )
      enriched.value must beInvalid.like {
        case (errs, _)
            if errs.size == 1 && errs.head.isInstanceOf[FailureDetails.SchemaViolation] =>
          ok
        case (errs, _) =>
          ko(s"failures [$errs] is not one SchemaViolation")
      }
    }

    "emit an EnrichmentFailure.IgluError if one of the contexts added by the enrichments is invalid (with JS enrichment)" >> {
      val script = """
        function process(event) {
          return [ { schema: "iglu:com.acme/email_sent/jsonschema/1-0-0",
                     data: {
                       emailAddress: "hello@world.com",
                       foo: "bar"
                     }
                   } ];
        }"""

      val config = json"""{
        "parameters": {
          "script": ${ConversionUtils.encodeBase64Url(script)}
        }
      }"""
      val schemaKey = SchemaKey(
        "com.snowplowanalytics.snowplow",
        "javascript_script_config",
        "jsonschema",
        SchemaVer.Full(1, 0, 0)
      )
      val jsEnrichConf =
        JavascriptScriptEnrichment.parse(config, schemaKey).toOption.get
      val jsEnrich = JavascriptScriptEnrichment(jsEnrichConf.schemaKey, jsEnrichConf.script)
      val enrichmentReg = EnrichmentRegistry[Eval](javascriptScript = Some(jsEnrich))

      val parameters = Map(
        "e" -> "pp",
        "tv" -> "js-0.13.1",
        "p" -> "web"
      )
      val rawEvent = RawEvent(api, parameters, None, source, context)
      val enriched = EnrichmentManager.enrichEvent(
        enrichmentReg,
        client,
        processor,
        timestamp,
        rawEvent
      )
      enriched.value must beInvalid.like {
        case (err, _) if err.size == 1 =>
          err.head match {
            case FailureDetails.EnrichmentFailure(
                _,
                FailureDetails.EnrichmentFailureMessage.IgluError(_, ValidationError(_))
                ) =>
              ok
            case _ =>
              ko(
                s"failure [${err.head}] is not an EnrichmentFailure wrapping an IgluError.ValidatiobError"
              )
          }
        case (errs, _) => ko(s"there are [${errs.size}] errors: [$errs]")
      }
    }

    "emit an EnrichedEvent if the input event contains a valid context and a valid unstructured event" >> {
      val parameters = Map(
        "e" -> "ue",
        "tv" -> "js-0.13.1",
        "p" -> "web",
        "co" -> """
          {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
              {
                "schema":"iglu:com.acme/email_sent/jsonschema/1-0-0",
                "data": {
                  "emailAddress": "hello@world.com",
                  "emailAddress2": "foo@bar.org"
                }
              }
            ]
          }
        """,
        "ue_pr" -> """
          {
            "schema":"iglu:com.snowplowanalytics.snowplow/unstruct_event/jsonschema/1-0-0",
            "data":{
              "schema":"iglu:com.acme/email_sent/jsonschema/1-0-0",
              "data": {
                "emailAddress": "hello@world.com",
                "emailAddress2": "foo@bar.org"
              }
            }    
          }"""
      )
      val rawEvent = RawEvent(api, parameters, None, source, context)
      val enriched = EnrichmentManager.enrichEvent(
        enrichmentReg,
        client,
        processor,
        timestamp,
        rawEvent
      )
      enriched.value must beValid
    }
  }
}
