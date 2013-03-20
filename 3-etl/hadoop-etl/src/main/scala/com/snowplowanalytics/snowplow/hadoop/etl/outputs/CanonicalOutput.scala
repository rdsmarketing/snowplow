/*
 * Copyright (c) 2012-2013 SnowPlow Analytics Ltd. All rights reserved.
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
package com.snowplowanalytics.snowplow.hadoop.etl
package outputs

// Scala
import scala.reflect.BeanProperty

/**
 * The canonical output format.
 *
 * For simplicity, we are using our Redshift format
 * as the canonical format, i.e. the below is
 * equivalent to the redshift-etl.q HiveQL script
 * used by the Hive ETL.
 *
 * When we move to Avro, we will
 * probably review some of these
 * types (e.g. move back to
 * Array for browser features, and
 * switch remaining Bytes to Booleans).
 */
// TODO: update to include new Redshift fields
class CanonicalOutput {

  // The application (site, game, app etc) this event belongs to, and the tracker platform
  @BeanProperty var app_id: String = _
  @BeanProperty var platform: String = _

  // Date/time
  @BeanProperty var collector_tstamp: String = _
  @BeanProperty var dvce_tstamp: String = _

  // Transaction (i.e. this logging event)
  @BeanProperty var event: String = _
  @BeanProperty var event_id: String = _
  @BeanProperty var txn_id: String = _

  // Versioning
  @BeanProperty var v_tracker: String = _
  @BeanProperty var v_collector: String = _
  @BeanProperty var v_etl: String = _

  // User and visit
  @BeanProperty var user_id: String = _
  @BeanProperty var user_ipaddress: String = _
  @BeanProperty var user_fingerprint: String = _
  @BeanProperty var visit_id: Int = _ // TODO: comment out

  // @BeanProperty var domain_userid String = _
  // @BeanProperty var domain_sessionidx: Int = _
  // @BeanProperty var network_userid String = _

  // Page
  @BeanProperty var page_url: String = _ // TODO: comment out
  @BeanProperty var page_title: String = _
  @BeanProperty var page_referrer: String = _

  // Page URL components
  /* @BeanProperty var page_urlscheme: String = _  
  @BeanProperty var page_urlhost: String = _   
  @BeanProperty var page_urlport: Int = _      
  @BeanProperty var page_urlpath: String = _
  @BeanProperty var page_urlquery: String = _
  @BeanProperty var page_urlfragment: String = _ */

  // Marketing
  @BeanProperty var mkt_medium: String = _
  @BeanProperty var mkt_source: String = _
  @BeanProperty var mkt_term: String = _
  @BeanProperty var mkt_content: String = _
  @BeanProperty var mkt_campaign: String = _

  // Event
  @BeanProperty var ev_category: String = _
  @BeanProperty var ev_action: String = _
  @BeanProperty var ev_label: String = _
  @BeanProperty var ev_property: String = _
  @BeanProperty var ev_value: String = _

  // Ecommerce transaction (from querystring)
  @BeanProperty var tr_orderid: String = _
  @BeanProperty var tr_affiliation: String = _
  @BeanProperty var tr_total: String = _
  @BeanProperty var tr_tax: String = _
  @BeanProperty var tr_shipping: String = _
  @BeanProperty var tr_city: String = _
  @BeanProperty var tr_state: String = _
  @BeanProperty var tr_country: String = _

  // Ecommerce transaction item (from querystring)
  @BeanProperty var ti_orderid: String = _
  @BeanProperty var ti_sku: String = _
  @BeanProperty var ti_name: String = _
  @BeanProperty var ti_category: String = _
  @BeanProperty var ti_price: String = _
  @BeanProperty var ti_quantity: String = _

  // User Agent
  @BeanProperty var useragent: String = _

  // Browser (from user-agent)
  @BeanProperty var br_name: String = _
  @BeanProperty var br_family: String = _
  @BeanProperty var br_version: String = _
  @BeanProperty var br_type: String = _
  @BeanProperty var br_renderengine: String = _

  // Page Pings
  @BeanProperty var pp_xoffset_min: String = _
  @BeanProperty var pp_xoffset_max: String = _
  @BeanProperty var pp_yoffset_min: String = _
  @BeanProperty var pp_yoffset_max: String = _

  // Browser (from querystring)
  @BeanProperty var br_lang: String = _
  // Individual feature fields for non-Hive targets (e.g. Infobright)
  @BeanProperty var br_features_pdf: Byte = _
  @BeanProperty var br_features_flash: Byte = _
  @BeanProperty var br_features_java: Byte = _
  @BeanProperty var br_features_director: Byte = _
  @BeanProperty var br_features_quicktime: Byte = _
  @BeanProperty var br_features_realplayer: Byte = _
  @BeanProperty var br_features_windowsmedia: Byte = _
  @BeanProperty var br_features_gears: Byte = _
  @BeanProperty var br_features_silverlight: Byte = _
  @BeanProperty var br_cookies: Byte = _
  @BeanProperty var br_colordepth: String = _
  // @BeanProperty var br_viewwidth: Int = _ 
  // @BeanProperty var br_viewheight: Int = _ 

  // OS (from user-agent)
  @BeanProperty var os_name: String = _
  @BeanProperty var os_family: String = _
  @BeanProperty var os_manufacturer: String = _
  @BeanProperty var os_timezone: String = _

  // Device/Hardware (from user-agent)
  @BeanProperty var dvce_type: String = _
  @BeanProperty var dvce_ismobile: Byte = _

  // Device (from querystring)
  @BeanProperty var dvce_screenwidth: Int = _
  @BeanProperty var dvce_screenheight: Int = _

  // Document
  // @BeanProperty var doc_charset: String = _
  // @BeanProperty var doc_width: Int = _
  // @BeanProperty var doc_height: Int = _
}
