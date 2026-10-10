#!/usr/bin/env node

import dotenv from "dotenv";
dotenv.config();

import { pathToFileURL } from "url";
import { randomUUID } from "crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type Tool,
  type CallToolResult,
  type CallToolRequest,
} from "@modelcontextprotocol/sdk/types.js";

import axios, { type AxiosError } from "axios";

import type { UberCookie, UberCredentials } from "./http/store.js";
import { ValidationError, encodePathSegment, redact, validateToolArgs } from "./security.js";

/* ---------------------------------- types --------------------------------- */

export type UberBaseUrl = "main" | "riders" | "www" | "payments";

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  method: string;
  pathTemplate: string;
  baseUrl: UberBaseUrl;
  pathParams?: string[];
  queryParams?: string[];
  bodyParams?: string[];
  bodyUnwrap?: string;
  requiresAuth: boolean;
}

export const MAIN_URL = "https://m.uber.com";
export const RIDERS_URL = "https://riders.uber.com";
export const WWW_URL = "https://www.uber.com";
export const PAYMENTS_URL = "https://payments.uber.com";

const PAYMENTS_HUB_KEY = "production_w0u8jzht15p89t0n";
const PAYMENTS_HUB_USE_CASE = "yhmvvwxovgzqionxwhprhrznpkikhrjvszqvkhlh";

export interface TokenProvider {
  getValidToken(): Promise<{
    token: string | null;
    accountId: string;
    deviceId?: string;
    sessionId?: string;
    error?: string;
    credentials?: UberCredentials;
  }>;
}

/* ----------------------------- env-based provider ------------------------- */

export class EnvTokenProvider implements TokenProvider {
  async getValidToken(): Promise<{
    token: string | null;
    accountId: string;
    error?: string;
    credentials?: UberCredentials;
  }> {
    const cookieHeader = process.env.UBER_COOKIE_HEADER;
    if (!cookieHeader) {
      return {
        token: null,
        accountId: "",
        error:
          "Not authenticated. Run `npm run start:http` and complete /login/start, then export UBER_COOKIE_HEADER, UBER_CITY_ID, UBER_SESSION_TYPE, UBER_USER_SUB into .env.",
      };
    }
    const cityId = Number(process.env.UBER_CITY_ID || "458");
    const sessionType =
      (process.env.UBER_SESSION_TYPE as "desktop_session" | "mobile_session") ||
      "desktop_session";
    const userSub = process.env.UBER_USER_SUB || "env-user";

    const cookies: UberCookie[] = cookieHeader
      .split(";")
      .map((p) => p.trim())
      .filter(Boolean)
      .map((kv) => {
        const eq = kv.indexOf("=");
        const name = eq >= 0 ? kv.slice(0, eq) : kv;
        const value = eq >= 0 ? kv.slice(eq + 1) : "";
        return {
          name,
          value,
          domain: ".uber.com",
          path: "/",
          expires: -1,
          httpOnly: false,
          secure: true,
        };
      });

    const credentials: UberCredentials = {
      cookies,
      cookieHeader,
      cityId,
      sessionType,
      userSub,
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
      capturedAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 86400,
    };

    return { token: "cookie", accountId: userSub, credentials };
  }
}

const defaultProvider = new EnvTokenProvider();

/* ----------------------- request header construction ---------------------- */

function originAndReferer(baseUrl: UberBaseUrl): { origin: string; referer: string } {
  switch (baseUrl) {
    case "main":
      return { origin: "https://m.uber.com", referer: "https://m.uber.com/go/home" };
    case "riders":
      return { origin: "https://riders.uber.com", referer: "https://riders.uber.com/" };
    case "www":
      return { origin: "https://www.uber.com", referer: "https://www.uber.com/" };
    case "payments":
      return {
        origin: "https://payments.uber.com",
        referer: "https://m.uber.com/go/product-selection",
      };
  }
}

function domainMatches(cookieDomain: string, host: string): boolean {
  const d = cookieDomain.startsWith(".") ? cookieDomain.slice(1) : cookieDomain;
  return host === d || host.endsWith("." + d);
}

function buildCookieHeaderForHost(creds: UberCredentials, host: string): string {
  const filtered = creds.cookies.filter((c) => domainMatches(c.domain, host));
  if (filtered.length > 0) {
    return filtered.map((c) => `${c.name}=${c.value}`).join("; ");
  }
  return creds.cookieHeader;
}

function targetHost(baseUrl: UberBaseUrl): string {
  switch (baseUrl) {
    case "main":
      return "m.uber.com";
    case "riders":
      return "riders.uber.com";
    case "www":
      return "www.uber.com";
    case "payments":
      return "payments.uber.com";
  }
}

function getDefaultHeaders(
  creds: UberCredentials,
  baseUrl: UberBaseUrl
): Record<string, string> {
  const { origin, referer } = originAndReferer(baseUrl);
  const cookie = buildCookieHeaderForHost(creds, targetHost(baseUrl));
  const headers: Record<string, string> = {
    accept: "*/*",
    "accept-language": "en-US,en;q=0.5",
    "content-type": "application/json",
    cookie,
    origin,
    referer,
    "user-agent": creds.userAgent,
    "x-csrf-token": "x",
  };
  // HAR-verified: only m.uber.com sends both RV headers; riders only sends session-type.
  if (baseUrl === "main") {
    headers["x-uber-rv-initial-load-city-id"] = String(creds.cityId);
    headers["x-uber-rv-session-type"] = creds.sessionType;
  } else if (baseUrl === "riders") {
    headers["x-uber-rv-session-type"] = creds.sessionType;
  }
  return headers;
}

/* ----------------------------- url construction --------------------------- */

function baseUrlFor(b: UberBaseUrl): string {
  switch (b) {
    case "main":
      return MAIN_URL;
    case "riders":
      return RIDERS_URL;
    case "www":
      return WWW_URL;
    case "payments":
      return PAYMENTS_URL;
  }
}

function buildPath(template: string, args: Record<string, unknown>): string {
  let path = template;
  const matches = template.match(/\{[^}]+\}/g);
  if (matches) {
    for (const m of matches) {
      const key = m.slice(1, -1);
      const val = args[key];
      if (val !== undefined && val !== null) {
        path = path.replace(m, encodePathSegment(val));
      }
    }
  }
  return path;
}

function buildQuery(
  def: McpToolDefinition,
  args: Record<string, unknown>
): Record<string, string> {
  const params: Record<string, string> = {};
  for (const key of def.queryParams || []) {
    const val = args[key];
    if (val !== undefined && val !== null && val !== "") {
      params[key] = String(val);
    }
  }
  if (def.baseUrl === "www" && !params.localeCode) {
    params.localeCode = "en";
  }
  if (def.baseUrl === "payments") {
    params.key = PAYMENTS_HUB_KEY;
    if (def.pathTemplate.includes("/_api/payment-options")) {
      // HAR: useCaseKey in URL for payment-options only
      params.useCaseKey = PAYMENTS_HUB_USE_CASE;
    }
    if (def.pathTemplate.includes("getPreCheckoutActions")) {
      // HAR: getPreCheckoutActions uses localeCode in URL, useCaseKey goes in the body
      params.localeCode = "en";
    }
  }
  return params;
}

function buildBody(
  def: McpToolDefinition,
  args: Record<string, unknown>
): Record<string, unknown> | undefined {
  if (!def.bodyParams || def.bodyParams.length === 0) return undefined;
  const body: Record<string, unknown> = {};
  for (const key of def.bodyParams) {
    const val = args[key];
    if (val !== undefined) body[key] = val;
  }
  return Object.keys(body).length > 0 ? body : undefined;
}

/* ----------------------------- GraphQL queries ---------------------------- */

const GET_STATUS_QUERY = `query GetStatus($latitude: Float!, $longitude: Float!, $share: InputShare, $targetProductType: EnumRVWebCommonTargetProductType) {
  status(latitude: $latitude, longitude: $longitude, share: $share, targetProductType: $targetProductType) {
    city { countryIso2 currencyCode id name timezone __typename }
    clientStatus
    coordinate { latitude longitude __typename }
    lastRequest { jobUUID message note type __typename }
    nearbyVehicles { bearing coordinate { latitude longitude __typename } etaInMin etaStringShort id mapImageUrl __typename }
    pollingIntervalMs
    productsUnavailableMessage
    trip { uuid clientStatus clientUUID eta etaStringShort fareString cancelable driver { name pictureUrl rating status uuid __typename } vehicle { licensePlate make model mapImageUrl bearing coordinate { latitude longitude __typename } __typename } waypoints { coordinate { latitude longitude __typename } title subtitle type __typename } __typename }
    trips { uuid clientStatus __typename }
    __typename
  }
}`;

const PUDO_LOCATION_SEARCH_QUERY = `query PudoLocationSearch($isUserTriggeredFallback: Boolean, $latitude: Float!, $longitude: Float!, $query: String!, $type: EnumRVWebCommonPickupOrDropoff!) {
  pudoLocationSearch(isUserTriggeredFallback: $isUserTriggeredFallback latitude: $latitude longitude: $longitude query: $query type: $type) {
    savedPlacesMeta { label tag __typename }
    addressLine1 addressLine2 categories confidence id source provider tag type
    __typename
  }
}`;

const PUDO_RESOLVE_QUERY = `query PudoResolveLocationPudoFragment($id: String, $includeAirportTerminals: Boolean = false, $includeRAPUStatus: Boolean = false, $includeTimezone: Boolean = false, $source: EnumRVWebCommonLocationSource, $provider: String, $latitude: Float, $longitude: Float) {
  pudoResolveLocation(id: $id source: $source provider: $provider latitude: $latitude longitude: $longitude) {
    addressLine1 addressLine2 categories confidence id source provider tag type
    coordinate { latitude longitude __typename }
    coordinateRefined { pickup { latitude longitude __typename } dropoff { latitude longitude __typename } __typename }
    timezone @include(if: $includeTimezone)
    airportTerminals @include(if: $includeAirportTerminals) { airline logoUrl terminals { addressLine1 addressLine2 coordinate { latitude longitude __typename } id __typename } __typename }
    reserveAirportPickupData @include(if: $includeRAPUStatus) { airportCode enabled __typename }
    __typename
  }
}`;

const PUDO_REFINEMENT_QUERY = `query PudoLocationRefinement($pickup: InputRVWebCommonCoordinate!, $pickupTime: Float, $vvid: Int!, $id: String, $provider: String, $source: EnumRVWebCommonLocationSource) {
  pudoLocationRefinement(pickup: $pickup pickupTime: $pickupTime vvid: $vvid id: $id provider: $provider source: $source) {
    anchor {
      addressLine1 addressLine2 id source provider tag type
      coordinate { latitude longitude __typename }
      locationRefinementMeta { instructions segment __typename }
      timezone
      __typename
    }
    containingZonePolygonPoints { latitude longitude __typename }
    locations {
      accessPoints { coordinate { latitude longitude __typename } instructions name provider segment shouldGeneratePickupDispatchPin subtitle uuid __typename }
      coordinate { latitude longitude __typename }
      id name
      polygonPoints { latitude longitude __typename }
      __typename
    }
    mode
    __typename
  }
}`;

const RANKED_OFFERS_QUERY = `query RankedOffers($cityId: Int!, $countryIso2: String!, $currencyCode: String!, $timezone: String!) {
  rankedOffers(cityId: $cityId countryIso2: $countryIso2 currencyCode: $currencyCode timezone: $timezone) {
    offers {
      id type
      award { description displayDate displayLocation promotionUuid uuid restrictions endTime startTime __typename }
      __typename
    }
    __typename
  }
}`;

const PRODUCTS_QUERY = `query Products($boostedVehicleId: String, $capacity: Int, $destinations: [InputCoordinate!]!, $includeRecommended: Boolean = false, $isRiderCurrentUser: Boolean, $payment: InputPayment, $paymentProfileUUID: String, $pickup: InputCoordinate!, $pickupFormattedTime: String, $profileType: String, $profileUUID: String, $returnByFormattedTime: String, $stuntID: String, $targetProductType: EnumRVWebCommonTargetProductType) {
  products(boostedVehicleId: $boostedVehicleId capacity: $capacity destinations: $destinations includeRecommended: $includeRecommended isRiderCurrentUser: $isRiderCurrentUser payment: $payment paymentProfileUUID: $paymentProfileUUID pickup: $pickup pickupFormattedTime: $pickupFormattedTime profileType: $profileType profileUUID: $profileUUID returnByFormattedTime: $returnByFormattedTime stuntID: $stuntID targetProductType: $targetProductType) {
    defaultVVID
    productsUnavailableMessage
    tiers {
      title
      products {
        badges { backgroundColor color contentColor icon text __typename }
        cityID currencyCode description displayName estimatedTripTime etaInMin etaStringShort
        fares { capacity discountPrimary fare fareAmountE5 hasPromo hasRidePass meta preAdjustmentValue __typename }
        hasPromo hasRidePass iconType id is3p isAvailable parentProductUuid preAdjustmentValue
        productClassificationTypeName productImageUrl productUuid reserveEnabled vehicleViewUuid
        __typename
      }
      __typename
    }
    __typename
  }
}`;

const PRE_PLUS_ONES_QUERY = `query GetPrePlusOnesData($pickup: InputCoordinate!, $pickupTime: Float, $vvid: Int!, $skipVenue: Boolean!) {
  venue(pickup: $pickup pickupTime: $pickupTime vvid: $vvid) @skip(if: $skipVenue) {
    id name hasVenue welcomeTitle welcomeDescription
    zones { name pickupLocations { coordinate { latitude longitude __typename } name subtitle __typename } __typename }
    __typename
  }
  ftux(pickup: $pickup vvid: $vvid) {
    main { caption subTitle title __typename }
    image { dark light __typename }
    rows { icon title __typename }
    __typename
  }
}`;

const RESERVATION_DATA_QUERY = `query DateTimeReservationData($coordinate: InputCoordinate!) {
  dateTimeReservationData(coordinate: $coordinate) {
    bookingRange { maximum minimum __typename }
    messages { caption icon subTitle title type __typename }
    terms { content title __typename }
    type
    __typename
  }
}`;

const TRIP_REQUEST_MUTATION = `mutation TripRequest($attribution: InputAttribution, $capacity: Int, $delegateID: String, $destinations: [InputLocation!]!, $guest: InputRVWebCommonBounceGuest, $tippingSpec: InputTippingSpec, $locationSource: EnumLocationSource, $meta: String!, $origin: InputOrigin!, $payment: InputTripPayment!, $pickupTimeMsec: Float, $type: EnumTripRequestType!, $hcvInfo: InputHCVInfo, $hourlyInfo: InputHourlyInfo, $vehicleView: InputVehicleView!, $waypointSpecs: [InputWaypointSpec!], $riderPreferences: InputTripRequestRiderPreferences) {
  tripRequest(attribution: $attribution capacity: $capacity delegateID: $delegateID destinations: $destinations guest: $guest hcvInfo: $hcvInfo hourlyInfo: $hourlyInfo tippingSpec: $tippingSpec locationSource: $locationSource meta: $meta origin: $origin payment: $payment pickupTimeMsec: $pickupTimeMsec riderPreferences: $riderPreferences type: $type vehicleView: $vehicleView waypointSpecs: $waypointSpecs) {
    errorCode errorKey
    plusOne { buttonPrimary { buttonkey text __typename } buttonSecondary { buttonkey text __typename } meta subtitle title type __typename }
    riderHasCompletedTrips uuid checkoutActionParameters
    __typename
  }
}`;

const CANCELLATION_INFO_QUERY = `query CancellationInformation($tripUUID: String!, $reservationUUID: String!, $pickup: InputLocation) {
  cancellationInformation(tripUUID: $tripUUID reservationUUID: $reservationUUID pickup: $pickup) {
    acceptButtonTitle cancelButtonTitle chargeFee messages title
    __typename
  }
}`;

const TRIP_CANCEL_MUTATION = `mutation TripCancel($current: Boolean!, $uuid: String) {
  tripCancel(current: $current, uuid: $uuid)
}`;

const GET_THREAD_QUERY = `query getThread($request: GetThreadRequest!) {
  getThread(request: $request) {
    threadType
    participantWithTurn { participantMappedId participantUUID __typename }
    participants { locale participantId { participantMappedId participantServiceType participantAppVariant participantUUID __typename } participantMeta uiConfiguration __typename }
    messages {
      messageUUID meta timestamp
      content {
        contentType
        contentData {
          __typename
          ... on TextType { type text __typename }
          ... on ContentJSON { type json __typename }
          ... on CustomData { type custom { contentJson __typename } __typename }
          ... on PrecannedContent { type precannedContent { text translated precannedKey __typename } __typename }
          ... on TextWithPrecannedSuggestions { type textWithPrecannedSuggestions { encodedText precannedKeys __typename } __typename }
        }
        __typename
      }
      sender { locale participantId { participantMappedId participantServiceType participantUUID __typename } __typename }
      __typename
    }
    turnContext { isStopEnabled __typename }
    __typename
  }
}`;

const GET_THREAD_BY_TRACKING_QUERY = `query getThreadByTrackingInfo($request: GetThreadByTrackingInfoRequest__Input!) {
  getThreadByTrackingInfo(request: $request) {
    threadUUID
    __typename
  }
}`;

const CURRENT_USER_RIDERS_QUERY = `query CurrentUserRidersWeb($includeDelegateProfiles: Boolean = false, $includeUserMemberships: Boolean = false, $useUberCashBalanceBreakdown: Boolean = false) {
  currentUser {
    firstName lastName email formattedNumber languageId role signupCountry
    lastSelectedPaymentProfileUuid pictureUrl rating tenancy uuid
    profileBalance
    userTags { hasDelegate isAdmin isTester isTeen __typename }
    paymentProfiles { authenticationType displayable { displayName iconURL __typename } hasBalance tokenType uuid __typename }
    profiles {
      defaultPaymentProfileUuid name secondaryPaymentProfileUuid type uuid
      managedBusinessProfileAttributes { isBilledToCompany logoUrl __typename }
      delegateProfileAttributes @include(if: $includeDelegateProfiles) {
        delegatorAttributes { delegatedProfileUUID uuid firstName lastName pictureUrl __typename }
        role __typename
      }
      __typename
    }
    uberCashBalances(useUberCashBalanceBreakdown: $useUberCashBalanceBreakdown) { amount currency __typename }
    membershipBenefits @include(if: $includeUserMemberships) { hasUberOne __typename }
    __typename
  }
}`;

const ACTIVITIES_QUERY = `query Activities($cityID: Int, $endTimeMs: Float, $includePast: Boolean = true, $includeUpcoming: Boolean = true, $limit: Int = 5, $nextPageToken: String, $orderTypes: [RVWebCommonActivityOrderType!] = [RIDES, TRAVEL], $profileType: RVWebCommonActivityProfileType = PERSONAL, $startTimeMs: Float) {
  activities(cityID: $cityID) {
    cityID
    past(endTimeMs: $endTimeMs limit: $limit nextPageToken: $nextPageToken orderTypes: $orderTypes profileType: $profileType startTimeMs: $startTimeMs) @include(if: $includePast) {
      activities { buttons { isDefault startEnhancerIcon text url __typename } cardURL description imageURL { light dark __typename } subtitle title uuid __typename }
      nextPageToken __typename
    }
    upcoming @include(if: $includeUpcoming) {
      activities { buttons { isDefault startEnhancerIcon text url __typename } cardURL description imageURL { light dark __typename } subtitle title uuid __typename }
      __typename
    }
    __typename
  }
}`;

const GET_TRIP_QUERY = `query GetTrip($tripUUID: String!) {
  getTrip(tripUUID: $tripUUID) {
    trip { beginTripTime cityID countryID disableCanceling disableRating disableResendReceipt driver dropoffTime fare guest isRidepoolTrip isScheduledRide isSurgeTrip isUberReserve jobUUID marketplace paymentProfileUUID showRating status uuid vehicleDisplayName vehicleViewID waypoints __typename }
    mapURL polandTaxiLicense rating reviewer
    receipt { carYear distance distanceLabel duration vehicleType __typename }
    concierge { sourceType __typename }
    organization { name __typename }
    __typename
  }
}`;

const GET_RECEIPT_QUERY = `query GetReceipt($tripUUID: String!, $timestamp: String) {
  getReceipt(tripUUID: $tripUUID, timestamp: $timestamp) {
    actionList { type helpNodeUUID __typename }
    receiptData
    receiptsForJob { timestamp type eventUUID __typename }
    __typename
  }
}`;

const SEND_RECEIPT_EMAIL_MUTATION = `mutation SendReceiptEmail($tripUUID: String!) {
  sendReceiptEmail(tripUUID: $tripUUID) {
    success __typename
  }
}`;

const GET_INVOICE_STATUS_QUERY = `query GetInvoiceStatus($tripUUID: ID!, $tripDate: Float, $tripCountryId: Int, $tripMarketplace: String, $tripVehicleViewId: Int) {
  invoiceStatus(tripUUID: $tripUUID tripDate: $tripDate tripCountryId: $tripCountryId tripMarketplace: $tripMarketplace tripVehicleViewId: $tripVehicleViewId) {
    status message
    errors { code title messages actions { label type isSecondary link __typename } __typename }
    __typename
  }
}`;

const GET_ARREARS_QUERY = `query GetArrears($enableNewArrearFlow: Boolean!) {
  getArrears(enableNewArrearFlow: $enableNewArrearFlow) {
    amountString beginTripTime tripUUID hasArrears __typename
  }
}`;

const NAV_LINKS_QUERY = `query NavLinks {
  navLinks {
    login { href icon imageUrl text type __typename }
    main { href icon imageUrl text type __typename }
    nava { href icon imageUrl text type __typename }
    profile { links { href icon imageUrl text type __typename } currentGeofenceCurrencyCode firstName lastName pictureURL __typename }
    signup { href icon imageUrl text type __typename }
    __typename
  }
}`;

const CLIENT_HAS_TAX_FORMS_QUERY = `query ClientHasTaxForms {
  clientHasTaxForms { clientHasTaxForms __typename }
}`;

export const HARDCODED_QUERIES: Record<string, string> = {
  uber_status_get: GET_STATUS_QUERY,
  uber_pudo_search: PUDO_LOCATION_SEARCH_QUERY,
  uber_pudo_resolve: PUDO_RESOLVE_QUERY,
  uber_pudo_refine: PUDO_REFINEMENT_QUERY,
  uber_offers_ranked: RANKED_OFFERS_QUERY,
  uber_products_list: PRODUCTS_QUERY,
  uber_pre_plus_ones_get: PRE_PLUS_ONES_QUERY,
  uber_reservation_data_get: RESERVATION_DATA_QUERY,
  uber_trip_request: TRIP_REQUEST_MUTATION,
  uber_trip_cancel: TRIP_CANCEL_MUTATION,
  uber_cancellation_info_get: CANCELLATION_INFO_QUERY,
  uber_thread_get: GET_THREAD_QUERY,
  uber_thread_by_tracking_get: GET_THREAD_BY_TRACKING_QUERY,
  uber_user_riders_get: CURRENT_USER_RIDERS_QUERY,
  uber_activities_list: ACTIVITIES_QUERY,
  uber_trip_get: GET_TRIP_QUERY,
  uber_receipt_get: GET_RECEIPT_QUERY,
  uber_receipt_send_email: SEND_RECEIPT_EMAIL_MUTATION,
  uber_invoice_status_get: GET_INVOICE_STATUS_QUERY,
  uber_arrears_get: GET_ARREARS_QUERY,
  uber_navlinks_get: NAV_LINKS_QUERY,
  uber_tax_forms_check: CLIENT_HAS_TAX_FORMS_QUERY,
};

/* -------------------------------- tools ----------------------------------- */

export const toolDefinitions: McpToolDefinition[] = [
  // ── m.uber.com GraphQL ──────────────────────────────────────────────────
  {
    name: "uber_status_get",
    description:
      "Get the rider's current status near a location: city info, current trip (if any), nearby vehicles. Use latitude=0, longitude=0 when location is unknown. Also useful as an auth probe.",
    inputSchema: {
      type: "object",
      properties: {
        latitude: { type: "number", description: "Latitude (use 0 if unknown)" },
        longitude: { type: "number", description: "Longitude (use 0 if unknown)" },
      },
      required: ["latitude", "longitude"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_pudo_search",
    description:
      "Autocomplete address search for pickup or dropoff. Returns candidate locations with IDs and provider metadata needed for uber_pudo_resolve.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search text (e.g. 'Av. Paulista')" },
        latitude: { type: "number", description: "User latitude hint" },
        longitude: { type: "number", description: "User longitude hint" },
        type: {
          type: "string",
          enum: ["PICKUP", "DROPOFF"],
          description: "Whether this is a pickup or dropoff search",
        },
        isUserTriggeredFallback: { type: "boolean" },
      },
      required: ["query", "latitude", "longitude", "type"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_pudo_resolve",
    description:
      "Resolve a place ID to full coordinates and address. Call after uber_pudo_search to get the lat/lng needed for uber_products_list.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Place ID from pudo_search" },
        provider: { type: "string", description: "Provider from pudo_search (e.g. 'uber_places', 'google_places')" },
        source: { type: "string", description: "Source from pudo_search (e.g. 'SEARCH')" },
        latitude: { type: "number" },
        longitude: { type: "number" },
        includeAirportTerminals: { type: "boolean" },
        includeRAPUStatus: { type: "boolean" },
        includeTimezone: { type: "boolean" },
      },
      required: ["id"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_pudo_refine",
    description:
      "Refine a pickup location within a venue (e.g., specific entrance or terminal). Use after uber_pudo_resolve when a venue has multiple access points.",
    inputSchema: {
      type: "object",
      properties: {
        pickup: {
          type: "object",
          description: "Pickup coordinate {latitude, longitude}",
          properties: { latitude: { type: "number" }, longitude: { type: "number" } },
          required: ["latitude", "longitude"],
        },
        vvid: { type: "number", description: "Vehicle view ID (integer, from products_list fare)" },
        id: { type: "string", description: "Place ID to refine" },
        provider: { type: "string" },
        source: { type: "string" },
        pickupTime: { type: "number", description: "Unix ms, for scheduled rides" },
      },
      required: ["pickup", "vvid"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_offers_ranked",
    description:
      "Get ranked promotional offers available in a city (discounts, Uber Cash bonuses, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        cityId: { type: "number", description: "City ID (e.g. 458 for São Paulo)" },
        countryIso2: { type: "string", description: "Two-letter country code (e.g. 'BR')" },
        currencyCode: { type: "string", description: "Currency code (e.g. 'BRL')" },
        timezone: { type: "string", description: "IANA timezone (e.g. 'America/Sao_Paulo')" },
      },
      required: ["cityId", "countryIso2", "currencyCode", "timezone"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_products_list",
    description:
      "List available ride products (UberX, Comfort, etc.) with real-time prices and ETAs for a given pickup→dropoff route. Returns fares with 'meta' field needed for uber_trip_request.",
    inputSchema: {
      type: "object",
      properties: {
        pickup: {
          type: "object",
          description: "Pickup coordinate {latitude, longitude}",
          properties: { latitude: { type: "number" }, longitude: { type: "number" } },
          required: ["latitude", "longitude"],
        },
        destinations: {
          type: "array",
          description: "Array of destination coordinates [{latitude, longitude}]",
          items: {
            type: "object",
            properties: { latitude: { type: "number" }, longitude: { type: "number" } },
            required: ["latitude", "longitude"],
          },
        },
        payment: {
          type: "object",
          description: "Payment profile {paymentProfileUUID, profileType, profileUUID}",
        },
        paymentProfileUUID: { type: "string" },
        profileType: { type: "string", description: "e.g. 'Personal'" },
        profileUUID: { type: "string" },
        includeRecommended: { type: "boolean" },
        capacity: { type: "number" },
        targetProductType: { type: "string" },
      },
      required: ["pickup", "destinations"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_pre_plus_ones_get",
    description:
      "Get venue data and first-time UX info for a pickup location. Useful for airports or large venues with multiple pickup zones.",
    inputSchema: {
      type: "object",
      properties: {
        pickup: {
          type: "object",
          properties: { latitude: { type: "number" }, longitude: { type: "number" } },
          required: ["latitude", "longitude"],
        },
        vvid: { type: "number", description: "Vehicle view ID from products_list" },
        skipVenue: { type: "boolean", default: false },
        pickupTime: { type: "number" },
      },
      required: ["pickup", "vvid", "skipVenue"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_reservation_data_get",
    description:
      "Get scheduling data for a location (booking time ranges, Uber Reserve availability). Use before requesting a scheduled ride.",
    inputSchema: {
      type: "object",
      properties: {
        coordinate: {
          type: "object",
          properties: { latitude: { type: "number" }, longitude: { type: "number" } },
          required: ["latitude", "longitude"],
        },
      },
      required: ["coordinate"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_trip_request",
    description:
      "Request an Uber ride. Requires 'meta' (JSON string from products_list fare.meta) and 'payment.checkoutActionResult' (JSON string built from pre_checkout_actions_get response). WARNING: this charges the user's payment method.",
    inputSchema: {
      type: "object",
      properties: {
        origin: {
          type: "object",
          description: "Origin with location {addressLine1, addressLine2, coordinate, id, provider, source} and optional rendezvous",
        },
        destinations: {
          type: "array",
          description: "Array of destination objects {addressLine1, addressLine2, coordinate, id, provider, source}",
        },
        meta: {
          type: "string",
          description: "JSON string from products_list fare.meta — contains fareUUIDs and pricing data",
        },
        payment: {
          type: "object",
          description: "Payment info {paymentProfileUUID, profileType, profileUUID, useCredits, checkoutActionResult}",
        },
        vehicleView: {
          type: "object",
          description: "Vehicle view {description, id (int), is3p}. id is vehicleViewID from fare.meta JSON.",
        },
        type: { type: "string", default: "ON_DEMAND", description: "Trip type: ON_DEMAND or RESERVE" },
        capacity: { type: "number" },
        locationSource: { type: "string", default: "SEARCH" },
        attribution: { type: "object" },
        tippingSpec: { type: "object" },
        pickupTimeMsec: { type: "number", description: "For scheduled rides" },
        waypointSpecs: { type: "array" },
        guest: { type: "object" },
      },
      required: ["origin", "destinations", "meta", "payment", "vehicleView", "type"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_cancellation_info_get",
    description:
      "Get cancellation fee information for an active trip before calling uber_trip_cancel.",
    inputSchema: {
      type: "object",
      properties: {
        tripUUID: { type: "string" },
        reservationUUID: { type: "string", default: "" },
        pickup: { type: "object", description: "Optional pickup location" },
      },
      required: ["tripUUID", "reservationUUID"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_trip_cancel",
    description:
      "Cancel an active trip. Check uber_cancellation_info_get first to see if a fee applies.",
    inputSchema: {
      type: "object",
      properties: {
        current: { type: "boolean", description: "true to cancel the current trip" },
        uuid: { type: "string", description: "Trip UUID (optional if current=true)" },
      },
      required: ["current"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_thread_get",
    description:
      "Get a chat thread with the driver by thread UUID and requester info.",
    inputSchema: {
      type: "object",
      properties: {
        request: {
          type: "object",
          description: "GetThreadRequest with requester {participantMappedId, participantServiceType} and threadUUID",
        },
      },
      required: ["request"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_thread_by_tracking_get",
    description:
      "Get a chat thread UUID by trip tracking info (tripUUID). Use this before uber_thread_get when you only have the tripUUID.",
    inputSchema: {
      type: "object",
      properties: {
        request: {
          type: "object",
          description: "Request with threadType and trackingInfo {tripUUID}",
        },
      },
      required: ["request"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },

  // ── riders.uber.com GraphQL ─────────────────────────────────────────────
  {
    name: "uber_user_riders_get",
    description:
      "Get the current user's full profile: name, email, payment profiles, Uber Cash balances, membership (Uber One), and ride profiles. Essential for getting profileUUID and paymentProfileUUID needed in uber_products_list.",
    inputSchema: {
      type: "object",
      properties: {
        includeDelegateProfiles: { type: "boolean" },
        includeUserMemberships: { type: "boolean" },
        useUberCashBalanceBreakdown: { type: "boolean" },
      },
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_activities_list",
    description:
      "List past and/or upcoming ride activities. Returns trip summaries with UUIDs for use with uber_trip_get and uber_receipt_get.",
    inputSchema: {
      type: "object",
      properties: {
        includePast: { type: "boolean", default: true },
        includeUpcoming: { type: "boolean", default: true },
        limit: { type: "number", default: 5, description: "Max results (default 5)" },
        orderTypes: {
          type: "array",
          items: { type: "string", enum: ["RIDES", "TRAVEL"] },
          default: ["RIDES", "TRAVEL"],
        },
        profileType: { type: "string", enum: ["PERSONAL", "BUSINESS"], default: "PERSONAL" },
        cityID: { type: "number" },
        nextPageToken: { type: "string" },
        startTimeMs: { type: "number" },
        endTimeMs: { type: "number" },
      },
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_trip_get",
    description:
      "Get full details of a specific trip: fare breakdown, driver info, waypoints, receipt summary. Requires a trip UUID from uber_activities_list.",
    inputSchema: {
      type: "object",
      properties: { tripUUID: { type: "string", description: "Trip UUID" } },
      required: ["tripUUID"],
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_receipt_get",
    description:
      "Get the detailed receipt for a completed trip including fare breakdown, distance, duration, and any promotions applied.",
    inputSchema: {
      type: "object",
      properties: {
        tripUUID: { type: "string" },
        timestamp: { type: "string", description: "Optional receipt timestamp for split receipts" },
      },
      required: ["tripUUID"],
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_receipt_send_email",
    description: "Send a receipt email for a completed trip to the user's registered email address.",
    inputSchema: {
      type: "object",
      properties: { tripUUID: { type: "string" } },
      required: ["tripUUID"],
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_invoice_status_get",
    description:
      "Check the invoice/NF-e status for a trip (relevant in Brazil and other markets that require fiscal receipts).",
    inputSchema: {
      type: "object",
      properties: {
        tripUUID: { type: "string" },
        tripDate: { type: "number", description: "Trip date as Unix timestamp ms" },
        tripCountryId: { type: "number" },
        tripMarketplace: { type: "string" },
        tripVehicleViewId: { type: "number" },
      },
      required: ["tripUUID"],
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_arrears_get",
    description:
      "Check if the user has outstanding payment arrears (unpaid balance from a previous trip).",
    inputSchema: {
      type: "object",
      properties: { enableNewArrearFlow: { type: "boolean", default: true } },
      required: ["enableNewArrearFlow"],
    },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_navlinks_get",
    description:
      "Get navigation links for the Uber web interface (profile, login, main menu). Useful for discovering deep-link URLs.",
    inputSchema: { type: "object", properties: {} },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },
  {
    name: "uber_tax_forms_check",
    description: "Check whether tax forms (e.g. 1099) are available for the current user.",
    inputSchema: { type: "object", properties: {} },
    method: "post",
    pathTemplate: "/graphql",
    baseUrl: "riders",
    bodyUnwrap: "_graphql",
    requiresAuth: true,
  },

  // ── www.uber.com REST ───────────────────────────────────────────────────
  {
    name: "uber_user_current",
    description:
      "Get basic profile info for the current user from the www.uber.com REST API (name, email, UUID, tenant).",
    inputSchema: { type: "object", properties: {} },
    method: "post",
    pathTemplate: "/api/getCurrentUser",
    baseUrl: "www",
    bodyParams: [],
    requiresAuth: true,
  },
  {
    name: "uber_activities_upcoming",
    description: "Get upcoming scheduled rides and activities from the www.uber.com REST API.",
    inputSchema: {
      type: "object",
      properties: { cityId: { type: "number", description: "City ID (e.g. 458 for São Paulo)" } },
    },
    method: "post",
    pathTemplate: "/api/getUpcomingActivities",
    baseUrl: "www",
    bodyParams: ["cityId"],
    requiresAuth: true,
  },
  {
    name: "uber_activities_past",
    description: "Get past trip history from the www.uber.com REST API.",
    inputSchema: {
      type: "object",
      properties: {
        cityId: { type: "number" },
        showOnlyTrip: { type: "boolean", default: false },
      },
    },
    method: "post",
    pathTemplate: "/api/getPastActivities",
    baseUrl: "www",
    bodyParams: ["cityId", "showOnlyTrip"],
    requiresAuth: true,
  },
  {
    name: "uber_user_travel_status",
    description:
      "Get the user's current travel status (whether they are currently on a trip, etc.) from the www.uber.com REST API.",
    inputSchema: {
      type: "object",
      properties: {
        location: {
          type: "object",
          description: "Current location {latitude, longitude}",
          properties: { latitude: { type: "number" }, longitude: { type: "number" } },
          required: ["latitude", "longitude"],
        },
      },
      required: ["location"],
    },
    method: "post",
    pathTemplate: "/api/getUserTravelStatus",
    baseUrl: "www",
    bodyParams: ["location"],
    requiresAuth: true,
  },
  {
    name: "uber_membership_attributes",
    description:
      "Get Uber One / membership attributes for the current user (member state, benefits eligibility).",
    inputSchema: {
      type: "object",
      properties: {
        queryFields: {
          type: "array",
          items: { type: "string" },
          default: ["FIELD_MEMBERSHIP"],
        },
        responseAttributes: {
          type: "array",
          items: { type: "string" },
          default: ["membership_member_state"],
        },
      },
    },
    method: "post",
    pathTemplate: "/api/getMembershipAttributes",
    baseUrl: "www",
    bodyParams: ["queryFields", "responseAttributes"],
    requiresAuth: true,
  },
  {
    name: "uber_promo_pill_get",
    description:
      "Get the current promotional pill/banner shown on the Uber home screen (e.g., active promo codes, referral offers).",
    inputSchema: { type: "object", properties: {} },
    method: "post",
    pathTemplate: "/api/getPromoPill",
    baseUrl: "www",
    bodyParams: [],
    requiresAuth: true,
  },
  {
    name: "uber_product_suggestions_list",
    description:
      "Get suggested product types for the user (e.g., UberX recommendation based on history).",
    inputSchema: {
      type: "object",
      properties: { type: { type: "string", default: "DEFAULT", description: "Suggestion type (DEFAULT)" } },
    },
    method: "post",
    pathTemplate: "/api/getProductSuggestions",
    baseUrl: "www",
    bodyParams: ["type"],
    requiresAuth: true,
  },
  {
    name: "uber_map_hero_products",
    description:
      "Get the hero products shown on the Uber map home screen (featured ride options with visual assets).",
    inputSchema: { type: "object", properties: {} },
    method: "post",
    pathTemplate: "/api/getMapHeroEnabledProducts",
    baseUrl: "www",
    bodyParams: [],
    requiresAuth: true,
  },

  // ── m.uber.com REST ─────────────────────────────────────────────────────
  {
    name: "uber_navigation_route",
    description:
      "Get a navigation route between origin and destinations (turn-by-turn polyline data).",
    inputSchema: {
      type: "object",
      properties: {
        routes: {
          type: "array",
          description: "Array of route objects [{origin: {latitude, longitude}, destinations: [{latitude, longitude}]}]",
          items: {
            type: "object",
            properties: {
              origin: {
                type: "object",
                properties: { latitude: { type: "number" }, longitude: { type: "number" } },
              },
              destinations: {
                type: "array",
                items: {
                  type: "object",
                  properties: { latitude: { type: "number" }, longitude: { type: "number" } },
                },
              },
            },
          },
        },
      },
      required: ["routes"],
    },
    method: "post",
    pathTemplate: "/go/custom-api/navigation/route",
    baseUrl: "main",
    bodyParams: ["routes"],
    requiresAuth: true,
  },

  // ── payments.uber.com REST ───────────────────────────────────────────────
  {
    name: "uber_payment_options_list",
    description:
      "List available payment options from the Uber payments hub (credit cards, Uber Cash, etc.). Returns payment profile UUIDs needed for uber_products_list.",
    inputSchema: {
      type: "object",
      properties: {
        orderContext: {
          type: "object",
          description: "Order context object (can be empty {} for a basic listing)",
          default: {},
        },
      },
    },
    method: "post",
    pathTemplate: "/_api/payment-options",
    baseUrl: "payments",
    bodyParams: ["orderContext"],
    requiresAuth: true,
  },
  {
    name: "uber_pre_checkout_actions_get",
    description:
      "Get pre-checkout actions before requesting a trip. Response is typically {status: 'success', data: {}} (empty data = no actions needed). The checkoutActionResult string used in uber_trip_request is CONSTRUCTED CLIENT-SIDE from request params + response.actionResults — see uber_ride_book_quick for the canonical reconstruction.",
    inputSchema: {
      type: "object",
      properties: {
        checkoutSessionUUID: { type: "string", description: "UUID for this checkout session (client-generated)" },
        useCaseKey: {
          type: "string",
          default: "yhmvvwxovgzqionxwhprhrznpkikhrjvszqvkhlh",
          description: "Uber payments use-case key (hardcoded constant, leave default)",
        },
        estimatedPaymentPlan: {
          type: "object",
          description: "Payment plan {defaultPaymentProfile: {currencyAmount: {amountE5, currencyCode}, paymentProfileUUID}, useCredits}",
        },
        orderContext: { type: "object", default: {} },
        isFirstCheckout: { type: "boolean", default: true },
      },
      required: ["checkoutSessionUUID", "estimatedPaymentPlan"],
    },
    method: "post",
    pathTemplate: "/api/getPreCheckoutActions",
    baseUrl: "payments",
    bodyParams: [
      "checkoutSessionUUID",
      "useCaseKey",
      "estimatedPaymentPlan",
      "orderContext",
      "isFirstCheckout",
    ],
    requiresAuth: true,
  },

  // ── Composite / convenience tools ───────────────────────────────────────
  {
    name: "uber_ride_book_quick",
    description:
      "Convenience tool: resolves pickup and dropoff addresses, lists products, builds the checkout action result, and requests a ride in one call. WARNING: this charges the user's payment method. Requires user confirmation before calling.",
    inputSchema: {
      type: "object",
      properties: {
        pickup_query: { type: "string", description: "Pickup address search text" },
        dropoff_query: { type: "string", description: "Dropoff address search text" },
        latitude: { type: "number", description: "User current latitude hint (used for address search)" },
        longitude: { type: "number", description: "User current longitude hint" },
        product_name: { type: "string", description: "Product name filter (e.g. 'UberX', 'Comfort'). Uses first available if omitted." },
      },
      required: ["pickup_query", "dropoff_query"],
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    requiresAuth: true,
  },
  {
    name: "uber_trip_status_watch",
    description:
      "Poll uber_status_get until the trip clientStatus changes or the timeout elapses. Useful for waiting until the driver arrives or the trip starts.",
    inputSchema: {
      type: "object",
      properties: {
        latitude: { type: "number", default: 0 },
        longitude: { type: "number", default: 0 },
        timeout_seconds: {
          type: "number",
          default: 120,
          description: "How long to wait for a status change (max 300s)",
        },
        poll_interval_seconds: {
          type: "number",
          default: 8,
          description: "Seconds between polls (min 5)",
        },
      },
    },
    method: "post",
    pathTemplate: "/go/graphql",
    baseUrl: "main",
    requiresAuth: true,
  },
];

const toolMap = new Map(toolDefinitions.map((t) => [t.name, t]));

/* ----------------------------- composite handlers ------------------------- */

type CompositeHandler = (
  args: Record<string, unknown>,
  tokenProvider: TokenProvider
) => Promise<CallToolResult>;

function parseToolText(result: CallToolResult): unknown {
  const text = (result.content[0] as { type: string; text: string } | undefined)?.text ?? "";
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function rideBookQuick(
  args: Record<string, unknown>,
  tokenProvider: TokenProvider
): Promise<CallToolResult> {
  const lat = (args.latitude as number) ?? 0;
  const lng = (args.longitude as number) ?? 0;

  const step = async (name: string, stepArgs: Record<string, unknown>) => {
    const def = toolMap.get(name)!;
    const result = await executeTool(def, stepArgs, tokenProvider);
    if (result.isError) {
      throw Object.assign(new Error(`Step ${name} failed: ${parseToolText(result)}`), { result });
    }
    return parseToolText(result);
  };

  try {
    // 1. Get user profile for payment info
    const userData = (await step("uber_user_riders_get", {})) as Record<string, unknown>;
    const currentUser = (userData as { data?: { currentUser?: Record<string, unknown> } }).data
      ?.currentUser as Record<string, unknown> | undefined;
    const profile = (currentUser?.profiles as Array<Record<string, unknown>> | undefined)?.[0];
    const profileUUID = profile?.uuid as string | undefined;
    const paymentProfileUUID = profile?.defaultPaymentProfileUuid as string | undefined;

    // 2. Search pickup
    const pickupSearch = (await step("uber_pudo_search", {
      query: args.pickup_query, latitude: lat, longitude: lng, type: "PICKUP",
    })) as Record<string, unknown>;
    const pickupLocations = (pickupSearch as { data?: { pudoLocationSearch?: Array<Record<string, unknown>> } })
      .data?.pudoLocationSearch;
    if (!pickupLocations?.length)
      return { content: [{ type: "text", text: `No pickup location found for: "${args.pickup_query}"` }], isError: true };
    const pickupCandidate = pickupLocations[0];

    // 3. Resolve pickup
    const pickupResolved = (await step("uber_pudo_resolve", {
      id: pickupCandidate.id, provider: pickupCandidate.provider, source: pickupCandidate.source,
    })) as Record<string, unknown>;
    const pickupLoc = (pickupResolved as { data?: { pudoResolveLocation?: Record<string, unknown> } })
      .data?.pudoResolveLocation as Record<string, unknown> | undefined;
    const pickupCoord = pickupLoc?.coordinate as { latitude: number; longitude: number } | undefined;
    if (!pickupCoord)
      return { content: [{ type: "text", text: "Failed to resolve pickup coordinates." }], isError: true };

    // 4. Search dropoff
    const dropoffSearch = (await step("uber_pudo_search", {
      query: args.dropoff_query, latitude: pickupCoord.latitude, longitude: pickupCoord.longitude, type: "DROPOFF",
    })) as Record<string, unknown>;
    const dropoffLocations = (dropoffSearch as { data?: { pudoLocationSearch?: Array<Record<string, unknown>> } })
      .data?.pudoLocationSearch;
    if (!dropoffLocations?.length)
      return { content: [{ type: "text", text: `No dropoff location found for: "${args.dropoff_query}"` }], isError: true };
    const dropoffCandidate = dropoffLocations[0];

    // 5. Resolve dropoff
    const dropoffResolved = (await step("uber_pudo_resolve", {
      id: dropoffCandidate.id, provider: dropoffCandidate.provider, source: dropoffCandidate.source,
    })) as Record<string, unknown>;
    const dropoffLoc = (dropoffResolved as { data?: { pudoResolveLocation?: Record<string, unknown> } })
      .data?.pudoResolveLocation as Record<string, unknown> | undefined;
    const dropoffCoord = dropoffLoc?.coordinate as { latitude: number; longitude: number } | undefined;
    if (!dropoffCoord)
      return { content: [{ type: "text", text: "Failed to resolve dropoff coordinates." }], isError: true };

    // 6. List products
    const productsData = (await step("uber_products_list", {
      pickup: pickupCoord, destinations: [dropoffCoord],
      payment: { paymentProfileUUID, profileType: "Personal", profileUUID },
      paymentProfileUUID, profileType: "Personal", profileUUID,
    })) as Record<string, unknown>;
    const tiers = (productsData as { data?: { products?: { tiers?: Array<Record<string, unknown>> } } })
      .data?.products?.tiers ?? [];
    const allProducts = (tiers as Array<{ products?: Array<Record<string, unknown>> }>)
      .flatMap((t) => t.products ?? []);
    let selected = args.product_name
      ? allProducts.find((p) =>
          (p.displayName as string)?.toLowerCase().includes((args.product_name as string).toLowerCase())
        )
      : allProducts.find((p) => p.isAvailable);
    if (!selected) selected = allProducts[0];
    if (!selected)
      return { content: [{ type: "text", text: "No available products found for this route." }], isError: true };

    const fares = selected.fares as Array<Record<string, unknown>> | undefined;
    const fare = fares?.[0];
    if (!fare)
      return { content: [{ type: "text", text: "Selected product has no fare data." }], isError: true };

    let vehicleViewId = 0;
    try {
      const metaObj = JSON.parse(fare.meta as string);
      vehicleViewId = metaObj.vehicleViewID ?? metaObj.upfrontFare?.vehicleViewId ?? 0;
    } catch {
      /* use 0 */
    }

    // 7. Build estimatedPaymentPlan from fare data
    const fareAmountE5 = (fare.fareAmountE5 as number) ?? 0;
    const currencyCode = (selected.currencyCode as string) ?? "BRL";
    const paymentProfilesList = (currentUser?.paymentProfiles as Array<Record<string, unknown>> | undefined) ?? [];
    const selectedPaymentProfile = paymentProfilesList.find(
      (pp) => (pp.uuid as string) === paymentProfileUUID
    ) ?? paymentProfilesList[0];
    const profileTokenType = (selectedPaymentProfile?.tokenType as string) ?? "braintree";
    const paymentMethodDisplayName =
      ((selectedPaymentProfile?.displayable as Record<string, unknown> | undefined)?.displayName as string) ?? "";

    // 8. Call getPreCheckoutActions to get (or confirm empty) pre-checkout actions.
    //    The checkoutActionResult is CLIENT-CONSTRUCTED from the request + response.
    //    getPreCheckoutActions returning {"status":"success","data":{}} = no actions needed.
    const checkoutSessionUUID = randomUUID();
    const estimatedPaymentPlan = {
      defaultPaymentProfile: {
        currencyAmount: { amountE5: fareAmountE5, currencyCode },
        paymentProfileUUID,
      },
      useCredits: true,
    };
    const preCheckoutResult = await executeTool(
      toolMap.get("uber_pre_checkout_actions_get")!,
      {
        checkoutSessionUUID,
        useCaseKey: PAYMENTS_HUB_USE_CASE,
        estimatedPaymentPlan,
        orderContext: {},
        isFirstCheckout: true,
      },
      tokenProvider
    );
    const preCheckoutData = parseToolText(preCheckoutResult) as Record<string, unknown> | null;
    const actionResults =
      (preCheckoutData as { data?: { actionResults?: unknown[] } } | null)?.data?.actionResults ?? [];

    const checkoutActionResult = JSON.stringify({
      checkoutSessionUUID,
      useCaseKey: PAYMENTS_HUB_USE_CASE,
      actionResults,
      estimatedPaymentPlan,
    });

    // 9. Request trip
    const tripResult = await executeTool(
      toolMap.get("uber_trip_request")!,
      {
        attribution: { sourceURL: "https://m.uber.com/home", utmParameters: {} },
        capacity: (fare.capacity as number) ?? 4,
        destinations: [
          {
            addressLine1: dropoffLoc?.addressLine1 ?? "",
            addressLine2: dropoffLoc?.addressLine2 ?? "",
            coordinate: dropoffCoord,
            id: dropoffCandidate.id,
            provider: dropoffCandidate.provider,
            source: dropoffCandidate.source,
          },
        ],
        locationSource: "SEARCH",
        meta: fare.meta ?? "{}",
        origin: {
          location: {
            addressLine1: pickupLoc?.addressLine1 ?? "",
            addressLine2: pickupLoc?.addressLine2 ?? "",
            coordinate: pickupCoord,
            id: pickupCandidate.id,
            provider: pickupCandidate.provider,
            source: pickupCandidate.source,
          },
        },
        payment: {
          paymentProfileUUID,
          profileTokenType,
          profileType: "Personal",
          profileUUID,
          paymentMethodDisplayName,
          useCredits: true,
          checkoutActionResult,
        },
        type: "ON_DEMAND",
        vehicleView: {
          description: selected.displayName,
          id: vehicleViewId,
          is3p: selected.is3p ?? false,
        },
      },
      tokenProvider
    );

    return tripResult;
  } catch (err) {
    if (err && typeof err === "object" && "result" in err) {
      return (err as { result: CallToolResult }).result;
    }
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [{ type: "text", text: msg }], isError: true };
  }
}

async function tripStatusWatch(
  args: Record<string, unknown>,
  tokenProvider: TokenProvider
): Promise<CallToolResult> {
  const lat = (args.latitude as number) ?? 0;
  const lng = (args.longitude as number) ?? 0;
  const timeoutMs = Math.min(((args.timeout_seconds as number) ?? 120) * 1000, 300_000);
  const pollMs = Math.max(((args.poll_interval_seconds as number) ?? 8) * 1000, 5_000);
  const def = toolMap.get("uber_status_get")!;

  const fetchStatus = async () => {
    const r = await executeTool(def, { latitude: lat, longitude: lng }, tokenProvider);
    if (r.isError) return { error: true, result: r };
    const data = parseToolText(r) as Record<string, unknown> | null;
    const status =
      (data as { data?: { status?: { clientStatus?: string } } } | null)?.data?.status
        ?.clientStatus ?? null;
    return { error: false, result: r, status };
  };

  const initial = await fetchStatus();
  if (initial.error) return initial.result!;
  const initialStatus = initial.status;

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollMs));
    const current = await fetchStatus();
    if (current.error) return current.result!;
    if (current.status !== initialStatus) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { changed: true, from: initialStatus, to: current.status, full: parseToolText(current.result!) },
              null,
              2
            ),
          },
        ],
      };
    }
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { changed: false, status: initialStatus, message: "Timeout waiting for status change" },
          null,
          2
        ),
      },
    ],
  };
}

/**
 * Smart wrapper for uber_trip_request: if `payment.checkoutActionResult` is
 * missing or empty, auto-build it by calling getPreCheckoutActions and
 * constructing the action-result JSON client-side. This is required by the
 * Uber rider-pickup backend, which validates the action-result struct.
 *
 * Without this wrapper, callers had to:
 *  1. Generate their own checkoutSessionUUID
 *  2. Compute fareAmountE5 from `meta.upfrontFare.fare`
 *  3. Call uber_pre_checkout_actions_get
 *  4. Build the JSON manually
 * The wrapper does all 4 steps automatically.
 */
async function tripRequestSmart(
  args: Record<string, unknown>,
  tokenProvider: TokenProvider
): Promise<CallToolResult> {
  const def = toolMap.get("uber_trip_request")!;
  const payment = { ...((args.payment as Record<string, unknown>) ?? {}) };
  const existing = payment.checkoutActionResult as string | undefined;
  const hasCheckout = !!existing && existing.trim() !== "{}" && existing.trim().length > 2;

  if (!hasCheckout) {
    const paymentProfileUUID = payment.paymentProfileUUID as string | undefined;
    if (!paymentProfileUUID) {
      return {
        content: [
          {
            type: "text",
            text: "uber_trip_request: payment.paymentProfileUUID is required to auto-build checkoutActionResult.",
          },
        ],
        isError: true,
      };
    }

    // Derive fareAmountE5 + currencyCode from the products meta JSON.
    let fareAmountE5 = 0;
    let currencyCode = "BRL";
    try {
      const metaObj = JSON.parse((args.meta as string) ?? "{}");
      const upfront = metaObj.upfrontFare ?? {};
      currencyCode = upfront.currencyCode ?? "BRL";
      if (typeof upfront.fare === "string") {
        fareAmountE5 = Math.round(parseFloat(upfront.fare) * 100000);
      } else if (typeof upfront.fareAmountE5 === "number") {
        fareAmountE5 = upfront.fareAmountE5;
      }
    } catch {
      /* meta parse failed — proceed with 0; backend may still accept */
    }

    const checkoutSessionUUID = randomUUID();
    const estimatedPaymentPlan = {
      defaultPaymentProfile: {
        currencyAmount: { amountE5: fareAmountE5, currencyCode },
        paymentProfileUUID,
      },
      useCredits: payment.useCredits !== false,
    };

    const preResult = await executeToolDirect(
      toolMap.get("uber_pre_checkout_actions_get")!,
      {
        checkoutSessionUUID,
        useCaseKey: PAYMENTS_HUB_USE_CASE,
        estimatedPaymentPlan,
        orderContext: {},
        isFirstCheckout: true,
      },
      tokenProvider
    );
    if (preResult.isError) return preResult;
    const preData = parseToolText(preResult) as Record<string, unknown> | null;
    const actionResults =
      (preData as { data?: { actionResults?: unknown[] } } | null)?.data?.actionResults ?? [];

    payment.checkoutActionResult = JSON.stringify({
      checkoutSessionUUID,
      useCaseKey: PAYMENTS_HUB_USE_CASE,
      actionResults,
      estimatedPaymentPlan,
    });
    args = { ...args, payment };
  }

  return executeToolDirect(def, args, tokenProvider);
}

const compositeHandlers = new Map<string, CompositeHandler>([
  ["uber_ride_book_quick", rideBookQuick],
  ["uber_trip_status_watch", tripStatusWatch],
  ["uber_trip_request", tripRequestSmart],
]);

/* ------------------------------- dispatcher ------------------------------- */

export async function executeTool(
  def: McpToolDefinition,
  args: Record<string, unknown>,
  tokenProvider: TokenProvider = defaultProvider
): Promise<CallToolResult> {
  const composite = compositeHandlers.get(def.name);
  if (composite) return composite(args, tokenProvider);
  return executeToolDirect(def, args, tokenProvider);
}

/**
 * Entry point for untrusted (client-supplied) arguments: validates them against
 * the tool's schema before dispatching. Internal composite steps call
 * executeTool directly with trusted, server-built arguments.
 */
export async function executeToolValidated(
  def: McpToolDefinition,
  rawArgs: unknown,
  tokenProvider: TokenProvider = defaultProvider
): Promise<CallToolResult> {
  let args: Record<string, unknown>;
  try {
    args = validateToolArgs(def.inputSchema, rawArgs);
  } catch (err) {
    if (err instanceof ValidationError) {
      return {
        content: [{ type: "text", text: `Invalid arguments: ${err.message}` }],
        isError: true,
      };
    }
    throw err;
  }
  return executeTool(def, args, tokenProvider);
}

/**
 * Direct (non-composite) HTTP dispatch. Composite handlers call this to
 * avoid recursing through their own wrapper.
 */
async function executeToolDirect(
  def: McpToolDefinition,
  args: Record<string, unknown>,
  tokenProvider: TokenProvider
): Promise<CallToolResult> {
  const url = `${baseUrlFor(def.baseUrl)}${buildPath(def.pathTemplate, args)}`;
  const query = buildQuery(def, args);
  const body = buildBody(def, args);

  const { token, error, credentials } = await tokenProvider.getValidToken();
  if (def.requiresAuth && (!token || !credentials)) {
    return {
      content: [{ type: "text", text: error ?? "Not authenticated." }],
      isError: true,
    };
  }

  const headers: Record<string, string> = credentials
    ? getDefaultHeaders(credentials, def.baseUrl)
    : { "content-type": "application/json" };

  const config: {
    method: string;
    url: string;
    params?: Record<string, string>;
    data?: unknown;
    headers: Record<string, string>;
    timeout: number;
  } = { method: def.method, url, headers, timeout: 30_000 };

  if (Object.keys(query).length > 0) config.params = query;

  if (["post", "put", "patch"].includes(def.method.toLowerCase())) {
    if (def.bodyUnwrap === "_graphql") {
      const queryStr = HARDCODED_QUERIES[def.name];
      if (!queryStr) {
        return {
          content: [
            { type: "text", text: `Internal error: no GraphQL query mapped for tool ${def.name}` },
          ],
          isError: true,
        };
      }
      const opName = queryStr.match(/(?:query|mutation)\s+(\w+)/)?.[1] ?? def.name;
      config.data = { operationName: opName, variables: args, query: queryStr };
    } else if (def.bodyUnwrap) {
      const raw = args[def.bodyUnwrap];
      if (raw !== undefined) config.data = raw;
    } else if (body) {
      config.data = body;
    } else {
      config.data = {};
    }
  }

  try {
    const res = await axios(config);
    return {
      content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
    };
  } catch (err) {
    const axErr = err as AxiosError<{ message?: string; error?: string }>;
    const status = axErr.response?.status;
    const data = axErr.response?.data;
    const msg =
      (typeof data === "string" ? data : data?.message || data?.error) ||
      axErr.message ||
      "Unknown error";

    if (status === 401 || status === 403) {
      return {
        content: [
          {
            type: "text",
            text: `Authentication failed (${status}). The Uber session expired — re-authenticate via /login/start.`,
          },
        ],
        isError: true,
      };
    }

    console.error(
      `[uber-mcp] FAIL tool=${def.name} ${def.method.toUpperCase()} ${url} status=${status ?? "network"} msg=${redact(msg, 300)}`
    );
    return {
      content: [
        {
          type: "text",
          text: `API Error (${status ?? "network"}): ${redact(msg)}`,
        },
      ],
      isError: true,
    };
  }
}

/* ------------------------------ stdio entry ------------------------------- */

const mcpServer = new McpServer(
  { name: "@aol/uber-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

const server = mcpServer.server;

server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools: Tool[] = toolDefinitions.map((def) => ({
    name: def.name,
    description: def.description,
    inputSchema: { type: "object" as const, ...def.inputSchema },
  }));
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
  const { name, arguments: args } = request.params;
  const def = toolMap.get(name);
  if (!def) {
    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  }
  console.error(`[uber-mcp] tools/call name=${name}`);
  return executeToolValidated(def, args ?? {});
});

export async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

const isEntrypoint = (() => {
  try {
    const entry = process.argv[1];
    if (!entry) return false;
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
})();

if (isEntrypoint) {
  main().catch((err) => {
    console.error(redact(err instanceof Error ? err.message : err));
    process.exit(1);
  });
}
