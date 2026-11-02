def _check_gemini_corpora_documents(r):
    """corpora/{c}/documents — vulnerable if 200 with documents field.
    Requires a known corpus; here we use 'corpora/-' wildcard which Gemini
    supports for listing across all corpora."""
    if r.status_code != 200:
        return False, None
    return ("documents" in (r.text or "") or "{}" == (r.text or "").strip()), None


COST_TABLE_VERSION = "2026-05-20"

PER_CALL_USD = {
    "Veo 2 video generate":     2.00,   # per ~4s clip
    "Imagen 3 generate":        0.04,   # per image
    "Lyria music generate":     0.20,   # per ~30s clip (estimate)
    "Speech longrunningrecognize": 0.024,  # per minute of audio
    "Video Intelligence":       0.10,   # per minute
    "Gemini 2.5 Pro (1k tokens out)": 0.0125,  # ~$12.50 / Mtok output, 1k = 1.25¢
    "Cloud Vision LABEL":       0.0015, # per image
    "Cloud Translation":        0.00002,# per character (negligible)
    "Cloud TTS Neural":         0.000016, # per char (~$16/Mchars)
    # Maps
    "Maps Place Details (Advanced)": 0.020,
    "Maps Directions (Advanced)":    0.010,
    "Maps Streetview":               0.007,
    "Maps Staticmap":                0.002,
}

# Mapping from probe display name → PER_CALL_USD key (when they differ)
COST_PROBE_MAP = {
    "Imagen 3 generate (cost-amp)":             "Imagen 3 generate",
    "Veo 2 video generate (cost-amp)":          "Veo 2 video generate",
    "Lyria music generate (cost-amp)":          "Lyria music generate",
    "Speech longrunningrecognize (cost-amp)":   "Speech longrunningrecognize",
    "Video Intelligence annotate (cost-amp)":   "Video Intelligence",
    "Cloud Vision": "Cloud Vision LABEL",
    "Cloud Translation": "Cloud Translation",
    "Cloud Text-to-Speech": "Cloud TTS Neural",
    "Place Details": "Maps Place Details (Advanced)",
    "Directions": "Maps Directions (Advanced)",
    "Streetview": "Maps Streetview",
    "Staticmap":  "Maps Staticmap",
}

def _check_imagen_reachable(r):
    """Reachability probe — accepts intentionally minimal body. 400 with
    INVALID_ARGUMENT body field = key accepted, model exists, format wrong."""
    text = r.text or ""
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    if r.status_code in (401, 403):
        return False, None
    if r.status_code == 200:
        try:
            data = r.json()
        except (ValueError, TypeError):
            return False, None
        return isinstance(data, dict) and not data.get("error"), None
    if r.status_code == 400:
        try:
            data = r.json()
        except (ValueError, TypeError):
            return False, None
        error = data.get("error") if isinstance(data, dict) else None
        if not isinstance(error, dict):
            return False, None
        text = " ".join(value for value in (error.get("status"), error.get("message"))
                        if isinstance(value, str))
    if r.status_code == 400 and ("INVALID_ARGUMENT" in text or "instances" in text or "contents" in text):
        return True, None
    return False, None


def _check_service_management_producer(r):
    """Require a non-empty producer service list; error responses are not findings."""
    if r.status_code != 200:
        return False, None
    try:
        data = json.loads(r.text or "")
        services = data.get("services") if isinstance(data, dict) else None
        if (isinstance(services, list) and services and not data.get("error")
                and all(isinstance(row, dict) for row in services)):
            return True, None
    except (json.JSONDecodeError, ValueError):
        pass
    return False, None


def _check_gemini_corpora_create(r):
    """Confirm corpus creation and delete the returned corpus; retain cleanup failures."""
    if r.status_code != 200:
        return False, None
    try:
        data = r.json()
    except Exception:
        return False, None
    corpus_name = data.get("name") if isinstance(data, dict) else None
    if not isinstance(corpus_name, str) or not re.fullmatch(r"corpora/[A-Za-z0-9_-]+", corpus_name):
        return False, None
    # Attempt cleanup — use the same key the probe was issued with.
    apikey = (r.request.url.split("key=", 1)[1] if "key=" in r.request.url else "")
    delete_url = "https://generativelanguage.googleapis.com/v1beta/%s?key=%s" % (corpus_name, apikey)
    try:
        dr = requests.delete(delete_url, **_request_kwargs_for_url(delete_url))
        if dr.status_code not in (200, 204):
            _it_record_artifact("Gemini Corpora create", corpus_name, None,
                                "delete returned HTTP %d" % dr.status_code)
            return True, "cleanup_failed_name=%s" % corpus_name
    except requests.RequestException as e:
        _it_record_artifact("Gemini Corpora create", corpus_name, None,
                            "delete request failed: %s" % e)
        return True, "cleanup_failed_name=%s" % corpus_name
    return True, None


def _check_vertex_express(r):
    """Distinguish valid generation responses from rejected or malformed requests."""
    text = (r.text or "")
    if "API keys are not supported" in text:
        return False, None
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    if r.status_code == 200 and "candidates" in text:
        return True, None
    if r.status_code == 400 and ("INVALID_ARGUMENT" in text or "contents" in text):
        return True, None
    return False, None


def _get_abuse_class(probe_name, category):
    """Return the abuse class for a probe. Falls back to category-based default."""
    if probe_name in ABUSE_CLASS_OVERRIDES:
        return ABUSE_CLASS_OVERRIDES[probe_name]
    if category == "maps":
        return "BillDrain"
    if category == "low":
        return "Recon"
    if category == "destructive":
        return "Destructive"
    if category == "cost-amp":
        return "BillDrain"
    if category == "authorization":
        return "CredentialUse"
    # category == "high" — default to Recon (list endpoints)
    return "Recon"


_IMPACT_TYPES = frozenset({
    "data_read", "data_write", "data_delete", "account",
    "quota_cost", "info_disclosure",

    "user_enumeration",
})
_CONFIRMATION_LEVELS = frozenset({
    "confirmed_data",       # vulnerable verdict backed by actual records
    "key_accepted_only",    # the key was accepted but no data was demonstrated
})
_DATA_SENSITIVITIES = frozenset({
    "none",                 # no data exposure (empty body, capability detection)
    "static_catalog",       # same response for any caller (regions, info types)
    "metadata",             # project IDs / leaked names / config metadata
    "customer_data",        # actual customer resources (buckets, topics, files)
    "secret_material",      # secret values / key material (CRITICAL bucket)
    "billing_reachable",    # paid endpoint reachable; sustained calls bill victim
})

_SEVERITIES = ("INFO", "LOW", "MED", "HIGH", "CRITICAL")


_CATEGORY_IMPACT_DEFAULTS = {
    "high": {
        "impact_type": "data_read",
        "confirmation": "confirmed_data",
        "data_sensitivity": "customer_data",
    },
    "maps": {
        "impact_type": "quota_cost",
        "confirmation": "confirmed_data",
        "data_sensitivity": "billing_reachable",
    },
    "low": {
        "impact_type": "quota_cost",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "billing_reachable",
    },
    "destructive": {
        "impact_type": "data_write",
        "confirmation": "key_accepted_only",  # capability detection by default
        "data_sensitivity": "none",
    },
    "cost-amp": {
        "impact_type": "quota_cost",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "billing_reachable",
    },
    "authorization": {
        "impact_type": "account",
        "confirmation": "confirmed_data",
        "data_sensitivity": "metadata",
    },

}

# Per-probe overrides applied AFTER the category default. Use sparingly — only
# for probes whose actual response semantics differ from their category mean.
_PROBE_IMPACT_DEFAULTS = {

    "Firebase Installations create (enum)":        {"impact_type": "info_disclosure",
                                                    "data_sensitivity": "metadata"},

    "Gemini Models List":                          {"impact_type": "info_disclosure",
                                                    "data_sensitivity": "metadata"},
    "Gemini countTokens (quota probe)":            {"impact_type": "info_disclosure",
                                                    "data_sensitivity": "metadata"},
    "Gemini operations list":                      {"impact_type": "info_disclosure",
                                                    "data_sensitivity": "metadata"},


    "Identity Toolkit createAuthUri (email enum)": {
        "impact_type": "user_enumeration",
        "confirmation": "confirmed_data",
        "data_sensitivity": "metadata",
    },

    "Identity Toolkit signUp anon (account creation + auto-cleanup)": {
        "impact_type": "account", "confirmation": "confirmed_data",
        "data_sensitivity": "customer_data"},

    "Cloud Translation": {
        "impact_type": "quota_cost",
        "confirmation": "confirmed_data",
        "data_sensitivity": "billing_reachable",
    },
    "Cloud Vision": {
        "impact_type": "quota_cost",
        "confirmation": "confirmed_data",
        "data_sensitivity": "billing_reachable",
    },
    "Cloud Natural Language": {
        "impact_type": "quota_cost",
        "confirmation": "confirmed_data",
        "data_sensitivity": "billing_reachable",
    },
    "Cloud Text-to-Speech": {
        "impact_type": "quota_cost",
        "confirmation": "confirmed_data",
        "data_sensitivity": "billing_reachable",
    },
    "Gemini Generate Content": {
        "impact_type": "quota_cost",
        "confirmation": "confirmed_data",
        "data_sensitivity": "billing_reachable",
    },
}


def _resolve_response_fields(probe_name, category, check_overrides=None):
    """Resolve (impact_type, confirmation, data_sensitivity) for a probe
    result. Precedence: check-function overrides > _PROBE_IMPACT_DEFAULTS >
    _CATEGORY_IMPACT_DEFAULTS > most conservative fallback."""
    fields = dict(_CATEGORY_IMPACT_DEFAULTS.get(category, {
        "impact_type": "info_disclosure",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "metadata",
    }))
    fields.update(_PROBE_IMPACT_DEFAULTS.get(probe_name, {}))
    if check_overrides:
        for k in ("impact_type", "confirmation", "data_sensitivity"):
            if k in check_overrides:
                fields[k] = check_overrides[k]
    return fields["impact_type"], fields["confirmation"], fields["data_sensitivity"]


def _derive_severity(impact_type, confirmation, data_sensitivity):
    """Return CRITICAL / HIGH / MED / LOW / INFO derived from the three
    response-driven fields. Rules (earlier rules dominate):

      - data_sensitivity=none           → INFO  (no actual exposure)
      - data_sensitivity=static_catalog → INFO  (public catalog, not customer data)
      - data_sensitivity=secret_material + confirmation=confirmed_data → CRITICAL
      - confirmation=key_accepted_only:
          impact_type=quota_cost → LOW  (paid endpoint reachable, no exfil yet)
          else                    → INFO (acceptance ≠ exposure)
      - confirmation=confirmed_data:
          data_sensitivity=customer_data:
              impact_type ∈ {account, data_write, data_delete, data_read} → HIGH
              else → MED
          data_sensitivity=billing_reachable + impact_type=quota_cost → MED
          data_sensitivity=metadata → LOW
          default → MED
      - fallback → INFO

    This is the SOLE source of reported severity. `category` (high/maps/low/
    destructive/cost-amp) stays as a run-group tag only.
    """
    if data_sensitivity == "none":
        return "INFO"
    if data_sensitivity == "static_catalog":
        return "INFO"
    if data_sensitivity == "secret_material" and confirmation == "confirmed_data":
        return "CRITICAL"
    if confirmation == "key_accepted_only":
        if impact_type == "quota_cost":
            return "LOW"
        return "INFO"
    if confirmation == "confirmed_data":

        if impact_type == "user_enumeration":
            return "MED"
        if data_sensitivity == "customer_data":
            if impact_type in ("account", "data_write", "data_delete", "data_read"):
                return "HIGH"
            return "MED"
        if data_sensitivity == "billing_reachable" and impact_type == "quota_cost":
            return "MED"
        if data_sensitivity == "metadata":
            return "LOW"
        return "MED"
    return "INFO"


ALL_PROBES = [
    ("Firebase Installations create (enum)", "high", "POST",
        "https://firebaseinstallations.googleapis.com/v1/projects/-/installations?key={key}",
        '{"fid":"fffffffffffffffffffffff","appId":"1:000000000000:android:0000000000000000","authVersion":"FIS_v2","sdkVersion":"a:0.0.0"}',
        "200+kw:fid",
        "Firebase Installations create — also leaks project info in error messages"),

    ("Gemini Models List", "high", "GET", "https://generativelanguage.googleapis.com/v1beta/models?key={key}", None, "200+kw:models", "Info disclosure — reveals enabled Gemini models"),
    ("Gemini Generate Content", "high", "POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={key}", '{"contents":[{"parts":[{"text":"say hello"}]}],"generationConfig":{"maxOutputTokens":64}}', "200+kw:candidates", "LLM abuse — sustained calls bill the victim project at the per-1k-token rate; scanner-supplied prompt only, no customer data read"),
    ("Gemini Files List", "high", "GET", "https://generativelanguage.googleapis.com/v1beta/files?key={key}", None, _check_non_empty_list, "Data leak — exposes uploaded files"),
    ("Gemini Cached Contents", "high", "GET", "https://generativelanguage.googleapis.com/v1beta/cachedContents?key={key}", None, _check_non_empty_list, "Data leak — exposes cached prompts and context"),
    ("Gemini Tuned Models", "high", "GET", "https://generativelanguage.googleapis.com/v1beta/tunedModels?key={key}", None, "200+ne:error", "Data leak — exposes fine-tuned model configurations"),
    ("Gemini Corpora", "high", "GET", "https://generativelanguage.googleapis.com/v1beta/corpora?key={key}", None, "200+ne:error", "Data leak — exposes RAG corpus and document data"),


    ("Cloud Vision", "low", "POST", "https://vision.googleapis.com/v1/images:annotate?key={key}", '{"requests":[{"image":{"source":{"imageUri":"https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/240px-PNG_transparency_demonstration_1.png"}},"features":[{"type":"LABEL_DETECTION","maxResults":1}]}]}', "200+kw:responses+ne:error", "Image analysis billing — scanner-supplied public PNG, processed at per-image rate; no customer images read"),
    ("Cloud Translation", "low", "GET", "https://translation.googleapis.com/language/translate/v2?q=hello&target=es&key={key}", None, "200+kw:translations", "Translation billing — scanner-supplied placeholder string processed at per-character rate; no customer text read"),
    ("Cloud Natural Language", "low", "POST", "https://language.googleapis.com/v1/documents:analyzeEntities?key={key}", '{"document":{"type":"PLAIN_TEXT","content":"Google Cloud Platform."},"encodingType":"UTF8"}', "200+kw:entities", "Text analysis billing — scanner-supplied placeholder string processed; no customer text read"),
    ("Cloud Text-to-Speech", "low", "POST", "https://texttospeech.googleapis.com/v1/text:synthesize?key={key}", '{"input":{"text":"test"},"voice":{"languageCode":"en-US","ssmlGender":"NEUTRAL"},"audioConfig":{"audioEncoding":"MP3"}}', "200+kw:audioContent", "TTS synthesis billing — scanner-supplied placeholder string synthesized at per-character rate"),

    ("Cloud Storage Buckets", "high", "GET", "https://storage.googleapis.com/storage/v1/b?project={project}&key={key}", None, _check_non_empty_list, "Data leak — list storage buckets"),
    ("Pub/Sub Topics", "high", "GET", "https://pubsub.googleapis.com/v1/projects/{project}/topics?key={key}", None, _check_non_empty_list, "Data leak — Pub/Sub topics"),
    ("Service Management", "high", "GET", "https://servicemanagement.googleapis.com/v1/services?producerProjectId={project}&key={key}", None, _check_service_management_producer, "200 = victim producer services (HIGH data leak) ; 403 = project NUMBER→NAME disclosure (LOW info leak)"),
    # Operation-list probes keep their worst-case HIGH registry tier, but the
    # classifier distinguishes response-bearing rows from name/metadata-only
    # rows. Empty is clean; metadata-only is LOW; response payload is HIGH.
    ("Service Usage", "high", "GET", "https://serviceusage.googleapis.com/v1/operations?key={key}", None, _check_non_empty_operations_list, "Operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),
    ("Integrations", "high", "GET", "https://integrations.googleapis.com/v1/connectorPlatformRegions:enumerate?key={key}", None, _check_non_empty_list, "Data leak — connector regions"),

    ("Speech Operations", "high", "GET", "https://speech.googleapis.com/v1/operations?key={key}", None, _check_non_empty_operations_list, "Speech operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),
    ("Firebase Rules", "high", "GET", "https://firebaserules.googleapis.com/v1/projects/{project}/rulesets?key={key}", None, _check_non_empty_list, "Data leak — Firebase security rules"),

    ("Org Policy", "high", "GET", "https://orgpolicy.googleapis.com/v2/projects/{project}/policies?key={key}", None, _check_non_empty_list, "Data leak — organization policies"),
    ("Service Consumer Management", "high", "GET", "https://serviceconsumermanagement.googleapis.com/v1/operations?key={key}", None, _check_non_empty_operations_list, "Operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),
    ("Video Intelligence", "high", "GET", "https://videointelligence.googleapis.com/v1/projects/{project}/locations/global/operations?pageSize=100&key={key}", None, _check_non_empty_operations_list, "Operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),
    ("Translation Hub Operations", "high", "GET", "https://translationhub.googleapis.com/v1main/projects/{project}/locations/global/operations?pageSize=1000&key={key}", None, _check_non_empty_operations_list, "Operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),
    ("Service Management Operations", "high", "GET", "https://servicemanagement.googleapis.com/v1/operations?filter=serviceName%3Dservicemanagement.googleapis.com&pageSize=100&key={key}", None, _check_non_empty_operations_list, "Operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),

    ("Staticmap", "maps", "GET", "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={key}", None, "image", "$2 per 1000 requests"),
    ("Streetview", "maps", "GET", "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={key}", None, "image", "$7 per 1000 requests"),
    ("Directions", "maps", "GET", "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={key}", None, "ne:error_message", "$5 per 1000 requests"),
    ("Geocode", "maps", "GET", "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={key}", None, "ne:error_message", "$5 per 1000 requests"),
    ("Distance Matrix", "maps", "GET", "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key={key}", None, "ne:error_message", "$5 per 1000 elements"),
    ("Find Place From Text", "maps", "GET", "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={key}", None, "ne:error_message", "$17 per 1000 elements"),
    ("Autocomplete", "maps", "GET", "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={key}", None, "ne:error_message", "$2.83 per 1000 requests"),
    ("Elevation", "maps", "GET", "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={key}", None, "ne:error_message", "$5 per 1000 requests"),
    ("Timezone", "maps", "GET", "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={key}", None, "ne:errorMessage", "$5 per 1000 requests"),
    ("Nearest Roads", "maps", "GET", "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key={key}", None, "ne:error", "$10 per 1000 requests"),
    ("Geolocation", "maps", "POST", "https://www.googleapis.com/geolocation/v1/geolocate?key={key}", '{"considerIp":"true"}', "ne:error", "$5 per 1000 requests"),
    ("Snap to Roads", "maps", "GET", "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key={key}", None, "ne:error", "$10 per 1000 requests"),
    ("Speed Limit-Roads", "maps", "GET", "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={key}", None, "ne:error", "$20 per 1000 requests"),
    ("Place Details", "maps", "GET", "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key={key}", None, "ne:error_message", "$17 per 1000 requests"),
    ("Nearby Search-Places", "maps", "GET", "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key={key}", None, "ne:error_message", "$32 per 1000 requests"),
    ("Text Search-Places", "maps", "GET", "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={key}", None, "ne:error_message", "$32 per 1000 requests"),
    ("Places Photo", "maps", "GET", "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key={key}", None, "302", "$7 per 1000 requests"),
    ("Address Validation", "maps", "POST", "https://addressvalidation.googleapis.com/v1:validateAddress?key={key}", '{"address":{"regionCode":"US","addressLines":["1600 Amphitheatre Pkwy, Mountain View, CA"]}}', "200+ne:error", "$5 per 1000 requests"),
    ("Air Quality", "maps", "POST", "https://airquality.googleapis.com/v1/currentConditions:lookup?key={key}", '{"location":{"latitude":37.419734,"longitude":-122.0827784}}', "200+ne:error", "Paid per request"),
    ("Aerial View", "maps", "GET", "https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111&key={key}", None, "200+ne:error", "Paid per request"),
    ("Routes computeRoutes", "maps", "POST", "https://routes.googleapis.com/directions/v2:computeRoutes?key={key}", '{"origin":{"location":{"latLng":{"latitude":37.419734,"longitude":-122.0827784}}},"destination":{"location":{"latLng":{"latitude":37.4220,"longitude":-122.0841}}},"travelMode":"DRIVE"}', "200+kw:routes+ne:error", "Paid per request"),
    ("Routes computeRouteMatrix", "maps", "POST", "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={key}", '{"origins":[{"waypoint":{"location":{"latLng":{"latitude":37.419734,"longitude":-122.0827784}}}}],"destinations":[{"waypoint":{"location":{"latLng":{"latitude":37.4220,"longitude":-122.0841}}}},{"waypoint":{"location":{"latLng":{"latitude":37.4250,"longitude":-122.0860}}}}],"travelMode":"DRIVE"}', "200+ne:error", "Paid per element"),

    ("Abusive Experience Report", "low", "GET", "https://abusiveexperiencereport.googleapis.com/v1/violatingSites?key={key}", None, "200", "Low — abusive experience report"),
    ("Accelerated Mobile Page URL", "low", "POST", "https://acceleratedmobilepageurl.googleapis.com/v1/ampUrls:batchGet?key={key}", '{"urls":["https://www.google.com/"],"lookupStrategy":"IN_INDEX_DOC"}', "200", "Low — AMP URL API"),
    ("Ad Experience Report", "low", "GET", "https://adexperiencereport.googleapis.com/v1/violatingSites?key={key}", None, "200", "Low — ad experience report"),
    ("Area Insights", "low", "POST", "https://areainsights.googleapis.com/v1:computeInsights?key={key}", '{"insights":["INSIGHT_COUNT"],"filter":{"locationFilter":{"circle":{"latLng":{"latitude":37.419734,"longitude":-122.0827784},"radius":100}},"typeFilter":{"includedTypes":["restaurant"]}}}', "200", "Low — area insights"),
    ("Blogger", "low", "GET", "https://blogger.googleapis.com/v3/blogs/2399953?key={key}", None, "200", "Low — Blogger data access"),
    ("Chrome UX Report", "low", "POST", "https://chromeuxreport.googleapis.com/v1/records:queryRecord?key={key}", '{"url":"https://www.google.com"}', "200", "Low — Chrome UX Report"),
    ("Civic Info", "low", "GET", "https://civicinfo.googleapis.com/civicinfo/v2/elections?key={key}", None, "200", "Low — civic info data"),
    ("Custom Search", "low", "GET", "https://customsearch.googleapis.com/customsearch/v1?q=test&key={key}", None, "200", "Low — custom search ($5 per 1000 queries)"),

    ("Homegraph", "low", "POST", "https://homegraph.googleapis.com/v1/devices:sync?key={key}", '{}', "200", "Low — Homegraph API"),
    ("Books API", "low", "GET", "https://www.googleapis.com/books/v1/volumes?q=test&maxResults=1&key={key}", None, "200+kw:totalItems", "Low — Books API (free quota; mostly public metadata)"),
    ("Knowledge Graph Search", "low", "GET", "https://kgsearch.googleapis.com/v1/entities:search?query=google&key={key}", None, "200", "Low — Knowledge Graph"),
    ("Library Agent", "low", "GET", "https://libraryagent.googleapis.com/v1/shelves?key={key}", None, "200", "Low — Library Agent"),
    ("PageSpeed Insights", "low", "GET", "https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://www.google.com&key={key}", None, "200", "Low — PageSpeed Insights"),
    ("Places (New)", "low", "POST", "https://places.googleapis.com/v1/places:searchText?key={key}", '{"textQuery":"restaurant","maxResultCount":1}', "200", "Low — Places (New) API"),
    ("Pollen", "low", "GET", "https://pollen.googleapis.com/v1/forecast:lookup?location.latitude=37.42&location.longitude=-122.08&days=1&key={key}", None, "200", "Low — Pollen API"),
    ("Safe Browsing", "low", "POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", '{"client":{"clientId":"test","clientVersion":"1.0"},"threatInfo":{"threatTypes":["MALWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"https://www.google.com/"}]}}', "200", "Low — Safe Browsing"),
    ("Solar", "low", "GET", "https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=37.42&location.longitude=-122.08&key={key}", None, "200", "Low — Solar API"),
    ("Travel Impact Model", "low", "POST", "https://travelimpactmodel.googleapis.com/v1/flights:computeFlightEmissions?key={key}", '{"flights":[{"origin":"LAX","destination":"SFO","operatingCarrierCode":"AA","departureDate":{"year":2025,"month":6,"day":15},"flightNumber":100}]}', "200", "Low — Travel Impact Model"),
    ("Verified Access", "low", "POST", "https://verifiedaccess.googleapis.com/v2/challenge:generate?key={key}", '{}', "200", "Low — Verified Access"),
    ("Version History", "low", "GET", "https://versionhistory.googleapis.com/v1/chrome/platforms?key={key}", None, "200", "Low — Version History"),
    ("Web Fonts", "low", "GET", "https://webfonts.googleapis.com/v1/webfonts?key={key}", None, "200", "Low — Web Fonts API"),
    ("Web Risk", "low", "GET", "https://webrisk.googleapis.com/v1/uris:search?uri=https%3A%2F%2Fwww.google.com%2F&threatTypes=MALWARE&key={key}", None, "200", "Low — Web Risk API"),
    ("YouTube Data v3", "low", "GET", "https://www.googleapis.com/youtube/v3/videos?part=snippet&id=dQw4w9WgXcQ&key={key}", None, "200+kw:items", "Low — YouTube Data v3 (free quota; public metadata reads)"),


    ("Identity Toolkit createAuthUri (email enum)", "low", "POST", "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={key}", '{"identifier":"probe-nonexistent@example.com","continueUri":"http://localhost"}', _check_it_create_auth_uri_enum, "Email enumeration — response leaks 'registered'/'allProviders'"),

    ("Gemini File Upload (write)", "destructive", "POST", "https://generativelanguage.googleapis.com/v1beta/files?key={key}", '{}', "not_auth", "Write access — can create files in victim's account"),
    ("Gemini Cached Content Create (write)", "destructive", "POST", "https://generativelanguage.googleapis.com/v1beta/cachedContents?key={key}", '{}', "not_auth", "Write access — can create cached content"),

    ("Identity Toolkit signUp anon (account creation + auto-cleanup)", "high", "POST", "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}", '{"returnSecureToken":true}', _check_it_signup_anon, "Open self-registration — creates an anonymous account (auto-deleted immediately; POTENTIAL chain-candidate on clean success, CONFIRMED + artifact if cleanup fails leaving a real account behind)"),

    ("Gemini File Search Stores", "high", "GET",
        "https://generativelanguage.googleapis.com/v1beta/fileSearchStores?pageSize=100&key={key}",
        None, _check_non_empty_list,
        "RAG data leak — exposes Gemini file search stores"),
    ("Gemini Generated Files", "high", "GET",
        "https://generativelanguage.googleapis.com/v1beta/generatedFiles?pageSize=100&key={key}",
        None, _check_non_empty_list,
        "Generated media/data leak — exposes Gemini generated files"),
    ("Gemini countTokens (quota probe)", "high", "POST",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:countTokens?key={key}",
        '{"contents":[{"parts":[{"text":"probe"}]}]}',
        "200+kw:totalTokens",
        "Quota / model availability probe — confirms Gemini API key works"),
    ("Gemini operations list", "high", "GET",
        "https://generativelanguage.googleapis.com/v1beta/models/-/operations?pageSize=100&key={key}",
        None, _check_non_empty_operations_list,
        "Long-running operations exposure — metadata-only rows are LOW; response-bearing rows keep HIGH data-leak semantics"),

    ("Gemini Corpora create (write)", "destructive", "POST",
        "https://generativelanguage.googleapis.com/v1beta/corpora?key={key}",
        '{"display_name":"gapiscanner-acceptance-probe"}',
        _check_gemini_corpora_create,
        "RAG poisoning primitive — create corpus in victim's account; auto-delete attempted, artifact reported if cleanup fails"),
    ("Gemini File Upload resumable (write)", "destructive", "POST",
        "https://generativelanguage.googleapis.com/upload/v1beta/files?key={key}",
        '{"file":{}}', "not_auth",
        "Arbitrary file storage in victim's Gemini account — free CDN abuse",
        {"content_type": "application/json"}),

    ("Imagen 3 generate (cost-amp)", "cost-amp", "POST",
        "https://generativelanguage.googleapis.com/v1beta/models/imagen-3.0-generate-002:predict?key={key}",
        '{"instances":[{}]}', _check_imagen_reachable,
        "Image generation reachability — ~$0.04/image if exploited"),
    ("Veo 2 video generate (cost-amp)", "cost-amp", "POST",
        "https://generativelanguage.googleapis.com/v1beta/models/veo-2.0-generate-001:predictLongRunning?key={key}",
        '{"instances":[{}]}', _check_imagen_reachable,
        "Video generation reachability — ~$2/clip if exploited"),
    ("Lyria music generate (cost-amp)", "cost-amp", "POST",
        "https://generativelanguage.googleapis.com/v1beta/models/lyria-002:predict?key={key}",
        '{"instances":[{}]}', _check_imagen_reachable,
        "Music generation reachability — ~$0.20/clip if exploited"),
    ("Speech longrunningrecognize (cost-amp)", "cost-amp", "POST",
        "https://speech.googleapis.com/v1/speech:longrunningrecognize?key={key}",
        '{"config":{},"audio":{}}', _check_imagen_reachable,
        "Speech-to-Text long-running — $0.024/min audio"),
    ("Video Intelligence annotate (cost-amp)", "cost-amp", "POST",
        "https://videointelligence.googleapis.com/v1/videos:annotate?key={key}",
        '{"features":["LABEL_DETECTION"]}', _check_imagen_reachable,
        "Video annotation — $0.10/min video"),


    ("Cloud Logging sinks", "high", "GET",
        "https://logging.googleapis.com/v2/projects/{project}/sinks?key={key}",
        None, _check_non_empty_list,
        "Data leak — victim Cloud Logging sinks (export destinations / log routing config)"),
    ("Cloud Logging metrics", "high", "GET",
        "https://logging.googleapis.com/v2/projects/{project}/metrics?key={key}",
        None, _check_non_empty_list,
        "Data leak — victim Cloud Logging log-based metrics (filters reveal log content/structure)"),
    ("Artifact Registry repositories", "high", "GET",
        "https://artifactregistry.googleapis.com/v1/projects/{project}/locations/-/repositories?key={key}",
        None, _check_non_empty_list,
        "Data leak — victim Artifact Registry image/package repository enumeration"),
    ("Dataproc Metastore services", "high", "GET",
        "https://metastore.googleapis.com/v1/projects/{project}/locations/-/services?key={key}",
        None, _check_non_empty_list,
        "Data leak — victim Dataproc (Hive) Metastore service enumeration"),
    ("Document AI Warehouse documents", "high", "GET",
        "https://contentwarehouse.googleapis.com/v1/projects/{project}/locations/-/documents?key={key}",
        None, _check_non_empty_list,
        "Data leak — victim Document AI Warehouse document-store enumeration"),
    ("BigQuery Data Transfer configs", "high", "GET",
        "https://bigquerydatatransfer.googleapis.com/v1/projects/{project}/transferConfigs?key={key}",
        None, _check_non_empty_list,
        "Data leak — victim BigQuery Data Transfer configurations (source datasets / schedules)"),

    ("Cloud TPU locations", "low", "GET",
        "https://tpu.googleapis.com/v2/projects/{project}/locations?key={key}",
        None, _check_non_empty_list,
        "Cloud TPU location enumeration (low-value resource/billing surface)"),
]


_OPT_IN_CATEGORIES = frozenset({"destructive", "cost-amp"})

ABUSE_CLASS_OVERRIDES.update({
    # Phase-0 enumeration
    "Firebase Installations create (enum)": "Recon",

    "Identity Toolkit createAuthUri (email enum)": "Recon",

    "Identity Toolkit signUp anon (account creation + auto-cleanup)": "ATO",

    "Gemini File Search Stores": "DataExfil",
    "Gemini Generated Files": "DataExfil",
    "Gemini countTokens (quota probe)": "Recon",
    "Gemini operations list": "Recon",
    "Gemini Corpora create (write)": "Persistence",
    "Gemini File Upload resumable (write)": "DataExfil",
    "Firebase RTDB root (.json)": "Recon",
    "Firebase RTDB shallow keys": "Recon",
    "Firebase Remote Config fetch": "DataExfil",
    "Firebase Storage list (default bucket)": "DataExfil",
    "Firebase Storage list (.firebasestorage.app)": "DataExfil",

    "Firebase Dynamic Links shortLinks (capability)": "Recon",
    "Firebase RTDB write probe": "Destructive",
    "Firebase App Check exchangeDebugToken": "Persistence",
    "Imagen 3 generate (cost-amp)":             "BillDrain",
    "Veo 2 video generate (cost-amp)":          "BillDrain",
    "Lyria music generate (cost-amp)":          "BillDrain",
    "Speech longrunningrecognize (cost-amp)":   "BillDrain",
    "Video Intelligence annotate (cost-amp)":   "BillDrain",
})


POTENTIAL_PROBES = {

    "Identity Toolkit signUp anon (account creation + auto-cleanup)",

}

POTENTIAL_NOTE_SHORT = (
    "Manual verification needed — see _potential_check_steps() / README. "
    "Common reasons this is NOT exploitable: (a) signUp/OAuth-IdP all disabled "
    "so attacker cannot obtain a valid idToken; (b) Google documents the "
    "endpoint behavior as 'intended-by-design'; (c) target backend does not "
    "trust Firebase tokens for primary auth."
)

# Compute count after definition
HARDCODED_ENDPOINTS_COUNT = len(ALL_PROBES)


def _mask_operator_pii(value):
    """Mask the email local part or phone number before logging."""
    if not value:
        return None
    s = str(value)
    if "@" in s:
        local, _, domain = s.partition("@")
        head = local[0] if local else ""
        return "%s***@%s" % (head, domain)
    # phone / non-email token: keep leading '+' and last 4 chars.
    plus = "+" if s.startswith("+") else ""
    digits = s[1:] if plus else s
    if len(digits) <= 4:
        return plus + ("*" * len(digits))
    return plus + ("*" * (len(digits) - 4)) + digits[-4:]


def _build_operator_oob_probes(it_test_email=None, it_test_phone=None):
    """Build optional email and SMS probes for caller-supplied test recipients.

    Each probe requires its recipient argument and the destructive-probe opt-in."""
    probes = []
    if it_test_email:
        email = json.dumps(it_test_email)  # JSON-escape the operator address
        probes.append((
            "Identity Toolkit sendOobCode PASSWORD_RESET (operator email)",
            "destructive", "POST",
            "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={key}",
            '{"requestType":"PASSWORD_RESET","email":%s}' % email,
            _check_it_oob_email_delivery,
            "Operator-controlled OOB email — PASSWORD_RESET dispatched to the "
            "operator's own mailbox (delivery = destructive capability; "
            "EMAIL_NOT_FOUND = non-finding)"))
        probes.append((
            "Identity Toolkit sendOobCode EMAIL_SIGNIN (operator email)",
            "destructive", "POST",
            "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={key}",
            '{"requestType":"EMAIL_SIGNIN","email":%s,"continueUrl":"http://localhost"}' % email,
            _check_it_oob_email_delivery,
            "Operator-controlled OOB email — EMAIL_SIGNIN link dispatched to "
            "the operator's own mailbox (delivery = destructive capability)"))
    if it_test_phone:
        phone = json.dumps(it_test_phone)
        probes.append((
            "Identity Toolkit sendVerificationCode SMS (operator phone)",
            "destructive", "POST",
            "https://identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode?key={key}",
            '{"phoneNumber":%s,"recaptchaToken":"x"}' % phone,
            _check_it_sms_delivery,
            "Operator-controlled SMS — verification code initiated to the "
            "operator's own phone (recaptcha-gated rejection = non-finding)"))
    return probes


_OPERATOR_OOB_PROBE_NAMES = frozenset({
    "Identity Toolkit sendOobCode PASSWORD_RESET (operator email)",
    "Identity Toolkit sendOobCode EMAIL_SIGNIN (operator email)",
    "Identity Toolkit sendVerificationCode SMS (operator phone)",
})
for _oob_name in _OPERATOR_OOB_PROBE_NAMES:
    _PROBE_IMPACT_DEFAULTS[_oob_name] = {
        "impact_type": "account",
        "confirmation": "confirmed_data",
        "data_sensitivity": "customer_data",
    }
    ABUSE_CLASS_OVERRIDES[_oob_name] = "ATO"

# Routes API probes that need extra headers
_ROUTES_FIELD_MASKS = {
    "Places (New)": "places.id,places.displayName",
    "Routes computeRoutes": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline",
    "Routes computeRouteMatrix": "originIndex,destinationIndex,status,distanceMeters,duration",
}

# Maps extras: when these are vulnerable, also report their advanced/session variants
_MAPS_EXTRAS = {
    "Directions": ("Directions (Advanced)", "$10 per 1000 requests"),
    "Distance Matrix": ("Distance Matrix (Advanced)", "$10 per 1000 elements"),
    "Autocomplete": ("Autocomplete (Per Session)", "$17 per 1000 requests"),
}

# Gemini probes that can be skipped if the API is disabled
_GEMINI_SKIP_PROBES = frozenset({
    "Gemini Generate Content", "Gemini Files List", "Gemini Cached Contents",
    "Gemini Tuned Models", "Gemini Corpora", "Gemini File Search Stores",
    "Gemini Generated Files",
})

PHASE_0_PROBE_NAMES = (
    "Gemini Models List",                          # disabled-API errors reliably include project number

    "Firebase Installations create (enum)",        # works on Firebase web/mobile keys; default `high`

    "Identity Toolkit createAuthUri (email enum)",
)

# Transient HTTP statuses that should trigger one retry in Phase 0
_PHASE_0_RETRY_STATUSES = frozenset({500, 502, 503, 504})

# PROXY CONFIGURATION
