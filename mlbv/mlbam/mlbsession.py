"""
mlbsession
"""
import datetime
import io
import logging
import os
import random
import re
import string
import base64
import hashlib

import lxml
import lxml.etree
import pytz

import mlbv.mlbam.common.config as config
import mlbv.mlbam.common.util as util
import mlbv.mlbam.common.session as session

LOG = logging.getLogger(__name__)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:66.0) "
    "Gecko/20100101 Firefox/66.0"
)

PLATFORM = "macintosh"
BAM_SDK_VERSION = "3.4"
MLB_API_KEY_URL = "https://www.mlb.com/tv/g490865/"
API_KEY_RE = re.compile(r'"x-api-key","value":"([^"]+)"')
CLIENT_API_KEY_RE = re.compile(r'"clientApiKey":"([^"]+)"')
OKTA_CLIENT_ID_RE = re.compile("""production:{clientId:"([^"]+)",""")
MLB_OKTA_URL = "https://www.mlbstatic.com/mlb.com/vendor/mlb-okta/mlb-okta.js"
AUTHN_URL = "https://ids.mlb.com/api/v1/authn"
OKTA_AUTHORIZE_URL = "https://ids.mlb.com/oauth2/aus1m088yK07noBfh356/v1/authorize"
OKTA_TOKEN_URL = "https://ids.mlb.com/oauth2/aus1m088yK07noBfh356/v1/token"

MEDIA_GATEWAY_GRAPHQL_URL = "https://media-gateway.mlb.com/graphql"
AIRINGS_URL_TEMPLATE = (
    "https://search-api-mlbtv.mlb.com/svc/search/v2/graphql/persisted/query/"
    "core/Airings?variables={{%22partnerProgramIds%22%3A[%22{game_id}%22]}}"
)


def gen_random_string(n):
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(n)
    )

def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(code_verifier):
    challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(challenge).rstrip(b'=').decode('utf-8')

class SGProviderLoginException(BaseException):
    """Flags that a login is required."""

    pass


# Notes on okta OIDC:
# https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1
#
# Discover endpoints:
# https://ids.mlb.com/oauth2/aus1m088yK07noBfh356/.well-known/openid-configuration
#
class MLBSession(session.Session):
    def __init__(self):
        super().__init__(USER_AGENT, PLATFORM)

    def login(self):
        authn_params = {
            "username": config.CONFIG.parser["username"],
            "password": config.CONFIG.parser["password"],
            "options": {
                "multiOptionalFactorEnroll": False,
                "warnBeforePasswordExpired": True,
            },
        }
        LOG.debug("login: %s", authn_params["username"])
        authn_response = self.session.post(AUTHN_URL, json=authn_params).json()
        LOG.debug("login: authn_response: %s", authn_response)
        self.session_token = authn_response["sessionToken"]
        self._state["session_token_time"] = str(datetime.datetime.now(tz=pytz.UTC))
        self.save()

    def get_okta_code(self, code_challenge):
        state_param = gen_random_string(64)
        nonce_param = gen_random_string(64)

        authz_params = {
            "client_id": self._state["okta_client_id"],
            "redirect_uri": "https://www.mlb.com/login",
            "response_type": "code",
            "response_mode": "okta_post_message",
            "state": state_param,
            "nonce": nonce_param,
            "prompt": "none",
            "sessionToken": self.session_token,
            "scope": "openid email",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        authz_response = self.session.get(OKTA_AUTHORIZE_URL, params=authz_params)
        authz_content = authz_response.text

        if config.VERBOSE:
            LOG.debug("get_okta_code response: %s", authz_content)

        for line in authz_content.split("\n"):
            if "data.code" in line:
                return line.split("'")[1].encode("utf-8").decode("unicode_escape")
            if "data.error = 'login_required'" in line:
                raise SGProviderLoginException

        LOG.debug("get_okta_code failed: %s", authz_content)
        raise Exception(f"could not authenticate: {authz_content}")

    def get_okta_token(self, code_verifier, code):
        token_data = {
            "client_id": self._state["okta_client_id"],
            "redirect_uri": "https://www.mlb.com/login",
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": code,
        }

        token_headers = {
            "Accept": "application/json",
            "Content-type": "application/x-www-form-urlencoded",
        }

        token_response = self.session.post(OKTA_TOKEN_URL, headers=token_headers, data=token_data)

        try:
            token_json = token_response.json()
        except Exception as e:
            LOG.error("Failed to parse token response JSON: %s", token_response.text)
            raise

        if config.VERBOSE:
            LOG.debug("get_okta_token response: %s", token_json)

        if "access_token" in token_json:
            return token_json
        else:
            LOG.error("No access_token in token response")
            LOG.debug("No access_token in token response: %s", token_response.text)
            raise Exception(f"could not authenticate: {token_response.text}")

    def _refresh_access_token(self, clear_token=False):
        if clear_token:
            self.session_token = None

        LOG.debug("Fetching MLB API keys")
        content = self.session.get(MLB_API_KEY_URL).text
        parser = lxml.etree.HTMLParser()
        data = lxml.etree.parse(io.StringIO(content), parser)

        for script in data.xpath(".//script"):
            if script.text and "x-api-key" in script.text:
                self._state["api_key"] = API_KEY_RE.search(script.text).groups()[0]
            if script.text and "clientApiKey" in script.text:
                self._state["client_api_key"] = CLIENT_API_KEY_RE.search(script.text).groups()[0]

        LOG.debug("Fetching Okta client ID")
        content = self.session.get(MLB_OKTA_URL).text
        self._state["okta_client_id"] = OKTA_CLIENT_ID_RE.search(content).groups()[0]

        self.login()

        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        try:
            self.okta_access_code = self.get_okta_code(code_challenge)
        except SGProviderLoginException:
            self.login()
            self.okta_access_code = self.get_okta_code(code_challenge)

        token_json = self.get_okta_token(code_verifier, self.okta_access_code)

        self._state["OKTA_ACCESS_TOKEN"] = token_json["access_token"]
        self._state["access_token_expiry"] = str(
            datetime.datetime.now(tz=pytz.UTC)
            + datetime.timedelta(seconds=token_json.get("expires_in", 3600))
        )
        self._state["access_token"] = token_json["access_token"]
        self.save()


    def get_game_content(self, game_pk):
        self._refresh_access_token()

        headers = {

            "Authorization": f"Bearer {self._state['OKTA_ACCESS_TOKEN']}",
            "User-agent": USER_AGENT,
            #            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }

        content_search_op = {
            "operationName": "contentSearch",
            "query": "query contentSearch($query: String!, $limit: Int = 10, $skip: Int = 0) {\n    contentSearch(\n        query: $query\n        limit: $limit\n        skip: $skip\n    ) {\n        total\n        content {\n            audioTracks {\n                language\n                name\n                renditionName\n                trackType\n            }\n            contentId\n            mediaId\n            contentType\n            contentRestrictions\n            contentRestrictionDetails {\n                code\n                details\n            }\n            sportId\n            feedType\n            callSign\n            mediaState {\n                state\n                mediaType\n                contentExperience\n            }\n            fields {\n                name\n                value\n            }\n            milestones {\n                milestoneType\n                relativeTime\n                absoluteTime\n                title\n                keywords {\n                    name\n                    value\n                }\n            }\n        }\n    }\n  }",
            "variables": {
                "limit": 16,
                "query": f"GamePk={game_pk} AND ContentType=\"GAME\" RETURNING HomeTeamId, HomeTeamName, AwayTeamId, AwayTeamName, Date, MediaType, ContentExperience, MediaState, PartnerCallLetters"
            }
        }

        r = self.session.post(MEDIA_GATEWAY_GRAPHQL_URL, json=content_search_op, headers=headers)
        j = r.json()
        # print(j)
        r.raise_for_status()

        return j['data']['contentSearch']['content']

    # Override
    def lookup_stream_url(self, game_pk, media_id, no_evi):
        """game_pk: game_pk
        media_id: mediaPlaybackId
        """
        stream_url = None

        self._refresh_access_token()

        headers = {

            "Authorization": f"Bearer {self._state['OKTA_ACCESS_TOKEN']}",
            "User-agent": USER_AGENT,
#            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }

        device_id, session_id = self._create_session()

        # playback session
        playback_session_op = {
            "operationName": "initPlaybackSession",
            "query": "mutation initPlaybackSession(\n        $adCapabilities: [AdExperienceType]\n        $mediaId: String!\n        $deviceId: String!\n        $sessionId: String!\n        $quality: PlaybackQuality\n    ) {\n        initPlaybackSession(\n            adCapabilities: $adCapabilities\n            mediaId: $mediaId\n            deviceId: $deviceId\n            sessionId: $sessionId\n            quality: $quality\n        ) {\n            playbackSessionId\n            playback {\n                url\n                token\n                expiration\n                cdn\n            }\n            adScenarios {\n                adParamsObj\n                adScenarioType\n                adExperienceType\n            }\n            adExperience {\n                adExperienceTypes\n                adEngineIdentifiers {\n                    name\n                    value\n                }\n                adsEnabled\n            }\n            heartbeatInfo {\n                url\n                interval\n            }\n            trackingObj\n        }\n    }",
            "variables": {
                "adCapabilities": ["GOOGLE_STANDALONE_AD_PODS"],
                "deviceId": device_id,
                "mediaId": media_id,
                "quality": "PLACEHOLDER",
                "sessionId": session_id
            }
        }

        response = self.session.post(MEDIA_GATEWAY_GRAPHQL_URL, json=playback_session_op, headers=headers)

        if response is not None and config.SAVE_JSON_FILE:
            output_filename = "stream"
            json_file = os.path.join(
                util.get_tempdir(), "{}.json".format(output_filename)
            )
            with open(json_file, "w") as out:  # write date to json_file
                out.write(response.text)

        stream = response.json()
        LOG.debug("lookup_stream_url, stream response: %s", stream)
        if "errors" in stream and stream["errors"]:
            LOG.error("Could not load stream\n%s", stream)
            return None
        stream_url = stream['data']['initPlaybackSession']['playback']['url']
        if no_evi:
            stream_url = re.sub("(/|-)(evi|EVI)", "", stream_url)
        return stream_url

    def _create_session(self):
        headers = {

            "Authorization": f"Bearer {self._state['OKTA_ACCESS_TOKEN']}",
            "User-agent": USER_AGENT,
            #            "Accept": "application/vnd.media-service+json; version=1",
            "x-bamsdk-version": BAM_SDK_VERSION,
            "x-bamsdk-platform": PLATFORM,
            "origin": "https://www.mlb.com",
        }

        # Init session
        init_session_op = {
            "operationName": "initSession",
            "query": "mutation initSession($device: InitSessionInput!, $clientType: ClientType!, $experience: ExperienceTypeInput) {\n    initSession(device: $device, clientType: $clientType, experience: $experience) {\n        deviceId\n        sessionId\n        entitlements {\n            code\n        }\n        location {\n            countryCode\n            regionName\n            zipCode\n            latitude\n            longitude\n        }\n        clientExperience\n        features\n    }\n  }",
            "variables": {
                "device": {},
                "clientType": "WEB"
            }
        }

        r = self.session.post(MEDIA_GATEWAY_GRAPHQL_URL, json=init_session_op, headers=headers)
        j = r.json()
        # print(j)
        r.raise_for_status()

        session = j['data']['initSession']
        return session['deviceId'], session['sessionId']
