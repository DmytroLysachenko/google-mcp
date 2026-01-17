import logging
import time
from typing import Iterable

from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from fastmcp.server.auth.providers.google import GoogleProvider
from mcp.server.auth.routes import cors_middleware
from fastmcp.server.auth.oauth_proxy import ProxyDCRClient
from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.handlers.register import RegistrationErrorResponse
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata

logger = logging.getLogger(__name__)


class StaticClientGoogleProvider(GoogleProvider):
    """GoogleProvider variant that can return a fixed client ID/secret on /register."""

    def __init__(
        self,
        *args,
        static_client_id: str | None = None,
        static_client_secret: str | None = None,
        static_redirect_uris: Iterable[str] | None = None,
        static_auth_method: str | None = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._static_client_id = static_client_id
        self._static_client_secret = static_client_secret
        self._static_redirect_uris = (
            list(static_redirect_uris) if static_redirect_uris else None
        )
        self._static_auth_method = static_auth_method or "client_secret_post"

    def _static_enabled(self) -> bool:
        return bool(self._static_client_id and self._static_client_secret)

    async def _register_static_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            raise ValueError("client_id is required for client registration")
        proxy_client = ProxyDCRClient(
            client_id=client_info.client_id,
            client_secret=client_info.client_secret,
            redirect_uris=client_info.redirect_uris or ["http://localhost"],
            grant_types=client_info.grant_types or ["authorization_code", "refresh_token"],
            scope=client_info.scope or self._default_scope_str,
            token_endpoint_auth_method=client_info.token_endpoint_auth_method
            or self._static_auth_method,
            allowed_redirect_uri_patterns=self._allowed_client_redirect_uris,
            client_name=getattr(client_info, "client_name", None),
        )
        await self._client_store.put(
            key=client_info.client_id,
            value=proxy_client,
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if self._static_enabled() and client_info.client_id == self._static_client_id:
            await self._register_static_client(client_info)
            return
        await super().register_client(client_info)

    async def get_client(self, client_id: str):
        if self._static_enabled() and client_id == self._static_client_id:
            client = await super().get_client(client_id)
            if client is None:
                await self._register_static_client(
                    OAuthClientInformationFull(
                        client_id=self._static_client_id,
                        client_secret=self._static_client_secret,
                        client_id_issued_at=int(time.time()),
                        client_secret_expires_at=None,
                        redirect_uris=self._static_redirect_uris or ["http://localhost"],
                        token_endpoint_auth_method=self._static_auth_method,
                        grant_types=["authorization_code", "refresh_token"],
                        response_types=["code"],
                        scope=self._default_scope_str,
                    )
                )
                client = await super().get_client(client_id)
            return client
        return await super().get_client(client_id)

    async def _handle_static_register(self, request: Request) -> Response:
        if not self._static_enabled():
            return Response(status_code=404)

        try:
            body = await request.json()
            client_metadata = OAuthClientMetadata.model_validate(body)
        except ValidationError as validation_error:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=stringify_pydantic_error(validation_error),
                ),
                status_code=400,
            )

        options = self.client_registration_options
        if client_metadata.token_endpoint_auth_method is None:
            client_metadata.token_endpoint_auth_method = self._static_auth_method

        if client_metadata.scope is None and options and options.default_scopes:
            client_metadata.scope = " ".join(options.default_scopes)
        elif client_metadata.scope is not None and options and options.valid_scopes:
            requested_scopes = set(client_metadata.scope.split())
            valid_scopes = set(options.valid_scopes)
            if not requested_scopes.issubset(valid_scopes):
                return PydanticJSONResponse(
                    content=RegistrationErrorResponse(
                        error="invalid_client_metadata",
                        error_description="Requested scopes are not valid: "
                        f"{', '.join(requested_scopes - valid_scopes)}",
                    ),
                    status_code=400,
                )

        if not {"authorization_code", "refresh_token"}.issubset(
            set(client_metadata.grant_types)
        ):
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=(
                        "grant_types must be authorization_code and refresh_token"
                    ),
                ),
                status_code=400,
            )

        if "code" not in client_metadata.response_types:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=(
                        "response_types must include 'code' for authorization_code grant"
                    ),
                ),
                status_code=400,
            )

        redirect_uris = (
            self._static_redirect_uris
            or client_metadata.redirect_uris
            or ["http://localhost"]
        )
        issued_at = int(time.time())
        client_info = OAuthClientInformationFull(
            client_id=self._static_client_id,
            client_id_issued_at=issued_at,
            client_secret=self._static_client_secret,
            client_secret_expires_at=None,
            redirect_uris=redirect_uris,
            token_endpoint_auth_method=client_metadata.token_endpoint_auth_method,
            grant_types=client_metadata.grant_types,
            response_types=client_metadata.response_types,
            client_name=client_metadata.client_name,
            client_uri=client_metadata.client_uri,
            logo_uri=client_metadata.logo_uri,
            scope=client_metadata.scope,
            contacts=client_metadata.contacts,
            tos_uri=client_metadata.tos_uri,
            policy_uri=client_metadata.policy_uri,
            jwks_uri=client_metadata.jwks_uri,
            jwks=client_metadata.jwks,
            software_id=client_metadata.software_id,
            software_version=client_metadata.software_version,
        )

        await self._register_static_client(client_info)
        return PydanticJSONResponse(content=client_info, status_code=201)

    def get_routes(self, mcp_path: str | None = None):
        routes = super().get_routes(mcp_path)
        if not self._static_enabled():
            return routes

        replaced: list[Route] = []
        for route in routes:
            if isinstance(route, Route) and route.path == "/register":
                replaced.append(
                    Route(
                        "/register",
                        endpoint=cors_middleware(
                            self._handle_static_register, ["POST", "OPTIONS"]
                        ),
                        methods=["POST", "OPTIONS"],
                    )
                )
            else:
                replaced.append(route)
        logger.info("OAuth 2.1: Static client registration enabled")
        return replaced
