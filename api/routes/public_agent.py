"""Public API endpoints for agent triggers.

SantaClues fork: routes use the unified ``Depends(get_user)`` resolver
(see ``api/services/auth/depends.py``) which in turn dispatches on
``AUTH_PROVIDER`` — Stack Auth, OSS email/password, X-API-Key, or
SantaClues JWT. Replacing the upstream bare-`Header(X-API-Key)`
parameter on the trigger endpoints was missing from the original fork
rebase: FastAPI parameter validation runs BEFORE dependencies, so a
JWT-only caller (the only kind the SantaClues backend issues now) got
a hard 422 "X-API-Key field required" before the auth dependency ever
ran. Patched 2026-05-21 — see [reference_dograh_public_agent_jwt_fix.md].

External systems can still trigger calls in non-SantaClues modes by
supplying X-API-Key; get_user honours it via _handle_api_key_auth.
"""

import random
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from pydantic import BaseModel

from api.db import db_client
from api.db.models import UserModel
from api.enums import TriggerState
from api.services.auth.depends import get_user
from api.services.quota_service import check_dograh_quota_by_user_id
from api.services.telephony.factory import (
    get_default_telephony_provider,
    get_telephony_provider_by_id,
)
from api.utils.common import get_backend_endpoints

router = APIRouter(prefix="/public/agent")


class TriggerCallRequest(BaseModel):
    """Request model for triggering a call via API"""

    phone_number: str
    initial_context: Optional[dict] = None
    telephony_configuration_id: int | None = None


class TriggerCallResponse(BaseModel):
    """Response model for successful call initiation"""

    status: str
    workflow_run_id: int
    workflow_run_name: str


def trigger_exists_in_workflow(workflow_definition: dict, trigger_path: str) -> bool:
    """Check if trigger node exists in workflow definition.

    Args:
        workflow_definition: The workflow definition JSON
        trigger_path: The trigger UUID to look for

    Returns:
        True if trigger node exists, False otherwise
    """
    nodes = workflow_definition.get("nodes", [])
    for node in nodes:
        if node.get("type") == "trigger":
            if node.get("data", {}).get("trigger_path") == trigger_path:
                return True
    return False


async def _initiate_call(
    uuid: str,
    request: TriggerCallRequest,
    user: UserModel,
    *,
    use_draft: bool,
) -> TriggerCallResponse:
    """Shared core for production and test trigger endpoints.

    When ``use_draft`` is True the latest draft definition is executed;
    otherwise the published (released) definition is used.
    """
    # 1. Resolve caller's organization. get_user always sets
    #    selected_organization_id (either from JWT.sub in santaclues
    #    mode, the API key's owning org in x-api-key mode, or the user's
    #    Stack-selected team). A missing value is a server bug not a
    #    client error — surface as 500 rather than masking with 401.
    organization_id = user.selected_organization_id
    if organization_id is None:
        logger.error(
            f"public/agent trigger: get_user returned UserModel without "
            f"selected_organization_id (user_id={user.id})"
        )
        raise HTTPException(status_code=500, detail="user has no organization")

    # 2. Lookup agent trigger by UUID
    trigger = await db_client.get_agent_trigger_by_path(uuid)
    if not trigger:
        raise HTTPException(status_code=404, detail="Agent trigger not found")

    # 3. Validate organization match — caller's org MUST own the trigger.
    if organization_id != trigger.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # 4. Validate trigger is active
    if trigger.state != TriggerState.ACTIVE.value:
        raise HTTPException(status_code=404, detail="Agent trigger is not active")

    # 4.5 Check Dograh quota before initiating the call (apply the trigger's
    # workflow's model_overrides so we evaluate the keys this run will use).
    quota_result = await check_dograh_quota_by_user_id(
        user.id, workflow_id=trigger.workflow_id
    )
    if not quota_result.has_quota:
        raise HTTPException(status_code=402, detail=quota_result.error_message)

    # 5. Get workflow and resolve the definition (published vs draft)
    workflow = await db_client.get_workflow_by_id(trigger.workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if use_draft:
        draft = await db_client.get_draft_version(trigger.workflow_id)
        # Fall back to the published definition when no draft exists, so the
        # test URL always runs *something* — typically the same agent the
        # production URL would run.
        workflow_definition = (
            draft.workflow_json if draft else workflow.released_definition.workflow_json
        )
    else:
        workflow_definition = workflow.released_definition.workflow_json

    # Validate trigger node still exists in the resolved definition
    if not trigger_exists_in_workflow(workflow_definition, uuid):
        raise HTTPException(
            status_code=404,
            detail="Trigger not found in the published Agent",
        )

    # 6. Get telephony provider — either the caller-specified config (validated
    # against the trigger's org) or the org's default config.
    if request.telephony_configuration_id is not None:
        cfg = await db_client.get_telephony_configuration_for_org(
            request.telephony_configuration_id, trigger.organization_id
        )
        if not cfg:
            raise HTTPException(
                status_code=404, detail="Telephony configuration not found"
            )
        try:
            provider = await get_telephony_provider_by_id(
                cfg.id, trigger.organization_id
            )
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Telephony provider not configured for this configuration",
            )
        resolved_cfg_id = cfg.id
    else:
        try:
            provider = await get_default_telephony_provider(trigger.organization_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Telephony provider not configured for this organization",
            )
        default_cfg = await db_client.get_default_telephony_configuration(
            trigger.organization_id
        )
        resolved_cfg_id = default_cfg.id if default_cfg else None

    # Validate provider is configured
    if not provider.validate_config():
        raise HTTPException(
            status_code=400,
            detail="Telephony provider not configured for this organization",
        )

    # 7. Determine the workflow run mode based on provider type
    workflow_run_mode = provider.PROVIDER_NAME

    # 8. Create workflow run
    mode_label = "TEST" if use_draft else "API"
    workflow_run_name = f"WR-{mode_label}-{random.randint(1000, 9999)}"
    workflow_run = await db_client.create_workflow_run(
        name=workflow_run_name,
        workflow_id=trigger.workflow_id,
        mode=workflow_run_mode,
        initial_context={
            "provider": provider.PROVIDER_NAME,
            "phone_number": request.phone_number,
            "agent_uuid": uuid,
            "trigger_mode": "test" if use_draft else "production",
            "telephony_configuration_id": resolved_cfg_id,
            **(request.initial_context or {}),
        },
        user_id=user.id,
        use_draft=use_draft,
    )

    logger.info(
        f"Created workflow run {workflow_run.id} for API trigger {uuid} "
        f"(mode={'test' if use_draft else 'production'}) "
        f"to phone number {request.phone_number}"
    )

    # 9. Construct webhook URL for telephony provider callback
    backend_endpoint, _ = await get_backend_endpoints()
    webhook_endpoint = provider.WEBHOOK_ENDPOINT

    webhook_url = (
        f"{backend_endpoint}/api/v1/telephony/{webhook_endpoint}"
        f"?workflow_id={trigger.workflow_id}"
        f"&user_id={user.id}"
        f"&workflow_run_id={workflow_run.id}"
        f"&organization_id={trigger.organization_id}"
    )

    # 10. Initiate call via telephony provider. workflow_id and user_id are
    # required by providers that build the media WebSocket URL at dial time
    # (e.g. Telnyx, Cloudonix); without them the URL contains "None/None" and
    # the stream connection fails.
    try:
        await provider.initiate_call(
            to_number=request.phone_number,
            webhook_url=webhook_url,
            workflow_run_id=workflow_run.id,
            workflow_id=trigger.workflow_id,
            user_id=user.id,
        )
    except Exception as e:
        logger.warning(
            f"Failed to initiate call for workflow run {workflow_run.id}: {e}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Failed to initiate call: {e}",
        )

    logger.info(
        f"Call initiated successfully for workflow run {workflow_run.id} "
        f"via trigger {uuid}"
    )

    return TriggerCallResponse(
        status="initiated",
        workflow_run_id=workflow_run.id,
        workflow_run_name=workflow_run_name,
    )


@router.post("/{uuid}", response_model=TriggerCallResponse)
async def initiate_call(
    uuid: str,
    request: TriggerCallRequest,
    user: UserModel = Depends(get_user),
):
    """Initiate a phone call against the published agent.

    Executes the workflow's currently released definition.
    """
    return await _initiate_call(uuid, request, user, use_draft=False)


@router.post("/test/{uuid}", response_model=TriggerCallResponse)
async def initiate_call_test(
    uuid: str,
    request: TriggerCallRequest,
    user: UserModel = Depends(get_user),
):
    """Initiate a phone call against the latest draft of the agent.

    Useful for verifying changes before publishing. Falls back to the
    published definition when no draft exists.
    """
    return await _initiate_call(uuid, request, user, use_draft=True)
