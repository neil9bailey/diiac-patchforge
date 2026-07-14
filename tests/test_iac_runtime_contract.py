from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_BICEP = (REPO_ROOT / "infra" / "bicep" / "main.bicep").read_text(encoding="utf-8")
APPS_BICEP = (REPO_ROOT / "infra" / "bicep" / "container-apps.bicep").read_text(
    encoding="utf-8"
)
PROD_PARAMS = (REPO_ROOT / "infra" / "parameters" / "prod.bicepparam").read_text(
    encoding="utf-8"
)


def test_production_scale_profile_is_explicit_and_cost_preserving():
    assert "param containerAppScaleProfile string = 'cost-optimized'" in MAIN_BICEP
    assert "scaleProfile: containerAppScaleProfile" in MAIN_BICEP
    assert "param containerAppScaleProfile = 'cost-optimized'" in PROD_PARAMS
    assert "var enterpriseScale = scaleProfile == 'enterprise'" in APPS_BICEP
    assert APPS_BICEP.count("minReplicas: enterpriseScale ? 1 : 0") == 4
    assert APPS_BICEP.count("maxReplicas: enterpriseScale ?") == 5
    assert "role: 'scheduler'" in APPS_BICEP
    scheduler = APPS_BICEP.split("role: 'scheduler'", 1)[0].rsplit("{", 1)[-1]
    assert "minReplicas: 1" in scheduler
    assert "maxReplicas: 1" in scheduler


def test_iac_preserves_live_search_and_openai_feature_flags():
    assert "searchMode: searchMode" in MAIN_BICEP
    assert "param searchMode = 'postgres'" in PROD_PARAMS
    assert "name: 'PATCHFORGE_SEARCH_MODE'" in APPS_BICEP
    assert "app.role != 'frontend'" in APPS_BICEP
    assert "name: 'PATCHFORGE_OPENAI_AGENT_ENABLED'" in APPS_BICEP
    assert "app.role == 'bridge-api' ? string(openAiAgentEnabled) : 'false'" in APPS_BICEP


def test_production_parameters_match_the_deployed_image_release_tuple():
    assert "param imageTag = 'pfaz-enterprise-20260714d-f51802d'" in PROD_PARAMS
    assert (
        "param sourceCommitSha = 'f51802d3544260259c252e6be88d6e7bae596868'"
        in PROD_PARAMS
    )
    assert "param productBaseline = 'PF-AZ-ENTERPRISE-AUTOMATION-20260714D'" in PROD_PARAMS
    assert (
        "param reportContextVersion = "
        "'patchforge-report-context.pfaz-enterprise-20260714d.v1'"
        in PROD_PARAMS
    )
