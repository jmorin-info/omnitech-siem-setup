"""Run the real refresh controller in Node: errors and cached data cannot look fresh."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(not NODE, reason="Node is required for the browser controller regression")


def execute(script):
    process = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=10)
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


@pytest.mark.parametrize("mode", ["success", "failed", "cached", "risk_failed", "health_failed", "risk_cached"])
def test_actual_refresh_only_records_a_success_after_fresh_required_requests(mode):
    source = (ROOT / "mobile/soc/app.js").read_text(encoding="utf-8")
    controller = source[source.index("async function loadAll(){"):source.index("\nlet TOPE=")]
    script = '''let RELOADING=false,LAST_REFRESH_FAILED=false,UPD_AT=123,marks=0,events=[],stale=false;
const document={body:{classList:{remove(){},toggle(name,value){stale=value;}}},dispatchEvent(e){events.push(e.detail);}};
function CustomEvent(type,options){this.detail=options.detail;}
function setSpin(){} function tickUpd(){} function markUpdated(){marks++;UPD_AT=999;}
function renderUnavailable(){} function toastNet(){} function toastWarn(){} function setTimeout(){} const window={};
function renderKpis(){} function renderTs(){} function renderTac(){} function renderDet(){}
function renderSrc(){} function renderMatrix(){} function renderCases(){} function loadDetections(){}
function renderLeaks(){} function renderHealth(){} function renderRisk(){} function renderKpiTrend(){}
function renderGeo(){} function renderSentinelPosture(){}
''' + 'const mode=' + json.dumps(mode) + ''';
function j(path){if(mode==='failed'||(mode==='risk_failed'&&path==='/risk')||(mode==='health_failed'&&path==='/health'))return Promise.reject(new Error('HTTP503'));return Promise.resolve(mode==='cached'||(mode==='risk_cached'&&path==='/risk')?{_socCachedAt:100}:{});}
''' + controller + '\nloadAll().then(()=>console.log(JSON.stringify({marks,UPD_AT,LAST_REFRESH_FAILED,stale,event:events[0]})));'
    result = execute(script)
    assert result["marks"] == (1 if mode == "success" else 0)
    assert result["UPD_AT"] == (999 if mode == "success" else 123)
    assert result["stale"] == (mode != "success")
    assert result["LAST_REFRESH_FAILED"] == (mode != "success")
    assert result["event"]["ok"] == (mode == "success")


def test_missing_threat_level_cannot_default_to_nominal():
    source = (ROOT / "mobile/soc/app.js").read_text(encoding="utf-8")
    renderer = source[source.index("function renderUnavailable(){"):source.index("\nfunction openTopE(")]
    script = '''const LANG="fr",elements={};
function $(id){return elements[id]||(elements[id]={textContent:'',className:'',classList:{add(){}}});}
const document={querySelectorAll(){return [];}};
''' + renderer + '\ntry{renderRisk({});}catch(e){}console.log(JSON.stringify(elements));'
    result = execute(script)
    assert result["#tlabel"]["textContent"] == "INDISPONIBLE"
    assert "grn" not in result["#threat"]["className"]


def test_valid_risk_with_empty_optional_lists_renders_without_masking_translator():
    source = (ROOT / "mobile/soc/app.js").read_text(encoding="utf-8")
    renderer = source[source.index("function renderUnavailable(){"):source.index("\nfunction openTopE(")]
    script = '''const LANG="fr",elements={};let TOPE=[],MLT=[];
function $(id){return elements[id]||(elements[id]={textContent:'',className:'',classList:{add(){}}});}
const document={querySelectorAll(){return [];}};
const t=key=>key,esc=value=>value;
''' + renderer + '\nrenderRisk({threat_level:"SURVEILLE"});console.log(JSON.stringify(elements));'
    result = execute(script)
    assert result["#tlabel"]["textContent"] == "SURVEILLE"
    assert result["#mlTop"]["innerHTML"] == '<div class="empty">empty_ml</div>'


@pytest.mark.parametrize("status,passed", [(200, True), (401, False), (500, False), (503, False)])
def test_json_error_body_cannot_be_used_as_dashboard_metrics(status, passed):
    source = (ROOT / "mobile/soc/app.js").read_text(encoding="utf-8")
    helper = source[source.index("const j="):source.index("\nconst esc=")]
    script = 'const API="/m/api"; const fetch=()=>Promise.resolve({status:' + str(status) + ',ok:' + str(passed).lower() + ''',headers:{get(){return null;}},json(){return Promise.resolve({error:'unavailable'});}});
''' + helper + '\nj("/kpis").then(()=>console.log(JSON.stringify({passed:true})),()=>console.log(JSON.stringify({passed:false})));'
    assert execute(script)["passed"] == passed
