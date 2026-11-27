# -*- coding: utf-8 -*-
# =============================================================================
# omni_mail_v3 (v4 SIEM, 26/11/2026) : charte HTML « v3 » des mails DSI appliquée aux mails du SIEM
# (triage immédiat, lot horaire, récapitulatif). Reproduit New-OmsReportHtmlV3 (C:\DC\Scripts\_Commun\
# OMS-ReportCommon.ps1) : en-tête blanc + liseré orange #e36517, logo 40 px (cid:omslogo), bandeau d'état
# coloré, tuiles, tableaux dans un conteneur défilant (mobile), badges doux, pied discret.
# Compatible Outlook / Gmail / mobiles : styles en tête + styles en ligne de repli, attributs width/height
# sur l'image, aucun JavaScript. Bibliothèque standard uniquement.
# Retour : OMNI_MAIL_CHARTE=v2 dans /etc/omni-alert-triage.env -> anciens gabarits (code d'origine conservé).
# =============================================================================
import html as _html, os, re, time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header
from email.utils import formatdate, make_msgid

LOGO_PATH = os.environ.get("OMNI_MAIL_LOGO", "/usr/local/share/omni-siem/logo-mail.png")
LOGO_CID = "omslogo"
OBJET_MAX = 150
ORANGE = "#e36517"
TONS = {
    "CRITIQUE":  {"fort": "#dc2626", "texte": "#b91c1c", "fond": "#fef2f2", "bord": "#fecaca", "libelle": "Critique — à traiter maintenant"},
    "ATTENTION": {"fort": "#d97706", "texte": "#b45309", "fond": "#fffbeb", "bord": "#fde68a", "libelle": "Attention — à vérifier dans la journée"},
    "OK":        {"fort": "#16a34a", "texte": "#15803d", "fond": "#f0fdf4", "bord": "#bbf7d0", "libelle": "Tout est en ordre"},
    "INFO":      {"fort": "#2563eb", "texte": "#1d4ed8", "fond": "#eff6ff", "bord": "#bfdbfe", "libelle": "Pour information"},
}
NEUTRE = {"fort": "#64748b", "texte": "#475569", "fond": "#f8fafc", "bord": "#e2e8f0", "libelle": ""}
_JOURS = ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."]
_MOIS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."]

try:
    from zoneinfo import ZoneInfo
    PARIS = ZoneInfo("Europe/Paris")
except Exception:          # pragma: no cover - repli : heure locale du serveur (déjà Europe/Paris)
    PARIS = None

def esc(s):
    return _html.escape(str(s if s is not None else ""))

def ton(niveau):
    return TONS.get(str(niveau or "").strip().upper(), NEUTRE)

def _dt_local(v=None):
    """datetime aware Europe/Paris depuis : None (maintenant), epoch, ou chaîne UTC Graylog
    ('2026-11-26 13:50:49.123', '2026-11-26T13:50:49.123Z')."""
    try:
        if v is None or v == "":
            d = datetime.now(timezone.utc)
        elif isinstance(v, (int, float)):
            d = datetime.fromtimestamp(float(v), timezone.utc)
        else:
            s = str(v).strip().replace("T", " ").rstrip("Z")[:19]
            d = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return d.astimezone(PARIS) if PARIS else d.astimezone()
    except Exception:
        return None

def quand(v=None, secondes=False):
    """Heure locale Europe/Paris au format jj/MM/aaaa HH:mm (ou chaîne vide)."""
    d = _dt_local(v)
    return d.strftime("%d/%m/%Y %H:%M:%S" if secondes else "%d/%m/%Y %H:%M") if d else ""

def quand_court(v=None):
    d = _dt_local(v)
    return d.strftime("%d/%m %H:%M") if d else ""

def quand_entete(v=None):
    d = _dt_local(v)
    if not d: return ""
    return f"{_JOURS[d.weekday()]} {d.day} {_MOIS[d.month - 1]} {d.year} · {d.strftime('%H:%M')}"

def badge(niveau, texte=None):
    t = ton(niveau)
    return (f"<span style=\"display:inline-block;padding:2px 9px;border-radius:999px;background:{t['fond']};"
            f"color:{t['texte']};border:1px solid {t['bord']};font-size:11px;font-weight:700;letter-spacing:.3px;"
            f"line-height:16px;white-space:nowrap\">{esc(texte if texte is not None else niveau)}</span>")

def puce(texte, fg="#374151", bg="#f3f4f6", bord="#e5e7eb", href=None):
    st = (f"display:inline-block;padding:2px 9px;border-radius:999px;background:{bg};color:{fg};border:1px solid {bord};"
          f"font-size:11px;font-weight:600;line-height:16px;margin:0 6px 6px 0;text-decoration:none;white-space:nowrap")
    return f'<a href="{esc(href)}" style="{st}">{texte}</a>' if href else f'<span style="{st}">{texte}</span>'

def kpis(items):
    """items : [(libellé, valeur, niveau|None)] -> tuiles (4 par ligne au plus, repli Outlook)."""
    items = list(items or [])
    nb = min(max(len(items), 1), 4); larg = int(100 / nb) - 2
    cells = []
    for lab, val, niv in items:
        c = ton(niv)["fort"] if str(niv or "").upper() in TONS else "#111827"
        cells.append(
            f"<!--[if mso]><td valign='top' width='150' style='padding:0 8px 8px 0'><![endif]-->"
            f"<div class='kpi' style='display:inline-block;vertical-align:top;width:{larg}%;box-sizing:border-box;margin:0 2% 8px 0;"
            f"padding:10px 12px;border:1px solid #e5e7eb;border-left:3px solid {c};border-radius:8px;background:#ffffff;text-align:left'>"
            f"<div style='font-size:24px;line-height:28px;font-weight:700;color:{c}'>{esc(val)}</div>"
            f"<div style='font-size:12px;line-height:16px;color:#6b7280;margin-top:2px'>{esc(lab)}</div></div>"
            f"<!--[if mso]></td><![endif]-->")
    return ("<div class='kpis' style='margin:14px 0 6px;font-size:0'><!--[if mso]><table role='presentation' cellpadding='0' "
            "cellspacing='0'><tr><![endif]-->" + "".join(cells) + "<!--[if mso]></tr></table><![endif]--></div>")

_TH = ("background:#f9fafb;color:#6b7280;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;"
       "letter-spacing:.4px;padding:8px 10px;border-bottom:1px solid #e5e7eb;white-space:nowrap")
_TD = "padding:8px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top;color:#374151;font-size:13px"

def table(entetes, lignes, vide="Aucun élément."):
    """entetes : [str] ; lignes : [[html_cellule, ...]] (déjà échappées). Conteneur défilant (mobile)."""
    if not lignes:
        return f"<div class='vide' style='color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:8px 12px;font-size:13px;margin:6px 0'>{esc(vide)}</div>"
    th = "".join(f"<th style=\"{_TH}\">{esc(h)}</th>" for h in entetes)
    trs = "".join("<tr>" + "".join(f"<td style=\"{_TD}\">{c}</td>" for c in l) + "</tr>" for l in lignes)
    return (f"<div class='tw' style='width:100%;max-width:100%;box-sizing:border-box;overflow-x:auto;margin:6px 0 4px;"
            f"border:1px solid #e5e7eb;border-radius:10px'><table class='t' role='presentation' width='100%' cellpadding='0' "
            f"cellspacing='0' style='width:100%;border-collapse:collapse;font-size:13px;margin:0'><tr>{th}</tr>{trs}</table></div>")

def faits(lignes):
    """Tableau clé / valeur (valeurs déjà en HTML) dans un conteneur défilant ; lignes vides ignorées."""
    trs = "".join(
        f"<tr><td style=\"padding:8px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top;width:110px;white-space:nowrap;"
        f"color:#6b7280;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px\">{esc(k)}</td>"
        f"<td style=\"padding:8px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top;color:#111827;font-size:14px;line-height:1.5;word-break:break-word\">{v}</td></tr>"
        for k, v in lignes if v not in (None, ""))
    return (f"<div class='tw' style='width:100%;max-width:100%;box-sizing:border-box;overflow-x:auto;margin:6px 0 4px;"
            f"border:1px solid #e5e7eb;border-radius:10px'><table class='t' role='presentation' width='100%' cellpadding='0' "
            f"cellspacing='0' style='width:100%;border-collapse:collapse;margin:0'>{trs}</table></div>")

def section(titre, contenu, note=""):
    n = f"<p class='note' style='color:#6b7280;font-size:12px;margin:-4px 0 8px'>{note}</p>" if note else ""
    return (f"<h2 style='font-size:15px;line-height:20px;font-weight:700;color:#111827;margin:26px 0 10px;padding:0 0 0 10px;"
            f"border-left:3px solid {ORANGE}'>{esc(titre)}</h2>{n}{contenu}")

def bouton(texte, href, principal=False):
    st = (f"background:{ORANGE};color:#ffffff;border:1px solid {ORANGE}" if principal
          else "background:#ffffff;color:#374151;border:1px solid #d1d5db")
    return (f'<a href="{esc(href)}" style="display:inline-block;{st};text-decoration:none;font-size:13px;font-weight:600;'
            f'padding:9px 16px;border-radius:8px;margin:0 8px 8px 0">{texte}</a>')

def objet(niveau, titre, resume=""):
    o = f"[OMS][{niveau}][SIEM] {titre}" + (f" — {resume}" if resume else "")
    o = re.sub(r"\s+", " ", o).strip()
    return o if len(o) <= OBJET_MAX else o[:OBJET_MAX - 1] + "…"

_CSS = """
body{margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;color:#374151;font-size:14px;line-height:1.5;-webkit-text-size-adjust:100%}
.wrap{width:100%;box-sizing:border-box;background:#f3f4f6}
.card{max-width:760px;width:100%;box-sizing:border-box;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;overflow:hidden;text-align:left}
.accent{height:4px;line-height:4px;font-size:0;background:#e36517}
.header{padding:20px 28px 6px}
.brand{font-size:11px;font-weight:700;letter-spacing:1.2px;color:#111827;text-transform:uppercase}
.brand2{font-size:11px;color:#6b7280}
.quand{font-size:12px;color:#6b7280;text-align:right;white-space:nowrap}
h1{margin:18px 0 2px;font-size:22px;line-height:28px;font-weight:700;color:#111827}
.sub{margin:0;font-size:13px;color:#6b7280}
.content{padding:12px 28px 24px}
.summary{margin:0}
.tw{width:100%;max-width:100%;box-sizing:border-box;overflow-x:auto;-webkit-overflow-scrolling:touch;margin:6px 0 4px;border:1px solid #e5e7eb;border-radius:10px}
table.t{width:100%;border-collapse:collapse;font-size:13px;margin:0}
table.t tr:last-child td{border-bottom:0}
a{color:#c2410c}
code{font-family:Consolas,'Courier New',monospace;font-size:12px;background:#f3f4f6;padding:1px 4px;border-radius:4px}
.mono{font-family:Consolas,'Courier New',monospace;font-size:12px;line-height:1.55;word-break:break-word}
.footer{background:#f9fafb;color:#6b7280;font-size:11px;line-height:1.5;padding:14px 28px;border-top:1px solid #e5e7eb}
@media (max-width:620px){
 .header{padding:16px 16px 4px}.content{padding:8px 16px 18px}.footer{padding:12px 16px}
 h1{font-size:19px;line-height:24px;margin-top:14px}
 .kpi{width:47% !important;margin-right:3% !important}
 table.t{font-size:12px}table.t th,table.t td{padding:6px 8px !important}
 .quand{display:none}.pill{display:none}
}
"""

def page(titre, sous_titre, niveau, resume_html, corps_html, pied_html="", preheader="", generateur="omni-alert"):
    """Page complète charte v3. resume_html : contenu du bandeau d'état ; corps_html : sections."""
    t = ton(niveau)
    etat = (f"<span style='display:inline-block;padding:3px 10px;border-radius:999px;background:{t['fort']};color:#ffffff;"
            f"font-size:11px;font-weight:700;letter-spacing:.4px;line-height:16px;white-space:nowrap'>{esc(niveau)}</span>") if niveau else ""
    libelle = (f"<div style='font-size:13px;font-weight:700;color:{t['texte']};margin:0 0 4px'>{esc(t['libelle'])}</div>"
               if t.get("libelle") else "")
    pre = preheader or re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", f"{niveau} — {resume_html}")).strip()
    pre = esc(_html.unescape(pre))[:180]
    logo = (f"<img src='cid:{LOGO_CID}' width='40' height='40' alt='OMNITECH' "
            f"style='display:block;width:40px;height:40px;border:0;border-radius:9px'>") if os.path.exists(LOGO_PATH) else ""
    sous = f"<p class='sub' style='margin:0;font-size:13px;color:#6b7280'>{esc(sous_titre)}</p>" if sous_titre else ""
    pied = f"<div style='margin-bottom:6px'>{pied_html}</div>" if pied_html else ""
    now = datetime.now(PARIS) if PARIS else datetime.now()
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="x-apple-disable-message-reformatting"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>{esc(titre)}</title><style>{_CSS}</style></head><body style="margin:0;padding:0;background:#f3f4f6">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;mso-hide:all">{pre}</div>
<div class="wrap" style="background:#f3f4f6;padding:20px 10px">
<!--[if mso]><table role="presentation" width="760" align="center" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
<div class="card" style="max-width:760px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;overflow:hidden">
<div class="accent" style="height:4px;line-height:4px;font-size:0;background:{ORANGE}">&nbsp;</div>
<div class="header" style="padding:20px 28px 6px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
<td width="48" valign="middle" style="width:48px">{logo}</td>
<td valign="middle"><div class="brand" style="font-size:11px;font-weight:700;letter-spacing:1.2px;color:#111827;text-transform:uppercase">Omnitech Security</div><div class="brand2" style="font-size:11px;color:#6b7280">Direction des systèmes d'information · SIEM</div></td>
<td valign="middle" align="right" class="quand" style="font-size:12px;color:#6b7280;white-space:nowrap">{esc(quand_entete())}</td>
</tr></table>
<h1 style="margin:18px 0 2px;font-size:22px;line-height:28px;font-weight:700;color:#111827">{esc(titre)}</h1>{sous}
</div>
<div class="content" style="padding:12px 28px 24px">
<div class="etat" style="border:1px solid {t['bord']};border-left:4px solid {t['fort']};background:{t['fond']};border-radius:10px;padding:12px 16px;margin:6px 0 4px;color:#1f2937"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td valign="top">{libelle}<div class="summary">{resume_html}</div></td><td valign="top" align="right" width="110" class="pill" style="padding-left:10px">{etat}</td></tr></table></div>
{corps_html}
</div>
<div class="footer" style="background:#f9fafb;color:#6b7280;font-size:11px;line-height:1.5;padding:14px 28px;border-top:1px solid #e5e7eb">{pied} Généré le {now.strftime('%d/%m/%Y à %H:%M')} par bx-it-graylog-vm ({esc(generateur)}) · notification automatique, merci de ne pas répondre.</div>
</div>
<!--[if mso]></td></tr></table><![endif]-->
</div>
</body></html>"""

def message(sujet, frm, to, texte, html):
    """multipart/alternative( text/plain , multipart/related( text/html , logo cid ) )."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(sujet, "utf-8")
    msg["From"] = frm
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="omnitech-security.fr")
    msg.attach(MIMEText(texte, "plain", "utf-8"))
    if os.path.exists(LOGO_PATH) and f"cid:{LOGO_CID}" in html:
        rel = MIMEMultipart("related")
        rel.attach(MIMEText(html, "html", "utf-8"))
        with open(LOGO_PATH, "rb") as f:
            img = MIMEImage(f.read(), "png")
        img.add_header("Content-ID", f"<{LOGO_CID}>")
        img.add_header("Content-Disposition", "inline", filename="logo-omnitech.png")
        rel.attach(img)
        msg.attach(rel)
    else:
        msg.attach(MIMEText(html, "html", "utf-8"))
    return msg

def apercu(html):
    """Aperçu hors messagerie : cid:omslogo -> data URI."""
    import base64
    try:
        with open(LOGO_PATH, "rb") as f:
            uri = "data:image/png;base64," + base64.b64encode(f.read()).decode()
        return html.replace(f"cid:{LOGO_CID}", uri)
    except Exception:
        return html

# --- titres lisibles ---------------------------------------------------------------------------------
_RX_PREFIXE = re.compile(r"^OMNI(?:\s+v\d+)?\s*-\s*", re.I)
_RX_SEAL = re.compile(r"^SEAL\s+([A-Z]{2,3}-\d{3})\s*-\s*", re.I)
_RX_SEUIL = re.compile(r"\s*\((?:>=|≥|>)[^)]*\)|\s+-\s+ops$", re.I)
_RX_CODE = re.compile(r"\s*\((?:\d{4}(?:/\d{1,4})?|Sysmon\s+[\d/]+|T\d{4}(?:\.\d{3})?|reg save)\)", re.I)

def titre_lisible(t):
    """'OMNI - SEAL ALM-003 - Intrusion physique (effraction…)' -> ('Intrusion physique (effraction…)', 'SEAL ALM-003').
    Les seuils techniques ('(>=10 échecs / compte / 10 min)') et codes d'événement ('(4698)') sont retirés du titre
    affiché ; ils restent dans la ligne « Règle déclenchée »."""
    s = _RX_PREFIXE.sub("", str(t or "").strip())
    regle = ""
    m = _RX_SEAL.match(s)
    if m:
        regle = "SEAL " + m.group(1).upper(); s = s[m.end():]
    s2 = _RX_CODE.sub("", _RX_SEUIL.sub("", s)).strip(" -")
    return (s2 or s), regle
