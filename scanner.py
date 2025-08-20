#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Instagram Private Check – Lightweight Scanner (Anon-Only)
Yasal/etik amaçlar için, SADECE kendi içeriğiniz ve yazılı izinli hedeflerde kullanın.
Brute force, rastgele ID/shortcode tahmini yapmaz. Rate-limit dostudur.

Kullanım:
    python scanner.py --target https://www.instagram.com/reel/<SHORTCODE>/
    python scanner.py --target https://www.instagram.com/p/<SHORTCODE>/ --cdn-url "https://scontent-.../video.mp4"
    python scanner.py --out report.md

Örnek:
    python scanner.py --target https://www.instagram.com/reel/DNksqAGooyvX36dLss2a3hzUCHpUeE079u2t640/
"""

from __future__ import annotations
import argparse
import json
import sys
import time
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlencode, urlunparse, quote

import requests

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

TIMEOUT = 12
SLEEP = 0.8  # nazik aralık
MAX_BODY_PREVIEW = 800

def is_instagram_url(u: str) -> bool:
    try:
        p = urlparse(u)
        host = (p.netloc or "").lower()
        return host.endswith("instagram.com")
    except Exception:
        return False

def normalize_target(u: str) -> str:
    """Kullanıcı /reel/ veya /p/ formatı verirse standart hale getirir."""
    p = urlparse(u)
    path = p.path or "/"
    # Sonunda slash yoksa ekle
    if not path.endswith("/"):
        path += "/"
    # Query ve fragment temiz
    new = p._replace(path=path, query="", fragment="")
    return urlunparse(new)

def extract_shortcode(u: str) -> Optional[str]:
    try:
        path = urlparse(u).path
        # /reel/<code>/ veya /p/<code>/ yakala
        m = re.search(r"/(reel|p)/([A-Za-z0-9\-_]+)/?", path)
        if m:
            return m.group(2)
        return None
    except Exception:
        return None

def build_url_with_params(base: str, params: Dict[str, Any]) -> str:
    p = urlparse(base)
    q = urlencode(params, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, q, p.fragment))

def safe_get(url: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "de-DE,de;q=0.9,en;q=0.8,tr;q=0.7"}
    if headers:
        h.update(headers)
    return requests.get(url, headers=h, timeout=TIMEOUT, allow_redirects=True)

def preview_body(text: str) -> str:
    if text is None:
        return ""
    t = text.strip()
    if len(t) > MAX_BODY_PREVIEW:
        return t[:MAX_BODY_PREVIEW] + "... [truncated]"
    return t

def analyze_json_body(text: str) -> Dict[str, Any]:
    out = {"is_json": False, "keys": [], "has_media_fields": False, "error_like": False}
    try:
        j = json.loads(text)
        out["is_json"] = True
        if isinstance(j, dict):
            out["keys"] = list(j.keys())[:20]
            # medyaya işaret eden alanlar:
            media_keys = {"thumbnail_url", "video_url", "display_url", "graphql", "items"}
            out["has_media_fields"] = any(k in j for k in media_keys)
            # tipik hata alanları
            error_keys = {"error", "error_message", "error_type", "errorSummary"}
            out["error_like"] = any(k in j for k in error_keys)
    except Exception:
        pass
    return out

def check_public_page(target: str) -> Dict[str, Any]:
    r = safe_get(target)
    info = {
        "name": "Public Page (login-wall)",
        "url": target,
        "status": r.status_code,
        "content_type": r.headers.get("Content-Type", ""),
        "body_preview": preview_body(r.text),
        "verdict": "OK",
        "detail": "Girişsiz sayfa beklenen şekilde login duvarını gösteriyor."
    }
    if r.status_code == 200 and ("Sorry" in r.text or "Log in" in r.text or "Anmelden" in r.text):
        info["verdict"] = "OK"
    elif r.status_code in (301, 302, 303, 307, 308):
        info["verdict"] = "OK"
    else:
        # 200 + içerik dökümü riskli olabilir (ama çoğu zaman login sayfası 200 döner)
        info["verdict"] = "REVIEW"
        info["detail"] = "Beklenmeyen durum: login duvarı olmayan 200/HTML. İncele."
    return info

def check_a1_variant(target: str, dis: bool = False) -> Dict[str, Any]:
    params = {"__a": 1}
    if dis:
        params["__d"] = "dis"
    url = build_url_with_params(target, params)
    r = safe_get(url, headers={"Accept": "application/json"})
    body_preview = preview_body(r.text)
    parsed = analyze_json_body(r.text)

    verdict = "OK"
    detail = "Private içerikte JSON dönmedi veya sadece hata gövdesi döndü."
    if parsed["is_json"] and parsed["has_media_fields"] and not parsed["error_like"]:
        verdict = "HIGH"
        detail = "JSON içinde media alanları döndü (girişsiz)."
    elif r.status_code == 200 and not parsed["is_json"]:
        verdict = "REVIEW"
        detail = "200 döndü ama JSON değil; beklenmeyen içerik."

    return {
        "name": f"?__a=1{'&__d=dis' if dis else ''}",
        "url": url,
        "status": r.status_code,
        "content_type": r.headers.get("Content-Type", ""),
        "body_preview": body_preview,
        "json_meta": parsed,
        "verdict": verdict,
        "detail": detail
    }

def check_oembed(shortcode: str) -> Dict[str, Any]:
    # canonical olarak reel formatını kullanalım
    reel_url = f"https://www.instagram.com/reel/{quote(shortcode)}/"
    oembed = f"https://www.instagram.com/api/oembed/?url={quote(reel_url, safe=':/?=&')}"
    r = safe_get(oembed, headers={"Accept": "application/json"})
    meta = analyze_json_body(r.text)
    verdict = "OK"
    detail = "oEmbed login'siz meta/thumbnail vermedi (beklenen)."
    if meta["is_json"] and meta["has_media_fields"] and not meta["error_like"]:
        verdict = "HIGH"
        detail = "oEmbed login'siz meta/thumbnail verdi (thumbnail_url/html/author_name)."
    elif r.status_code == 200 and not meta["is_json"]:
        verdict = "REVIEW"
        detail = "200 döndü ama JSON değil; beklenmeyen içerik."

    return {
        "name": "oEmbed",
        "url": oembed,
        "status": r.status_code,
        "content_type": r.headers.get("Content-Type", ""),
        "body_preview": preview_body(r.text),
        "json_meta": meta,
        "verdict": verdict,
        "detail": detail
    }

def check_cdn(cdn_url: str) -> Dict[str, Any]:
    """Kullanıcının SADECE kendi içeriğinden elde ettiği CDN linki login'siz açılıyor mu?"""
    r = safe_get(cdn_url)
    ct = r.headers.get("Content-Type", "")
    verdict = "OK"
    detail = "CDN linki login'siz erişilebilir değil (veya bloklandı)."
    # Eğer 200 + video/image ise ciddi risk
    risky_ct = ("video/", "image/")
    if r.status_code == 200 and any(ct.startswith(x) for x in risky_ct):
        verdict = "HIGH"
        detail = "CDN linki login'siz 200 döndü ve medya içerik servislendi."
    elif r.status_code in (301, 302, 303, 307, 308):
        verdict = "OK"
        detail = "Yönlendirme/engelleme var (beklenen)."
    return {
        "name": "CDN media URL",
        "url": cdn_url,
        "status": r.status_code,
        "content_type": ct,
        "body_preview": preview_body(r.text if "text" in ct else ""),
        "verdict": verdict,
        "detail": detail
    }

def make_report(results: list[Dict[str, Any]], out: Optional[str]) -> None:
    sev_order = {"HIGH": 0, "REVIEW": 1, "OK": 2}
    results_sorted = sorted(results, key=lambda x: sev_order.get(x.get("verdict","OK"), 3))
    print("\n=== Sonuç Özeti ===")
    for r in results_sorted:
        print(f"[{r['verdict']}] {r['name']}  → {r['status']}  ({r['url']})")
        print(f"    {r.get('detail','')}")
    # Markdown rapor yaz
    if out:
        lines = []
        lines.append("# Instagram Private Check – Rapor\n")
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"- Tarih: {t}\n")
        lines.append("## Sonuçlar\n")
        for r in results_sorted:
            lines.append(f"### {r['name']}\n")
            lines.append(f"- URL: `{r['url']}`\n")
            lines.append(f"- Durum: **{r['verdict']}**\n")
            lines.append(f"- HTTP: `{r['status']}` | Content-Type: `{r.get('content_type','')}`\n")
            if "json_meta" in r:
                lines.append(f"- JSON meta: `{json.dumps(r['json_meta'], ensure_ascii=False)}`\n")
            lines.append(f"- Detay: {r.get('detail','')}\n")
            if r.get("body_preview"):
                lines.append("<details><summary>Body Preview</summary>\n\n")
                lines.append("```\n" + r["body_preview"] + "\n```\n")
                lines.append("</details>\n")
        lines.append("\n---\n")
        lines.append("**Not:** Bu rapor yalnızca girişsiz (anon) isteklerle elde edilmiştir. Sadece kendi içeriğiniz/izinli hedeflerde kullanınız.\n")
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"\nRapor yazıldı: {out}")

def main():
    ap = argparse.ArgumentParser(description="Instagram Private Check – Anon Tarayıcı")
    ap.add_argument("--target", required=True, help="Reel/Post URL (ör: https://www.instagram.com/reel/<SHORTCODE>/)")
    ap.add_argument("--cdn-url", help="İsteğe bağlı: KENDİ içeriğinizden elde ettiğiniz CDN medya linki (mp4/jpg).")
    ap.add_argument("--out", default="report.md", help="Rapor çıktısı (Markdown). Varsayılan: report.md")
    args = ap.parse_args()

    target = args.target.strip()
    if not is_instagram_url(target):
        print("❌ Lütfen instagram.com alan adındaki bir URL verin.")
        sys.exit(2)

    target = normalize_target(target)
    sc = extract_shortcode(target)
    if not sc:
        print("❌ Shortcode bulunamadı. URL /reel/<code>/ veya /p/<code>/ formatında olmalı.")
        sys.exit(2)

    print("≡ Hedef:", target)
    print("≡ Shortcode:", sc)

    results = []
    try:
        # 1) Public page (login duvarı)
        results.append(check_public_page(target))
        time.sleep(SLEEP)

        # 2) ?__a=1
        results.append(check_a1_variant(target, dis=False))
        time.sleep(SLEEP)

        # 3) ?__a=1&__d=dis
        results.append(check_a1_variant(target, dis=True))
        time.sleep(SLEEP)

        # 4) oEmbed
        results.append(check_oembed(sc))
        time.sleep(SLEEP)

        # 5) CDN (opsiyonel)
        if args.cdn_url:
            if args.cdn_url.startswith("http"):
                results.append(check_cdn(args.cdn_url))
            else:
                results.append({
                    "name":"CDN media URL",
                    "url": args.cdn_url,
                    "status": "-",
                    "content_type": "-",
                    "verdict": "REVIEW",
                    "detail": "Geçersiz CDN URL formatı."
                })

        make_report(results, args.out)

        # Önemli eşikler – HIGH varsa çıkış kodu 1 (CI/CD entegrasyonu için)
        if any(r.get("verdict") == "HIGH" for r in results):
            print("\n⚠️ Potansiyel sızıntı bulguları var (HIGH). Raporu Meta Whitehat formatına dönüştürün.")
            sys.exit(1)
        else:
            print("\n✅ Kritik sızıntı tespit edilmedi (Anon testlere göre).")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\nİptal edildi.")
        sys.exit(130)
    except Exception as e:
        print("Beklenmeyen hata:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
