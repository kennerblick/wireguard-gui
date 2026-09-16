"""Wartung: verwaiste iptables-Chains finden/entfernen, Firewall-Ist-Zustand anzeigen."""

from flask import flash, redirect, render_template, url_for

from .. import acl, app, firewall, wireguard
from ..db import get_db


@app.route("/maintenance")
def maintenance():
    db = get_db()
    clients = db.execute("SELECT wg_ip FROM clients").fetchall()
    known_chains = {firewall.chain_name(c["wg_ip"]) for c in clients}
    ok, result = firewall.list_remote_wgacl_chains()
    orphaned = []
    remote_error = None
    if ok:
        orphaned = sorted(c for c in result if c not in known_chains)
    else:
        remote_error = result

    ip_labels = acl.build_ip_label_map(db)
    firewall_sections = []
    for chain in ("DOCKER-USER", "FORWARD"):
        f_ok, f_out = wireguard.run_on_target(f"iptables -S {chain} 2>&1")
        if not f_ok:
            firewall_sections.append({"chain": chain, "ok": False, "error": f_out})
            continue
        rules = firewall.parse_iptables_rules(f_out)
        for r in rules:
            r["src_label"] = ip_labels.get((r["src"] or "").split("/")[0], r["src"] or "*")
            r["dst_label"] = ip_labels.get((r["dst"] or "").split("/")[0], r["dst"] or "*")
        firewall_sections.append({
            "chain": chain,
            "ok": True,
            "rules": rules,
            "raw": firewall.annotate_ips(f_out, ip_labels),
        })

    return render_template(
        "maintenance.html",
        orphaned=orphaned,
        remote_error=remote_error,
        firewall_sections=firewall_sections,
    )


@app.route("/maintenance/cleanup", methods=["POST"])
def cleanup_orphaned_chains():
    db = get_db()
    clients = db.execute("SELECT wg_ip FROM clients").fetchall()
    known_chains = {firewall.chain_name(c["wg_ip"]) for c in clients}
    ok, result = firewall.list_remote_wgacl_chains()
    if not ok:
        flash(f"Konnte verwaiste Chains nicht ermitteln: {result}", "error")
        return redirect(url_for("maintenance"))

    hook_chain = firewall.detect_hook_chain()
    removed, errors = [], []
    for chain in result:
        if chain in known_chains:
            continue
        ip_guess = firewall.chain_name_to_ip(chain)
        rok, rout = wireguard.run_on_target(firewall.build_remove_script(ip_guess, hook_chain))
        (removed if rok else errors).append(chain)

    if removed:
        flash(f"{len(removed)} verwaiste Chain(s) entfernt: {', '.join(removed)}", "success")
    if errors:
        flash(f"Fehler beim Entfernen von: {', '.join(errors)}", "error")
    if not removed and not errors:
        flash("Keine verwaisten Chains gefunden.", "success")
    return redirect(url_for("maintenance"))
