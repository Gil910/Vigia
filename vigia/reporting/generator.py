"""
VIGÍA — Report Generator v0.1
Genera informes en HTML, JSON y Markdown desde datos de campañas.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─── Data Models ──────────────────────────────────────────────

@dataclass
class AttackResult:
    """Resultado individual de un ataque."""
    seed_id: str
    vector: str
    owasp: str
    language: str
    prompt: str
    response: str
    score: int
    success: bool
    reasoning: str
    duration_ms: int = 0
    # Agent-specific fields (parsed from evaluator_reasoning JSON)
    scores: dict = field(default_factory=dict)
    violations: list[dict] = field(default_factory=list)
    owasp_agentic: list[str] = field(default_factory=list)


@dataclass
class CampaignData:
    """Datos completos de una campaña para el informe."""
    campaign_id: int = 0
    name: str = ""
    target_model: str = ""
    started_at: str = ""
    finished_at: str = ""
    config: dict = field(default_factory=dict)
    attacks: list[AttackResult] = field(default_factory=list)
    # Computed
    total_attacks: int = 0
    total_successes: int = 0
    success_rate: float = 0.0
    # Optional enrichment
    remediation: dict = field(default_factory=dict)
    plan: dict = field(default_factory=dict)

    def compute_stats(self):
        """Calcula estadísticas derivadas."""
        self.total_attacks = len(self.attacks)
        self.total_successes = sum(1 for a in self.attacks if a.success)
        self.success_rate = (
            self.total_successes / self.total_attacks * 100
            if self.total_attacks > 0 else 0.0
        )

    def score_distribution(self) -> dict[str, int]:
        """Distribución de scores por rango."""
        dist = {"safe": 0, "info": 0, "risk": 0, "vuln": 0, "error": 0}
        for a in self.attacks:
            if a.score < 0:
                dist["error"] += 1
            elif a.score == 0:
                dist["safe"] += 1
            elif a.score < 5:
                dist["info"] += 1
            elif a.score < 8:
                dist["risk"] += 1
            else:
                dist["vuln"] += 1
        return dist

    def by_vector(self) -> dict[str, list[AttackResult]]:
        """Agrupa ataques por vector."""
        groups: dict[str, list[AttackResult]] = {}
        for a in self.attacks:
            groups.setdefault(a.vector, []).append(a)
        return groups

    def by_owasp(self) -> dict[str, list[AttackResult]]:
        """Agrupa ataques exitosos por código OWASP."""
        groups: dict[str, list[AttackResult]] = {}
        for a in self.attacks:
            if a.success and a.owasp:
                groups.setdefault(a.owasp, []).append(a)
            # Also check agentic OWASP codes
            for code in a.owasp_agentic:
                if a.success:
                    groups.setdefault(code, []).append(a)
        return groups

    def avg_score(self) -> float:
        """Score promedio (excluyendo errores)."""
        valid = [a.score for a in self.attacks if a.score >= 0]
        return sum(valid) / len(valid) if valid else 0.0

    def dimension_summary(self) -> dict[str, float]:
        """Promedio de scores por dimensión (solo agent mode)."""
        dims = {
            "info_disclosure": [], "unauthorized_actions": [],
            "privilege_escalation": [], "goal_hijacking": [],
            "tool_misuse": [],
        }
        for a in self.attacks:
            for dim in dims:
                val = a.scores.get(dim)
                if val is not None:
                    dims[dim].append(val)
        return {
            dim: sum(vals) / len(vals) if vals else 0.0
            for dim, vals in dims.items()
        }


# ─── Report Generator ────────────────────────────────────────

class ReportGenerator:
    """Genera informes en múltiples formatos."""

    def from_database(self, db_path: str, campaign_id: int) -> CampaignData:
        """Carga datos de campaña desde la base de datos SQLite."""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Campaign metadata
        row = conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Campaign {campaign_id} not found")

        data = CampaignData(
            campaign_id=row["id"],
            name=row["name"],
            target_model=row["target_model"],
            started_at=row["started_at"],
            finished_at=row["finished_at"] or "",
            config=json.loads(row["config"]) if row["config"] else {},
        )

        # Attacks
        attacks = conn.execute(
            "SELECT * FROM attacks WHERE campaign_id = ? ORDER BY id", (campaign_id,)
        ).fetchall()

        for atk in attacks:
            # Try to parse evaluator_reasoning as JSON for agent evaluations
            scores = {}
            violations = []
            owasp_agentic = []
            reasoning_raw = atk["evaluator_reasoning"] or ""
            try:
                eval_data = json.loads(reasoning_raw)
                if isinstance(eval_data, dict):
                    scores = eval_data.get("scores", {})
                    violations = eval_data.get("violations", [])
                    owasp_agentic = eval_data.get("owasp_agentic", [])
                    reasoning_raw = eval_data.get("reasoning", reasoning_raw)
            except (json.JSONDecodeError, TypeError):
                pass

            data.attacks.append(AttackResult(
                seed_id=atk["seed_id"],
                vector=atk["vector"],
                owasp=atk["owasp"] or "",
                language=atk["language"] or "es-ES",
                prompt=atk["prompt"],
                response=atk["response"] or "",
                score=atk["score"] or 0,
                success=bool(atk["success"]),
                reasoning=reasoning_raw,
                duration_ms=atk["duration_ms"] or 0,
                scores=scores,
                violations=violations,
                owasp_agentic=owasp_agentic,
            ))

        conn.close()
        data.compute_stats()
        return data

    def from_evaluations(
        self,
        evaluations: list[dict],
        campaign_name: str = "Agent Campaign",
        target_model: str = "unknown",
        seeds: list[dict] = None,
        remediation: dict = None,
    ) -> CampaignData:
        """Construye CampaignData desde evaluaciones en memoria."""
        seeds = seeds or []
        data = CampaignData(
            name=campaign_name,
            target_model=target_model,
            started_at=datetime.now().isoformat(),
            remediation=remediation or {},
        )

        for i, ev in enumerate(evaluations):
            scores = ev.get("scores", {})
            seed = seeds[i] if i < len(seeds) else {}
            overall = scores.get("overall", 0)

            data.attacks.append(AttackResult(
                seed_id=seed.get("id", f"eval-{i+1:03d}"),
                vector=seed.get("vector", "unknown"),
                owasp=seed.get("owasp_agentic", ""),
                language=seed.get("language", "es-ES"),
                prompt=seed.get("prompt", ""),
                response="",
                score=overall,
                success=ev.get("success", False),
                reasoning=ev.get("reasoning", ""),
                scores=scores,
                violations=ev.get("violations", []),
                owasp_agentic=ev.get("owasp_agentic", []),
            ))

        data.compute_stats()
        return data

    # ─── Format Generators ───────────────────────────────────

    def to_json(self, data: CampaignData) -> str:
        """Genera informe en formato JSON."""
        report = {
            "meta": {
                "generator": "VIGÍA Reporting v0.1",
                "generated_at": datetime.now().isoformat(),
                "campaign_id": data.campaign_id,
                "campaign_name": data.name,
            },
            "summary": {
                "target_model": data.target_model,
                "started_at": data.started_at,
                "finished_at": data.finished_at,
                "total_attacks": data.total_attacks,
                "total_successes": data.total_successes,
                "success_rate": round(data.success_rate, 1),
                "avg_score": round(data.avg_score(), 1),
                "score_distribution": data.score_distribution(),
                "dimension_summary": {
                    k: round(v, 1)
                    for k, v in data.dimension_summary().items()
                },
            },
            "owasp_mapping": {
                code: len(attacks)
                for code, attacks in data.by_owasp().items()
            },
            "attacks": [
                {
                    "seed_id": a.seed_id,
                    "vector": a.vector,
                    "owasp": a.owasp,
                    "language": a.language,
                    "score": a.score,
                    "success": a.success,
                    "reasoning": a.reasoning[:200],
                    "scores": a.scores,
                    "owasp_agentic": a.owasp_agentic,
                    "violations_count": len(a.violations),
                }
                for a in data.attacks
            ],
            "remediation": data.remediation if data.remediation else None,
        }
        return json.dumps(report, ensure_ascii=False, indent=2)

    def to_markdown(self, data: CampaignData) -> str:
        """Genera informe en formato Markdown."""
        lines = []
        dist = data.score_distribution()
        dim_summary = data.dimension_summary()
        owasp_map = data.by_owasp()

        # Header
        lines.append(f"# VIGÍA Security Report — {data.name}")
        lines.append("")
        lines.append(f"**Modelo objetivo:** {data.target_model}")
        lines.append(f"**Fecha:** {data.started_at[:10] if data.started_at else 'N/A'}")
        lines.append(f"**Generado por:** VIGÍA Reporting v0.1")
        lines.append("")

        # Executive Summary
        lines.append("## Resumen Ejecutivo")
        lines.append("")
        lines.append(
            f"Se ejecutaron **{data.total_attacks}** ataques contra el agente. "
            f"**{data.total_successes}** fueron exitosos "
            f"(**{data.success_rate:.1f}%** de tasa de éxito del atacante). "
            f"El score promedio fue **{data.avg_score():.1f}/10**."
        )
        lines.append("")

        # Score Distribution
        lines.append("## Distribución de Resultados")
        lines.append("")
        lines.append("| Categoría | Cantidad | Porcentaje |")
        lines.append("|-----------|----------|------------|")
        total = max(data.total_attacks, 1)
        for label, emoji, key in [
            ("Vulnerabilidad (8-10)", "🔴", "vuln"),
            ("Riesgo (5-7)", "🟡", "risk"),
            ("Informativo (1-4)", "🔵", "info"),
            ("Seguro (0)", "🟢", "safe"),
            ("Error", "⚫", "error"),
        ]:
            count = dist[key]
            pct = count / total * 100
            lines.append(f"| {emoji} {label} | {count} | {pct:.0f}% |")
        lines.append("")

        # Dimension Analysis (agent mode)
        has_dims = any(v > 0 for v in dim_summary.values())
        if has_dims:
            lines.append("## Análisis por Dimensión de Seguridad")
            lines.append("")
            lines.append("| Dimensión | Score Promedio | Nivel |")
            lines.append("|-----------|---------------|-------|")
            for dim, avg in dim_summary.items():
                dim_display = dim.replace("_", " ").title()
                if avg >= 7:
                    level = "🔴 Crítico"
                elif avg >= 5:
                    level = "🟡 Alto"
                elif avg >= 2:
                    level = "🔵 Medio"
                else:
                    level = "🟢 Bajo"
                lines.append(f"| {dim_display} | {avg:.1f}/10 | {level} |")
            lines.append("")

        # OWASP Mapping
        if owasp_map:
            lines.append("## Mapeo OWASP")
            lines.append("")
            lines.append("| Código | Descripción | Incidencias |")
            lines.append("|--------|-------------|-------------|")
            owasp_names = {
                "ASI01": "Agent Goal Hijacking",
                "ASI02": "Tool Misuse",
                "ASI03": "Identity & Privilege Abuse",
                "ASI04": "Excessive Agency",
                "ASI05": "Inadequate Sandboxing",
                "ASI06": "Inadequate Sandboxing",
                "LLM02": "Sensitive Information Disclosure",
                "LLM07": "System Prompt Leakage",
            }
            for code, attacks in sorted(owasp_map.items()):
                # Extract base code (ASI01 from ASI01:AgentGoalHijacking)
                base_code = code.split(":")[0]
                desc = owasp_names.get(base_code, code)
                lines.append(f"| {base_code} | {desc} | {len(attacks)} |")
            lines.append("")

        # Attack Details
        lines.append("## Detalle de Ataques")
        lines.append("")
        lines.append("| # | Seed ID | Vector | Score | Status | OWASP |")
        lines.append("|---|---------|--------|-------|--------|-------|")
        for i, a in enumerate(data.attacks, 1):
            status = "🔴 VULN" if a.score >= 8 else (
                "🟡 RISK" if a.score >= 5 else (
                    "🔵 INFO" if a.score >= 1 else "🟢 SAFE"
                )
            )
            if a.score < 0:
                status = "⚫ ERROR"
            owasp_str = a.owasp or ", ".join(a.owasp_agentic) or "—"
            lines.append(
                f"| {i} | {a.seed_id[:20]} | {a.vector[:15]} | "
                f"{a.score} | {status} | {owasp_str[:20]} |"
            )
        lines.append("")

        # Vectors breakdown
        by_vec = data.by_vector()
        if by_vec:
            lines.append("## Análisis por Vector de Ataque")
            lines.append("")
            for vector, attacks in sorted(by_vec.items()):
                successes = sum(1 for a in attacks if a.success)
                avg = sum(a.score for a in attacks if a.score >= 0) / max(len(attacks), 1)
                lines.append(f"### {vector}")
                lines.append(f"- Ataques: {len(attacks)}, Exitosos: {successes}, Score promedio: {avg:.1f}")
                lines.append("")

        # Remediation
        if data.remediation:
            lines.append("## Recomendaciones de Remediación")
            lines.append("")
            rem = data.remediation

            if rem.get("quick_wins"):
                lines.append("### Quick Wins")
                lines.append("")
                for qw in rem["quick_wins"]:
                    lines.append(f"- {qw}")
                lines.append("")

            if rem.get("countermeasures"):
                lines.append("### Contramedidas")
                lines.append("")
                lines.append("| ID | Prioridad | Título | OWASP | Esfuerzo |")
                lines.append("|----|-----------|--------|-------|----------|")
                for cm in rem["countermeasures"]:
                    lines.append(
                        f"| {cm['id']} | {cm['priority']} | {cm['title']} | "
                        f"{cm['owasp']} | {cm['effort']} |"
                    )
                lines.append("")

            if rem.get("architecture_recommendations"):
                lines.append("### Recomendaciones de Arquitectura")
                lines.append("")
                for rec in rem["architecture_recommendations"]:
                    lines.append(f"- {rec}")
                lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Generado por VIGÍA — Framework de Red Teaming para Agentes AI*")
        lines.append(f"*{datetime.now().strftime('%Y-%m-%d %H:%M')}*")

        return "\n".join(lines)

    def to_html(self, data: CampaignData) -> str:
        """Genera informe HTML interactivo standalone."""
        dist = data.score_distribution()
        dim_summary = data.dimension_summary()
        owasp_map = data.by_owasp()
        has_dims = any(v > 0 for v in dim_summary.values())

        # Build attack rows
        attack_rows = ""
        for i, a in enumerate(data.attacks, 1):
            if a.score >= 8:
                status_class, status_text = "vuln", "VULN"
            elif a.score >= 5:
                status_class, status_text = "risk", "RISK"
            elif a.score >= 1:
                status_class, status_text = "info", "INFO"
            elif a.score < 0:
                status_class, status_text = "error", "ERROR"
            else:
                status_class, status_text = "safe", "SAFE"

            owasp_str = a.owasp or ", ".join(c.split(":")[0] for c in a.owasp_agentic) or "—"
            reasoning_escaped = a.reasoning[:150].replace('"', '&quot;').replace('<', '&lt;')

            attack_rows += f"""
            <tr class="{status_class}">
                <td>{i}</td>
                <td title="{a.seed_id}">{a.seed_id[:18]}</td>
                <td>{a.vector[:15]}</td>
                <td><span class="score-badge {status_class}">{a.score}</span></td>
                <td><span class="status-badge {status_class}">{status_text}</span></td>
                <td>{owasp_str[:20]}</td>
                <td title="{reasoning_escaped}">{reasoning_escaped[:60]}...</td>
            </tr>"""

        # Dimension bars (for agent mode)
        dim_bars = ""
        if has_dims:
            for dim, avg in dim_summary.items():
                dim_display = dim.replace("_", " ").title()
                width = avg * 10  # 0-100%
                color = "#ef4444" if avg >= 7 else ("#eab308" if avg >= 5 else ("#3b82f6" if avg >= 2 else "#22c55e"))
                dim_bars += f"""
                <div class="dim-row">
                    <span class="dim-label">{dim_display}</span>
                    <div class="dim-bar-bg">
                        <div class="dim-bar" style="width:{width}%;background:{color}"></div>
                    </div>
                    <span class="dim-value">{avg:.1f}</span>
                </div>"""

        # OWASP section
        owasp_rows = ""
        owasp_names = {
            "ASI01": "Agent Goal Hijacking", "ASI02": "Tool Misuse",
            "ASI03": "Identity & Privilege Abuse", "ASI04": "Excessive Agency",
            "ASI05": "Inadequate Sandboxing", "ASI06": "Inadequate Sandboxing",
            "LLM02": "Sensitive Info Disclosure", "LLM07": "System Prompt Leakage",
        }
        for code, attacks in sorted(owasp_map.items()):
            base = code.split(":")[0]
            desc = owasp_names.get(base, code)
            owasp_rows += f"<tr><td><strong>{base}</strong></td><td>{desc}</td><td>{len(attacks)}</td></tr>"

        # Remediation section
        remediation_html = ""
        if data.remediation:
            rem = data.remediation
            qw_html = ""
            if rem.get("quick_wins"):
                qw_items = "".join(f"<li>{qw}</li>" for qw in rem["quick_wins"])
                qw_html = f'<div class="card"><h3>Quick Wins</h3><ul>{qw_items}</ul></div>'

            cm_rows = ""
            if rem.get("countermeasures"):
                for cm in rem["countermeasures"]:
                    prio_class = cm["priority"].lower()
                    cm_rows += f"""
                    <tr>
                        <td>{cm['id']}</td>
                        <td><span class="prio-badge {prio_class}">{cm['priority']}</span></td>
                        <td><strong>{cm['title']}</strong></td>
                        <td>{cm['owasp']}</td>
                        <td>{cm['effort']}</td>
                    </tr>"""

            cm_table = ""
            if cm_rows:
                cm_table = f"""
                <table class="data-table">
                    <thead><tr><th>ID</th><th>Prioridad</th><th>Título</th><th>OWASP</th><th>Esfuerzo</th></tr></thead>
                    <tbody>{cm_rows}</tbody>
                </table>"""

            arch_html = ""
            if rem.get("architecture_recommendations"):
                items = "".join(f"<li>{r}</li>" for r in rem["architecture_recommendations"])
                arch_html = f'<div class="card"><h3>Recomendaciones de Arquitectura</h3><ul>{items}</ul></div>'

            remediation_html = f"""
            <section id="remediation">
                <h2>Remediación</h2>
                {qw_html}
                {cm_table}
                {arch_html}
            </section>"""

        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIGÍA Report — {_html_escape(data.name)}</title>
    <style>
        :root {{
            --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
            --text: #e2e8f0; --text-dim: #94a3b8; --accent: #f97316;
            --red: #ef4444; --yellow: #eab308; --green: #22c55e; --blue: #3b82f6;
            --cyan: #06b6d4;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
        header {{ text-align: center; padding: 3rem 0 2rem; border-bottom: 1px solid var(--surface2); margin-bottom: 2rem; }}
        header h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: 0.5rem; }}
        header .meta {{ color: var(--text-dim); font-size: 0.9rem; }}
        h2 {{ color: var(--cyan); font-size: 1.4rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--surface2); }}
        h3 {{ color: var(--text); font-size: 1.1rem; margin: 1rem 0 0.5rem; }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: var(--surface); border-radius: 12px; padding: 1.5rem; text-align: center; }}
        .stat-card .value {{ font-size: 2.2rem; font-weight: 700; }}
        .stat-card .label {{ color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-card.danger .value {{ color: var(--red); }}
        .stat-card.warning .value {{ color: var(--yellow); }}
        .stat-card.success .value {{ color: var(--green); }}
        .stat-card.info .value {{ color: var(--blue); }}

        .card {{ background: var(--surface); border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }}
        .card ul {{ padding-left: 1.2rem; }}
        .card li {{ margin-bottom: 0.4rem; color: var(--text-dim); }}

        .dist-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.5rem; margin-bottom: 2rem; }}
        .dist-item {{ background: var(--surface); border-radius: 8px; padding: 1rem; text-align: center; }}
        .dist-item .count {{ font-size: 1.8rem; font-weight: 700; }}
        .dist-item.vuln .count {{ color: var(--red); }}
        .dist-item.risk .count {{ color: var(--yellow); }}
        .dist-item.info .count {{ color: var(--blue); }}
        .dist-item.safe .count {{ color: var(--green); }}
        .dist-item .label {{ font-size: 0.75rem; color: var(--text-dim); }}

        .dim-row {{ display: flex; align-items: center; margin-bottom: 0.6rem; }}
        .dim-label {{ width: 180px; font-size: 0.85rem; color: var(--text-dim); }}
        .dim-bar-bg {{ flex: 1; height: 20px; background: var(--surface2); border-radius: 10px; overflow: hidden; }}
        .dim-bar {{ height: 100%; border-radius: 10px; transition: width 0.5s; }}
        .dim-value {{ width: 40px; text-align: right; font-weight: 600; font-size: 0.85rem; margin-left: 0.5rem; }}

        .data-table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; font-size: 0.85rem; }}
        .data-table th {{ background: var(--surface2); color: var(--text-dim); text-align: left; padding: 0.7rem; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        .data-table td {{ padding: 0.6rem 0.7rem; border-bottom: 1px solid var(--surface2); }}
        .data-table tr:hover {{ background: var(--surface); }}

        .score-badge, .status-badge, .prio-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
        .score-badge.vuln, .status-badge.vuln {{ background: rgba(239,68,68,0.2); color: var(--red); }}
        .score-badge.risk, .status-badge.risk {{ background: rgba(234,179,8,0.2); color: var(--yellow); }}
        .score-badge.info, .status-badge.info {{ background: rgba(59,130,246,0.2); color: var(--blue); }}
        .score-badge.safe, .status-badge.safe {{ background: rgba(34,197,94,0.2); color: var(--green); }}
        .score-badge.error, .status-badge.error {{ background: rgba(100,100,100,0.2); color: #888; }}
        .prio-badge.p0 {{ background: rgba(239,68,68,0.2); color: var(--red); }}
        .prio-badge.p1 {{ background: rgba(249,115,22,0.2); color: var(--accent); }}
        .prio-badge.p2 {{ background: rgba(234,179,8,0.2); color: var(--yellow); }}
        .prio-badge.p3 {{ background: rgba(34,197,94,0.2); color: var(--green); }}

        footer {{ text-align: center; padding: 2rem 0; color: var(--text-dim); font-size: 0.8rem; border-top: 1px solid var(--surface2); margin-top: 3rem; }}
        @media (max-width: 768px) {{ .dist-grid {{ grid-template-columns: repeat(3, 1fr); }} .stats-grid {{ grid-template-columns: 1fr 1fr; }} }}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>VIGÍA Security Report</h1>
        <div class="meta">{_html_escape(data.name)} &mdash; {_html_escape(data.target_model)} &mdash; {now}</div>
    </header>

    <section id="summary">
        <h2>Resumen Ejecutivo</h2>
        <div class="stats-grid">
            <div class="stat-card"><div class="value">{data.total_attacks}</div><div class="label">Ataques totales</div></div>
            <div class="stat-card danger"><div class="value">{data.total_successes}</div><div class="label">Vulnerabilidades</div></div>
            <div class="stat-card warning"><div class="value">{data.success_rate:.1f}%</div><div class="label">Tasa de explotación</div></div>
            <div class="stat-card info"><div class="value">{data.avg_score():.1f}</div><div class="label">Score promedio</div></div>
        </div>

        <div class="dist-grid">
            <div class="dist-item vuln"><div class="count">{dist['vuln']}</div><div class="label">Vulnerabilidad</div></div>
            <div class="dist-item risk"><div class="count">{dist['risk']}</div><div class="label">Riesgo</div></div>
            <div class="dist-item info"><div class="count">{dist['info']}</div><div class="label">Informativo</div></div>
            <div class="dist-item safe"><div class="count">{dist['safe']}</div><div class="label">Seguro</div></div>
            <div class="dist-item"><div class="count">{dist['error']}</div><div class="label">Error</div></div>
        </div>
    </section>

    {"<section id='dimensions'><h2>Dimensiones de Seguridad</h2><div class='card'>" + dim_bars + "</div></section>" if has_dims else ""}

    {"<section id='owasp'><h2>Mapeo OWASP</h2><table class='data-table'><thead><tr><th>Código</th><th>Descripción</th><th>Incidencias</th></tr></thead><tbody>" + owasp_rows + "</tbody></table></section>" if owasp_rows else ""}

    <section id="attacks">
        <h2>Detalle de Ataques</h2>
        <table class="data-table">
            <thead>
                <tr><th>#</th><th>Seed ID</th><th>Vector</th><th>Score</th><th>Status</th><th>OWASP</th><th>Razonamiento</th></tr>
            </thead>
            <tbody>{attack_rows}</tbody>
        </table>
    </section>

    {remediation_html}

    <footer>
        VIGÍA &mdash; Framework de Red Teaming para Agentes AI &mdash; {now}
    </footer>
</div>
</body>
</html>"""
        return html


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
